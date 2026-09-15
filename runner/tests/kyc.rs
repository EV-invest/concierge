//! The identity-verification flow, driven through the REAL axum router against a REAL
//! Postgres.
//!
//! The webhook is the first public, unauthenticated, non-OAuth entry point in this
//! plane, and the thing on the other side of it is a KYC level that the money plane
//! mirrors. So these tests exercise the route as an attacker reaches it — an HTTP
//! request with headers and a body — rather than the functions behind it, and they
//! assert on the two places the damage would show: `users.kyc_level` and `user_outbox`.
//!
//! The stub provider stands in for Didit. It stubs only the network call that opens a
//! session; callback verification is the same code the live adapter runs, so a test that
//! passes here is a test of what ships.

use std::sync::{
	Arc,
	atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use axum::{
	Router,
	body::Body,
	http::{HeaderMap, Request, StatusCode},
};
use concierge::{
	infrastructure::{
		db,
		kyc::{
			cases::PgKycCases,
			didit::{sign_body, sign_body_v2},
			stub::StubKyc,
		},
		notifications::PgNotifications,
		users::{AdminAction, PgUsers},
	},
	ports::{CallbackHeaders, KYC_CALLBACK_WINDOW_SECS, KycCallbackError, KycCaseRepository, KycDecision, KycProvider, KycSession, KycStatus, UserDirectoryRepository},
	web::{self, KycDeps, START_MAX_PER_WINDOW},
};
use domain::{
	error::DomainError,
	users::{AuthSubject, Email, UserId},
};
use evconcierge_auth::AuthService;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::{Notify, watch};
use tower::ServiceExt;
use uuid::Uuid;

const SECRET: &str = "kyc-integration-secret";
const PROVIDER: &str = "stub";
const SUPPORT: &str = "support@evinvest.test";

/// The vendor's own words for an exhausted account. It must never reach a browser, so
/// the tests below grep the response body for this exact string.
const VENDOR_DETAIL: &str = "insufficient balance on the didit account";

/// A provider that is configured, reachable and simply will not open a session — the
/// out-of-balance / over-quota / vendor-is-down case.
///
/// It fails the way the live adapter fails: `start_session` collapses every non-success
/// into one `DomainError`, so this double does not need to imitate any particular vendor
/// status code (and deliberately does not — we do not know which one Didit sends).
struct RefusingKyc;

#[async_trait]
impl KycProvider for RefusingKyc {
	fn name(&self) -> &'static str {
		PROVIDER
	}

	async fn start_session(&self, _case_id: Uuid, _requested_tier: u32) -> Result<KycSession, DomainError> {
		Err(DomainError::Repository(format!("didit: session rejected with 402 Payment Required: {VENDOR_DETAIL}")))
	}

	fn parse_callback(&self, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
		StubKyc::new(SECRET.to_string(), "https://evinvest.test/cabinet".to_string()).parse_callback(headers, body, now)
	}
}

/// The stub, plus a tally of how many times a session was actually bought.
///
/// The gate this counts is in front of a BILLABLE call, and "did we skip the vendor?" is
/// not visible in the response or in the database — a reused case and a fresh one look
/// alike from outside. Counting the port call is the only place the difference shows.
struct CountingKyc {
	inner: StubKyc,
	sessions: Arc<AtomicUsize>,
}

impl CountingKyc {
	fn new(sessions: Arc<AtomicUsize>) -> Self {
		Self {
			inner: StubKyc::new(SECRET.to_string(), "https://evinvest.test/cabinet".to_string()),
			sessions,
		}
	}
}

#[async_trait]
impl KycProvider for CountingKyc {
	fn name(&self) -> &'static str {
		self.inner.name()
	}

	async fn start_session(&self, case_id: Uuid, requested_tier: u32) -> Result<KycSession, DomainError> {
		self.sessions.fetch_add(1, Ordering::SeqCst);
		self.inner.start_session(case_id, requested_tier).await
	}

	fn parse_callback(&self, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
		self.inner.parse_callback(headers, body, now)
	}
}

/// [`CountingKyc`] whose vendor call can be held open by the test.
///
/// A race needs the first caller to still be "at the vendor" when the second arrives,
/// and a stub that answers instantly closes that window before a test can aim at it.
/// `entered` fires when a session is being bought; nothing completes until [`Self::release`].
struct GatedKyc {
	inner: CountingKyc,
	entered: Notify,
	open: watch::Sender<bool>,
}

impl GatedKyc {
	fn new(sessions: Arc<AtomicUsize>) -> Self {
		Self {
			inner: CountingKyc::new(sessions),
			entered: Notify::new(),
			open: watch::channel(false).0,
		}
	}

	/// Let every vendor call through — the ones waiting and any that arrive later.
	fn release(&self) {
		self.open.send_replace(true);
	}
}

#[async_trait]
impl KycProvider for GatedKyc {
	fn name(&self) -> &'static str {
		self.inner.name()
	}

	async fn start_session(&self, case_id: Uuid, requested_tier: u32) -> Result<KycSession, DomainError> {
		// Tally first, so a start that reaches the vendor is counted even while held.
		let session = self.inner.start_session(case_id, requested_tier).await;
		self.entered.notify_one();
		self.open.subscribe().wait_for(|open| *open).await.expect("the test keeps the gate alive");
		session
	}

	fn parse_callback(&self, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
		self.inner.parse_callback(headers, body, now)
	}
}

/// The body BOTH unavailable causes must produce, byte for byte.
fn unavailable_body() -> Value {
	json!({ "error": "kyc_unavailable", "contact": SUPPORT })
}

struct Harness {
	router: Router,
	users: Arc<PgUsers>,
	cases: Arc<PgKycCases>,
	pool: PgPool,
}

async fn setup() -> Option<Harness> {
	setup_with(Some(Arc::new(StubKyc::new(SECRET.to_string(), "https://evinvest.test/cabinet".to_string())))).await
}

/// The same router with the vendor swapped out, so a test can drive the two ways
/// verification becomes unavailable — absent, and present but refusing.
async fn setup_with(provider: Option<Arc<dyn KycProvider>>) -> Option<Harness> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let users = Arc::new(PgUsers::new(pool.clone()));
	let cases = Arc::new(PgKycCases::new(pool.clone()));
	let state = web::WebState::try_new(
		AuthService::unconfigured(),
		"https://evinvest.test".to_string(),
		false,
		KycDeps {
			users: users.clone(),
			cases: cases.clone(),
			notifications: Arc::new(PgNotifications::new(pool.clone())),
			provider,
			support_email: SUPPORT.to_string(),
		},
	)
	.await
	.expect("build the web state");

	Some(Harness {
		router: web::router(state),
		users,
		cases,
		pool,
	})
}

impl Harness {
	/// A brand-new user, so runs neither collide nor need a clean database.
	async fn user(&self) -> UserId {
		let subject = AuthSubject::parse(&format!("kyc-itest-{}", Uuid::new_v4())).unwrap();
		self.users.provision(subject, Email::parse("kyc@example.com").unwrap(), true).await.expect("provision").id()
	}

	/// Open a case the way `/kyc/start` does, without going through the session cookie.
	async fn case(&self, user: UserId, tier: u32) -> (Uuid, String) {
		let id = Uuid::new_v4();
		let provider_ref = format!("stub-{id}");
		let redirect_url = format!("https://evinvest.test/cabinet?kyc_session={provider_ref}");
		self.cases.open_case(id, user, PROVIDER, &provider_ref, tier, &redirect_url).await.expect("open case");
		(id, provider_ref)
	}

	/// Finish this user's open cases without a verdict, so a test about the WINDOW cap is
	/// not answered by the reuse rule first. Both are gates on the same route and the
	/// running-case one runs earlier.
	async fn close_open_cases(&self, user: UserId) {
		sqlx::query("UPDATE kyc_cases SET status = 'abandoned', decision_at = now() WHERE user_id = $1 AND decision_at IS NULL")
			.bind(user.raw())
			.execute(&self.pool)
			.await
			.expect("close cases");
	}

	/// `POST /kyc/start` as the cabinet reaches it. `body` is passed through verbatim.
	async fn start(&self, cookie: &str, csrf: Option<&str>, body: &str) -> (StatusCode, Value) {
		let (status, _, body) = self.start_response(cookie, csrf, body).await;
		(status, body)
	}

	/// The same, with the response HEADERS kept — `/kyc/start` reads the session through
	/// the same rotating reader `/kyc/status` does, so it owes the browser the same
	/// refreshed access cookie.
	async fn start_response(&self, cookie: &str, csrf: Option<&str>, body: &str) -> (StatusCode, HeaderMap, Value) {
		let mut request = Request::builder()
			.method("POST")
			.uri("/kyc/start")
			.header("content-type", "application/json")
			.header("cookie", cookie);
		if let Some(token) = csrf {
			request = request.header("x-ev-csrf", token);
		}
		let response = self.router.clone().oneshot(request.body(Body::from(body.to_owned())).unwrap()).await.expect("router answered");
		let status = response.status();
		let headers = response.headers().clone();
		let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("read body");
		(status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
	}

	/// `GET /kyc/status` as the cabinet reaches it. `None` is the signed-out caller.
	async fn status(&self, cookie: Option<&str>) -> (StatusCode, Value) {
		let (status, _, body) = self.status_response(cookie).await;
		(status, body)
	}

	/// `GET /kyc/status` with the response HEADERS kept, for the two properties that
	/// live there rather than in the body: the rotated access cookie, and the
	/// cache directives a polled per-user document needs.
	async fn status_response(&self, cookie: Option<&str>) -> (StatusCode, HeaderMap, Value) {
		let mut request = Request::builder().method("GET").uri("/kyc/status");
		if let Some(cookie) = cookie {
			request = request.header("cookie", cookie);
		}
		let response = self.router.clone().oneshot(request.body(Body::empty()).unwrap()).await.expect("router answered");
		let status = response.status();
		let headers = response.headers().clone();
		let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("read body");
		(status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
	}

	async fn post(&self, body: Vec<u8>, signature: String, timestamp: i64) -> (StatusCode, Value) {
		self.post_with(body, Some(signature), None, timestamp).await
	}

	/// The webhook with either signature header, both, or neither.
	async fn post_with(&self, body: Vec<u8>, signature: Option<String>, signature_v2: Option<String>, timestamp: i64) -> (StatusCode, Value) {
		let mut builder = Request::builder()
			.method("POST")
			.uri("/kyc/callback/didit")
			.header("content-type", "application/json")
			.header("x-timestamp", timestamp.to_string());
		if let Some(v) = signature {
			builder = builder.header("x-signature", v);
		}
		if let Some(v) = signature_v2 {
			builder = builder.header("x-signature-v2", v);
		}
		let request = builder.body(Body::from(body)).unwrap();
		let response = self.router.clone().oneshot(request).await.expect("router answered");
		let status = response.status();
		let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("read body");
		let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
		(status, value)
	}

	async fn kyc_level(&self, user: UserId) -> u32 {
		self.users.find_by_id(user).await.expect("read user").expect("user exists").kyc_level()
	}

	/// How many KYC_CHANGED rows this user has on the cross-plane outbox. The number the
	/// money plane will mirror, so a double application shows up here first.
	async fn kyc_changed_count(&self, user: UserId) -> i64 {
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_outbox WHERE user_id = $1 AND kind = 'KYC_CHANGED'")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.expect("count outbox rows")
	}

	/// Attempt rows this user owns. A vendor call that failed must leave this at zero:
	/// a `pending` row nobody can act on later reads as an abandoned attempt.
	async fn case_count(&self, user: UserId) -> i64 {
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kyc_cases WHERE user_id = $1")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.expect("count cases")
	}

	/// The signed instant the stored verdict was made at — the ordering key an
	/// out-of-order delivery is judged against.
	async fn case_event_at(&self, id: Uuid) -> Option<i64> {
		sqlx::query_scalar::<_, Option<i64>>("SELECT event_at FROM kyc_cases WHERE id = $1")
			.bind(id)
			.fetch_one(&self.pool)
			.await
			.expect("read case")
	}

	async fn case_row(&self, id: Uuid) -> (String, bool, Value) {
		sqlx::query_as::<_, (String, bool, Value)>("SELECT status, decision_at IS NOT NULL, payload FROM kyc_cases WHERE id = $1")
			.bind(id)
			.fetch_one(&self.pool)
			.await
			.expect("read case")
	}
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A webhook body in Didit's shape. `extra` is merged in at the top level so a test can
/// bolt on the fields an attacker would.
fn body(session_id: &str, status: &str, vendor_data: &str, at: i64, extra: Value) -> Vec<u8> {
	let mut payload = json!({
		"event_id": Uuid::new_v4().to_string(),
		"webhook_type": "status.updated",
		"timestamp": at,
		"session_id": session_id,
		"status": status,
		"vendor_data": vendor_data,
		"workflow_id": "wf-test",
		"environment": "sandbox",
		"decision": {
			"kyc": { "status": status, "document_type": "Passport", "issuing_state": "PRT", "document_number": "SECRET-DOC-9911", "date_of_birth": "1990-01-01" },
			"liveness": { "status": "Approved" },
		},
	});
	if let (Some(target), Some(extra)) = (payload.as_object_mut(), extra.as_object()) {
		for (k, v) in extra {
			target.insert(k.clone(), v.clone());
		}
	}
	serde_json::to_vec(&payload).unwrap()
}

fn signed(raw: &[u8]) -> String {
	sign_body(SECRET, raw)
}

macro_rules! harness {
	() => {
		match setup().await {
			Some(h) => h,
			None => {
				eprintln!("DATABASE_URL unset — skipping real-DB test");
				return;
			}
		}
	};
}

#[tokio::test]
async fn an_approval_raises_the_level_and_emits_exactly_one_kyc_changed() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;
	assert_eq!(h.kyc_level(user).await, 0);

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let (status, answer) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK, "a correctly signed approval is accepted: {answer}");
	assert_eq!(
		h.kyc_level(user).await,
		1,
		"the case's requested tier is applied through the same set_kyc_level the operator RPC uses"
	);
	assert_eq!(h.kyc_changed_count(user).await, 1, "the money plane must see the decision exactly once");

	let (case_status, decided, payload) = h.case_row(case_id).await;
	assert_eq!(case_status, "approved");
	assert!(decided, "an approval is a decision, so decision_at is set");
	let stored = payload.to_string();
	assert!(!stored.contains("SECRET-DOC-9911"), "no document number may reach the database: {stored}");
	assert!(!stored.contains("1990-01-01"), "no date of birth may reach the database: {stored}");
	assert_eq!(payload["document_country"], "PRT", "the allowlisted metadata IS kept");
}

#[tokio::test]
async fn a_redelivery_is_idempotent() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let (first, _) = h.post(raw.clone(), signed(&raw), at).await;
	assert_eq!(first, StatusCode::OK);

	// Byte-for-byte the same delivery, exactly as an at-least-once provider retries it.
	let (second, answer) = h.post(raw.clone(), signed(&raw), at).await;
	assert_eq!(second, StatusCode::OK, "a retry must not look like a failure, or the provider retries forever");
	assert_eq!(answer["duplicate"], true);
	assert_eq!(h.kyc_changed_count(user).await, 1, "a replayed approval must not re-emit KYC_CHANGED onto the outbox");
	assert_eq!(h.kyc_level(user).await, 1);
}

#[tokio::test]
async fn the_body_cannot_name_the_user_it_acts_on() {
	let h = harness!();
	let victim = h.user().await;
	let attacker = h.user().await;
	// The attacker legitimately opens their own case, then tries to spend its verdict on
	// someone else by naming them in the body.
	let (case_id, session_id) = h.case(attacker, 1).await;

	let at = now();
	let raw = body(
		&session_id,
		"Approved",
		&case_id.to_string(),
		at,
		json!({ "user_id": victim.to_string(), "userId": victim.to_string(), "kyc_level": 3 }),
	);
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(h.kyc_level(victim).await, 0, "identity comes from the stored case, never from the request body");
	assert_eq!(h.kyc_changed_count(victim).await, 0, "nothing about the victim may reach the cross-plane outbox");
	assert_eq!(h.kyc_level(attacker).await, 1, "and the tier is the CASE's, not the body's — a body cannot ask for more");
}

#[tokio::test]
async fn a_failed_attempt_never_lowers_an_existing_level() {
	let h = harness!();
	let user = h.user().await;
	// An operator granted tier 2 by hand.
	h.users.set_kyc_level(user, 2, &AdminAction::system("kyc_level_set"), 0).await.expect("manual grant");
	let manual_events = h.kyc_changed_count(user).await;

	// Every way an attempt can fail, one after another, on cases at the entry tier.
	// Spelling copied from Didit's integration guide: `"Kyc Expired"`, not `"KYC
	// Expired"`. This list used to carry the wrong capitalisation AND a `"Not Finished"`
	// that the vendor does not send, and it passed — because the adapter carried the
	// same wrong word. A vocabulary test is only worth something when its words come
	// from the vendor's document rather than from the code it is checking.
	for failure in ["Declined", "Abandoned", "Expired", "Kyc Expired"] {
		let (case_id, session_id) = h.case(user, 1).await;
		let at = now();
		let raw = body(&session_id, failure, &case_id.to_string(), at, json!({}));
		let (status, _) = h.post(raw.clone(), signed(&raw), at).await;

		assert_eq!(status, StatusCode::OK, "{failure} is a legitimate verdict, not a bad request");
		assert_eq!(h.kyc_level(user).await, 2, "{failure} must not take away a level a human granted");
		assert_eq!(h.case_row(case_id).await.0, failure.to_lowercase().replace(' ', "_"), "the case still records what happened");
	}
	assert_eq!(h.kyc_changed_count(user).await, manual_events, "a failed attempt emits nothing across the bridge");
}

#[tokio::test]
async fn an_in_review_verdict_leaves_the_level_alone() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "In Review", &case_id.to_string(), at, json!({}));
	assert_eq!(h.post(raw.clone(), signed(&raw), at).await.0, StatusCode::OK);

	assert_eq!(h.kyc_level(user).await, 0, "a reviewer has not answered yet");
	let (status, decided, _) = h.case_row(case_id).await;
	assert_eq!(status, "in_review");
	assert!(!decided, "in_review is not a decision, so decision_at stays NULL");
}

#[tokio::test]
async fn a_forged_signature_is_refused_and_writes_nothing() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;
	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));

	for (label, signature) in [
		("a signature under the wrong secret", sign_body("not-our-secret", &raw)),
		("a syntactically plausible guess", "0".repeat(64)),
		("nonsense", "deadbeef".to_string()),
		("an empty header", String::new()),
	] {
		let (status, _) = h.post(raw.clone(), signature, at).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{label} must be refused");
	}

	// A valid signature over a DIFFERENT body must not carry this one.
	let other = body(&session_id, "Declined", &case_id.to_string(), at, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&other), at).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED, "the signature covers these exact bytes");

	assert_eq!(h.kyc_level(user).await, 0);
	assert_eq!(h.kyc_changed_count(user).await, 0);
	assert_eq!(h.case_row(case_id).await.0, "pending", "a refused callback leaves the case untouched");
}

#[tokio::test]
async fn a_stale_delivery_is_refused() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	// Correctly signed, genuinely from the provider — but captured and replayed later.
	let sent = now() - KYC_CALLBACK_WINDOW_SECS - 60;
	let raw = body(&session_id, "Approved", &case_id.to_string(), sent, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&raw), sent).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);

	// Re-stamping the transport header does not help: only the body's timestamp is under
	// the signature, and it is the one that puts this delivery out of the window.
	let (restamped, _) = h.post(raw.clone(), signed(&raw), now()).await;
	assert_eq!(restamped, StatusCode::BAD_REQUEST, "the replay window has to hold against a re-stamped X-Timestamp");

	// And a delivery with no timestamp at all.
	let request = Request::builder()
		.method("POST")
		.uri("/kyc/callback/didit")
		.header("content-type", "application/json")
		.header("x-signature", signed(&raw))
		.body(Body::from(raw))
		.unwrap();
	let response = h.router.clone().oneshot(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::BAD_REQUEST);

	assert_eq!(h.kyc_level(user).await, 0);
	assert_eq!(h.case_row(case_id).await.0, "pending");
}

/// The replay window must not rest on a field the body is free to omit.
///
/// `X-Timestamp` is not covered by either signature, so an attacker holding one captured
/// delivery can re-stamp it at will. The only dateable copy is the one INSIDE the signed
/// body — and if that one may be absent, the window is a formality: the same bytes stay
/// acceptable a year later. A body with no `timestamp` is therefore malformed, not
/// "in-window by default".
#[tokio::test]
async fn a_body_with_no_signed_timestamp_is_refused_however_fresh_the_header() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	// A genuine, correctly signed approval captured long ago — with the one field that
	// dates it stripped out, exactly as a vendor that "forgot" to send it would look.
	let captured = now() - KYC_CALLBACK_WINDOW_SECS * 10;
	let mut payload: Value = serde_json::from_slice(&body(&session_id, "Approved", &case_id.to_string(), captured, json!({}))).unwrap();
	payload.as_object_mut().unwrap().remove("timestamp");
	let raw = serde_json::to_vec(&payload).unwrap();
	assert!(!String::from_utf8_lossy(&raw).contains("timestamp"));

	// The signature is VALID over these exact bytes, and the transport header says now.
	let (status, _) = h.post(raw.clone(), signed(&raw), now()).await;

	assert_eq!(status, StatusCode::BAD_REQUEST, "an undateable body cannot be checked against the replay window");
	assert_eq!(h.kyc_level(user).await, 0);
	assert_eq!(h.kyc_changed_count(user).await, 0);
	assert_eq!(h.case_row(case_id).await.0, "pending", "and nothing about the case moved");
}

#[tokio::test]
async fn a_callback_for_an_unknown_session_is_refused() {
	let h = harness!();
	let at = now();
	let raw = body("stub-does-not-exist", "Approved", "", at, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;
	// 404 rather than 200: this is also the shape of the race where the webhook overtakes
	// the insert, and a retry is exactly what resolves it.
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_echoed_correlation_value_must_match_the_case_it_names() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "Approved", &Uuid::new_v4().to_string(), at, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::BAD_REQUEST, "vendor_data is a cross-check; a mismatch means the two ends disagree");
	assert_eq!(h.kyc_level(user).await, 0);

	// The point of the refusal, and what it did not do before #54: a 400 that keeps the
	// write is not a refusal. The row must still be the `pending` one `open_case` wrote —
	// no status, no `decision_at`, no allowlisted payload out of a body we just rejected.
	let (status, decided, payload) = h.case_row(case_id).await;
	assert_eq!(status, "pending", "a refused delivery must not move the case it disagreed about");
	assert!(!decided);
	assert_eq!(payload, json!({}));
	assert_eq!(h.case_event_at(case_id).await, None, "and it must not become the case's ordering key either");
}

#[tokio::test]
async fn a_disagreeing_redelivery_is_refused_rather_than_re_asserted() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	assert_eq!(h.post(raw.clone(), signed(&raw), at).await.0, StatusCode::OK);
	assert_eq!(h.kyc_level(user).await, 1);

	// Same verdict, same case, wrong correlation value. Read as a redelivery this would be
	// re-applied; the cross-check outranks that, because a delivery the two ends disagree
	// about is not evidence of anything — including of what the case already holds.
	let raw = body(&session_id, "Approved", &Uuid::new_v4().to_string(), at, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(h.kyc_changed_count(user).await, 1, "and it emits nothing onto the cross-plane outbox");
}

#[tokio::test]
async fn the_webhook_needs_no_cookie_and_no_csrf_token() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;
	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));

	// Exactly what a server-to-server caller sends: no cookie jar, no `x-ev-csrf`.
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;
	assert_eq!(status, StatusCode::OK, "a CSRF check here could only ever refuse the provider");
	assert_eq!(h.kyc_level(user).await, 1);
}

/// Opens a REAL session in the locker the router reads, and returns the cookie header
/// plus the CSRF token to pair with it.
///
/// `None` when Redis is absent: the in-process fallback is per-instance by design (see
/// `web_sessions.rs`), so a session opened here would be invisible to the router.
async fn signed_in(user: UserId) -> Option<(String, String)> {
	signed_in_for(user, 900).await
}

/// The same, with the access token's remaining lifetime chosen by the caller.
///
/// A value inside `ACCESS_SKEW_SECS` (30) is what puts `WebSessions::fresh` on its
/// REFRESH path — the one that rotates the pair and saves it — which is the only way a
/// test can observe whether a handler hands the new token back to the browser.
async fn signed_in_for(user: UserId, access_ttl_secs: i64) -> Option<(String, String)> {
	std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty())?;
	let sessions = web::WebSessions::from_env().await.expect("session store");
	let now_s = now();
	let (session_id, csrf, _) = sessions
		.put(evconcierge_contracts::concierge::v1::TokenResponse {
			access_token: "access".into(),
			access_expires_at: now_s + access_ttl_secs,
			refresh_token: "family.secret".into(),
			refresh_expires_at: now_s + 3600,
			user: Some(evconcierge_contracts::concierge::v1::UserSummary {
				user_id: user.to_string(),
				email: "kyc@example.com".into(),
				status: "active".into(),
				token_version: 0,
				role: "investor".into(),
				role_is_break_glass: false,
			}),
		})
		.await
		.expect("open session")
		.expect("token pair carries a user");
	Some((format!("ev_session={session_id}; ev_csrf={csrf}"), csrf))
}

/// The signed-in half. It needs the session locker to be SHARED with the router's own
/// instance, which only Redis gives us — the in-process fallback is per-instance by
/// design (see `web_sessions.rs`).
#[tokio::test]
async fn start_opens_a_case_and_hands_back_a_redirect() {
	let h = harness!();
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	// Without the double-submit header this is an ordinary cookie-authenticated POST and
	// must be refused, exactly as /auth/logout is.
	let refused = h.start(&cookie, None, "").await;
	assert_eq!(refused.0, StatusCode::FORBIDDEN);

	// And no body at all is the shape the cabinet actually sends.
	let (status, answer) = h.start(&cookie, Some(&csrf), "").await;
	assert_eq!(status, StatusCode::OK);
	let case_id: Uuid = answer["case_id"].as_str().expect("case_id").parse().expect("a uuid");
	assert!(answer["redirect_url"].as_str().is_some_and(|u| u.starts_with("https://evinvest.test/cabinet")));

	let (status, decided, _) = h.case_row(case_id).await;
	assert_eq!(status, "pending");
	assert!(!decided);
	let owner: Uuid = sqlx::query_scalar("SELECT user_id FROM kyc_cases WHERE id = $1").bind(case_id).fetch_one(&h.pool).await.unwrap();
	assert_eq!(owner, user.raw(), "the case belongs to the session's user");
}

/// The CSRF check, driven through the only state-changing route these tests reach.
///
/// A near miss is the interesting input: it is what a comparison that stops at the first
/// differing byte answers fastest, and it is what the constant-time one must answer
/// exactly like a wild guess. Timing is not assertable from here — what is, is that
/// narrowing the comparison did not narrow the CHECK: the header must still match the
/// cookie AND the server-side copy, and a correct token must still get through.
#[tokio::test]
async fn a_csrf_token_that_is_merely_close_is_still_refused() {
	let h = harness!();
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let mut near = csrf.clone();
	let last = near.pop().expect("a non-empty token");
	near.push(if last == 'a' { 'b' } else { 'a' });

	assert_eq!(h.start(&cookie, Some(&near), "").await.0, StatusCode::FORBIDDEN, "one byte out is out");
	assert_eq!(
		h.start(&cookie, Some(&format!("{csrf}x")), "").await.0,
		StatusCode::FORBIDDEN,
		"a correct prefix is not a correct token"
	);
	assert_eq!(h.start(&cookie, Some(""), "").await.0, StatusCode::FORBIDDEN);

	// The half this plane has that the cabinet does not: a caller who controls their own
	// cookie jar can make the header and the cookie agree, and it still is not enough —
	// the value held on the session is what decides.
	let session_cookie = cookie.split(';').next().expect("the session cookie comes first");
	assert_eq!(
		h.start(&format!("{session_cookie}; ev_csrf={near}"), Some(&near), "").await.0,
		StatusCode::FORBIDDEN,
		"a matching header and cookie the server never issued are still refused"
	);

	assert_eq!(h.case_count(user).await, 0, "and none of that opened a case");

	// A check nothing gets through is not a check.
	assert_eq!(h.start(&cookie, Some(&csrf), "").await.0, StatusCode::OK);
	assert_eq!(h.case_count(user).await, 1);
}

/// The applicant used to choose the level they would be granted.
///
/// `POST {"tier":2}` was recorded as the case's `requested_tier`, the vendor was never
/// told (`start_session` dropped it and asked for the one workflow it has), and the
/// approval that came back from a document-and-selfie check granted level 2 — which
/// `banking`'s `users.proto` defines as proof of address and source of funds. The cabinet
/// has never sent the field. It is now ignored rather than rejected: nothing here could
/// honour it, and a 400 would only break a client that is already wrong.
#[tokio::test]
async fn a_tier_in_the_body_is_ignored_and_the_case_opens_at_the_entry_tier() {
	let h = harness!();
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let (status, answer) = h.start(&cookie, Some(&csrf), r#"{"tier":2}"#).await;
	assert_eq!(status, StatusCode::OK, "an unknown field is not a client error: {answer}");
	let case_id: Uuid = answer["case_id"].as_str().expect("case_id").parse().expect("a uuid");

	let tier: i32 = sqlx::query_scalar("SELECT requested_tier FROM kyc_cases WHERE id = $1")
		.bind(case_id)
		.fetch_one(&h.pool)
		.await
		.unwrap();
	assert_eq!(tier, 1, "the body does not decide what the applicant is applying for");
}

/// The other half of the same hole, and the half the entry point cannot close.
///
/// Cases asking for tier 2 are already in the table — every `{"tier":2}` sent before the
/// field was removed — and some of them have not been decided yet. Refusing the field at
/// `/kyc/start` does nothing for a case opened yesterday, so the ceiling that retires them
/// is the one applied where the VERDICT lands.
#[tokio::test]
async fn a_case_asking_for_tier_2_still_grants_only_what_the_vendor_verified() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 2).await;

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(h.kyc_level(user).await, 1, "one workflow, one tier's worth of evidence — whatever the row asked for");
}

/// `/kyc/start` had nothing between the session check and a BILLABLE `POST /v3/session/`.
/// A user already mid-flow — refreshing, coming back from the vendor, double-clicking —
/// must get the attempt they are in, not a second one bought at our expense.
#[tokio::test]
async fn a_second_start_reuses_the_live_case_and_never_calls_the_vendor() {
	let counter = Arc::new(AtomicUsize::new(0));
	let Some(h) = setup_with(Some(Arc::new(CountingKyc::new(counter.clone())))).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let (status, first) = h.start(&cookie, Some(&csrf), "{}").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(counter.load(Ordering::SeqCst), 1, "the first start is the one that buys a session");

	let (status, second) = h.start(&cookie, Some(&csrf), "{}").await;
	assert_eq!(status, StatusCode::OK, "a user mid-flow is not an error");
	assert_eq!(counter.load(Ordering::SeqCst), 1, "and the second start must not reach the vendor at all");
	assert_eq!(second["case_id"], first["case_id"], "they are sent back to the attempt they already have");
	assert_eq!(second["redirect_url"], first["redirect_url"]);
	assert_eq!(h.case_count(user).await, 1, "one attempt, one row — a second would read as an abandoned try");
}

/// Two starts from one user at the SAME time — the race #56 describes.
///
/// The gate is a read, so this cannot be shown with two sequential calls: the second
/// must arrive while the first is still at the vendor, before its row exists. The gated
/// provider makes that moment as long as the test needs — `start_session` announces it
/// has been entered and then holds until released — and every call, not just the first,
/// waits on the same release, so a build that lets both through fails on the tally
/// instead of hanging.
#[tokio::test]
async fn two_simultaneous_starts_buy_one_session_and_share_the_case() {
	let counter = Arc::new(AtomicUsize::new(0));
	let provider = Arc::new(GatedKyc::new(counter.clone()));
	let Some(h) = setup_with(Some(provider.clone())).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let start = |router: Router, cookie: String, csrf: String| {
		tokio::spawn(async move {
			let request = Request::builder()
				.method("POST")
				.uri("/kyc/start")
				.header("content-type", "application/json")
				.header("cookie", cookie)
				.header("x-ev-csrf", csrf)
				.body(Body::from("{}"))
				.unwrap();
			let response = router.oneshot(request).await.expect("router answered");
			let status = response.status();
			let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("read body");
			(status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
		})
	};

	let first = start(h.router.clone(), cookie.clone(), csrf.clone());
	tokio::time::timeout(std::time::Duration::from_secs(10), provider.entered.notified())
		.await
		.expect("the first start reaches the vendor");

	// Now the first start is inside the vendor call and its row does not exist yet: this
	// is exactly where a second read of the gate would say "no live case".
	let second = start(h.router.clone(), cookie, csrf);
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	assert!(!second.is_finished(), "the second start must wait for the first, not answer on its own read of the gate");
	assert_eq!(counter.load(Ordering::SeqCst), 1, "and it must not have reached the vendor while waiting");

	provider.release();
	let (first_status, first) = tokio::time::timeout(std::time::Duration::from_secs(10), first)
		.await
		.expect("the first start completes")
		.expect("join");
	let (second_status, second) = tokio::time::timeout(std::time::Duration::from_secs(10), second)
		.await
		.expect("the second start completes")
		.expect("join");

	assert_eq!(first_status, StatusCode::OK, "{first}");
	assert_eq!(second_status, StatusCode::OK, "a user mid-flow is not an error: {second}");
	assert_eq!(counter.load(Ordering::SeqCst), 1, "one session bought — the second start is handed the first one's case");
	assert_eq!(second["case_id"], first["case_id"]);
	assert_eq!(second["redirect_url"], first["redirect_url"]);
	assert_eq!(h.case_count(user).await, 1, "one attempt, one row — the second would later read as an abandoned try");
}

/// The loop the issue describes: call it again and again. Once the running case is out of
/// the way the window cap is what stands between one account and the platform's Didit
/// balance — and past that balance every user's verification answers 503.
#[tokio::test]
async fn the_window_cap_refuses_a_start_without_calling_the_vendor() {
	let counter = Arc::new(AtomicUsize::new(0));
	let Some(h) = setup_with(Some(Arc::new(CountingKyc::new(counter.clone())))).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	// Walking away from each attempt is what a determined caller would do to get past the
	// reuse rule, so the test does exactly that.
	for attempt in 1..=START_MAX_PER_WINDOW {
		let (status, answer) = h.start(&cookie, Some(&csrf), "{}").await;
		assert_eq!(status, StatusCode::OK, "attempt {attempt} is still inside the cap: {answer}");
		h.close_open_cases(user).await;
	}
	assert_eq!(counter.load(Ordering::SeqCst), START_MAX_PER_WINDOW as usize);

	let (status, _) = h.start(&cookie, Some(&csrf), "{}").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the caller is over the cap, and this is their doing — not an outage");
	assert_eq!(
		counter.load(Ordering::SeqCst),
		START_MAX_PER_WINDOW as usize,
		"the refusal happens BEFORE the vendor is dialled — that is the whole point"
	);
	assert_eq!(h.case_count(user).await, START_MAX_PER_WINDOW, "and no row is written for a refused start");
}

/// A user must never be told "you did something wrong" or shown a stack of vendor noise
/// when the fault is entirely on our side of the fence.
///
/// This is the arm reached when the vendor is not configured at all. Note that no cookie
/// and no CSRF token are sent: the check runs FIRST, so a caller who cannot verify learns
/// that before being asked to prove anything.
#[tokio::test]
async fn an_unconfigured_vendor_answers_the_unavailable_contract() {
	let Some(h) = setup_with(None).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};

	let request = Request::builder()
		.method("POST")
		.uri("/kyc/start")
		.header("content-type", "application/json")
		.body(Body::from(r#"{"tier":1}"#))
		.unwrap();
	let response = h.router.clone().oneshot(request).await.expect("router answered");

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "temporary, not a client mistake");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("read body");
	let answer: Value = serde_json::from_slice(&bytes).expect("a json body the cabinet can switch on");
	assert_eq!(answer, unavailable_body());
}

/// The out-of-balance case, which is the one that actually motivated this arm: the keys
/// are present and correct, and the vendor still will not open a session.
///
/// Three things are asserted, and the first is the point of the whole exercise — the user
/// sees EXACTLY what they see when the feature was never configured. One screen in the
/// cabinet, not two, and no way to tell from outside which of our problems it is.
#[tokio::test]
async fn a_vendor_that_refuses_a_session_degrades_exactly_like_an_unconfigured_one() {
	let Some(h) = setup_with(Some(Arc::new(RefusingKyc))).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let request = Request::builder()
		.method("POST")
		.uri("/kyc/start")
		.header("content-type", "application/json")
		.header("cookie", cookie)
		.header("x-ev-csrf", csrf)
		.body(Body::from(r#"{"tier":1}"#))
		.unwrap();
	let response = h.router.clone().oneshot(request).await.expect("router answered");

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("read body");
	let answer: Value = serde_json::from_slice(&bytes).expect("a json body");
	assert_eq!(answer, unavailable_body(), "the same answer an unconfigured vendor gives");

	// Nothing the vendor said about OUR account may cross the boundary: not the status
	// code it chose, not its prose, not even its name. A user learning that a payment is
	// overdue at a supplier is a leak of a business fact, dressed up as an error message.
	let raw = String::from_utf8_lossy(&bytes).to_lowercase();
	for leak in ["402", "balance", "payment", "didit", "insufficient"] {
		assert!(!raw.contains(leak), "vendor detail {leak:?} leaked into the response: {raw}");
	}

	// And no half-open attempt is left behind. A `pending` row here would later be read
	// as a user who started verifying and gave up, which is the opposite of what happened.
	assert_eq!(h.case_count(user).await, 0, "a failed vendor call must not leave a case row");
}

/// The delivery arrives with a raw signature that cannot match, because something on the
/// way here re-serialised the JSON — a Cloudflare tunnel, Traefik, and a Next.js rewrite
/// in the site conductor all sit between Didit and this handler. `X-Signature-V2` is what
/// survives that, and it must be enough on its own.
#[tokio::test]
async fn a_repacked_delivery_is_accepted_on_the_v2_signature_alone() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	// What a middlebox leaves behind: a body that means the same thing, byte-for-byte
	// different, and a raw signature computed over what the vendor originally sent.
	let repacked = serde_json::to_vec(&serde_json::from_slice::<Value>(&raw).unwrap()).unwrap();
	let stale_raw_signature = signed(&raw);

	let (status, answer) = h.post_with(repacked.clone(), Some(stale_raw_signature), sign_body_v2(SECRET, &repacked), at).await;

	assert_eq!(status, StatusCode::OK, "V2 alone authenticates it: {answer}");
	assert_eq!(h.kyc_level(user).await, 1);
	assert_eq!(h.case_row(case_id).await.0, "approved");
}

/// Neither signature valid is still a rejection, and it must write nothing. Accepting
/// either form must not become accepting anything.
#[tokio::test]
async fn a_delivery_with_two_wrong_signatures_is_refused() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let (status, _) = h.post_with(raw.clone(), Some(sign_body("wrong-secret", &raw)), sign_body_v2("wrong-secret", &raw), at).await;

	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(h.kyc_level(user).await, 0, "a forgery moves nothing");
	assert_eq!(h.case_row(case_id).await.0, "pending", "and writes nothing");
}

/// Didit will add words to its status vocabulary. The day it does, this endpoint must
/// keep answering 2xx: a 4xx would reject a genuine delivery and a 5xx would put the
/// vendor in a retry loop that can never succeed. Nothing is written either way.
#[tokio::test]
async fn a_status_this_build_does_not_know_is_accepted_and_changes_nothing() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let raw = body(&session_id, "Some Status We Have Never Seen", &case_id.to_string(), at, json!({}));
	let (status, answer) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK, "a vocabulary change must not break the endpoint");
	assert_eq!(answer["ignored"], "unknown status");
	assert_eq!(h.kyc_level(user).await, 0, "an unclassifiable status is never guessed into an approval");
	let (recorded, decided, _) = h.case_row(case_id).await;
	assert_eq!(recorded, "pending", "and the case is left exactly as it was");
	assert!(!decided);
	assert_eq!(h.kyc_changed_count(user).await, 0);
}

/// A reviewer asking for specific steps again puts the attempt back in the user's hands.
/// It is NOT an outcome: no level moves, and the case must stay open — a `decision_at`
/// here would claim the flow had finished when it has just restarted.
#[tokio::test]
async fn a_resubmission_reopens_the_case_rather_than_closing_it() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	// The vendor sends `resubmit_info` in place of `decision` here. The parser must not
	// need `decision` to be present.
	let raw = body(
		&session_id,
		"Resubmitted",
		&case_id.to_string(),
		at,
		json!({ "resubmit_info": { "nodes_to_resubmit": ["id_verification"], "reasons": ["document is blurred"] } }),
	);
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(h.kyc_level(user).await, 0, "a resubmission grants nothing");
	let (recorded, decided, _) = h.case_row(case_id).await;
	assert_eq!(recorded, "resubmitted");
	assert!(!decided, "the attempt is running again, so it carries no decision_at");
	assert_eq!(h.kyc_changed_count(user).await, 0);
}

/// Didit offers `event_id` as a dedupe key. We do not use it — idempotency is the status
/// comparison under `FOR UPDATE` on `(provider, provider_ref)`, which holds whatever
/// `event_id` happens to mean — so a body without one must behave exactly like a body
/// with one, redelivery included.
#[tokio::test]
async fn a_body_without_an_event_id_is_handled_and_still_idempotent() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let at = now();
	let mut payload: Value = serde_json::from_slice(&body(&session_id, "Approved", &case_id.to_string(), at, json!({}))).unwrap();
	payload.as_object_mut().unwrap().remove("event_id");
	let raw = serde_json::to_vec(&payload).unwrap();
	assert!(!String::from_utf8_lossy(&raw).contains("event_id"));

	let (first, _) = h.post(raw.clone(), signed(&raw), at).await;
	let (second, again) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(first, StatusCode::OK);
	assert_eq!(second, StatusCode::OK);
	assert_eq!(again["duplicate"], true, "the second delivery is recognised without an event_id");
	assert_eq!(h.kyc_level(user).await, 1);
	assert_eq!(h.kyc_changed_count(user).await, 1, "exactly one crossing of the bridge");
}

/// The vendor path must not undo a human decision it raced with.
///
/// The old handler read the level on one connection and wrote it on another. Between the
/// two, an operator under `Permission::KycManage` can commit anything — including a grant
/// ABOVE what a vendor may ever give. The webhook then wrote its own stale conclusion on
/// top, and a tier 3 the consilium had just granted came back as tier 2, decided by a
/// vendor that is not allowed past 2 in the first place. Nothing logs an error: from the
/// inside it looks like an approval being applied.
///
/// Asserted as an INVARIANT rather than as one interleaving: whichever of the two commits
/// first, a vendor approval for tier 2 must never leave the user below the 3 a human set.
/// The row lock is what makes both orders end the same way, so the test also pins that the
/// comparison really is inside it — the webhook must BLOCK while the row is held.
#[tokio::test]
async fn a_vendor_approval_never_overwrites_a_concurrent_human_grant() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	// Hold the user row exactly where `raise_kyc_level_to` needs it, so both writers line
	// up behind it instead of interleaving by luck.
	let mut holder = h.pool.begin().await.unwrap();
	sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
		.bind(user.raw())
		.fetch_one(&mut *holder)
		.await
		.unwrap();

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let router = h.router.clone();
	let webhook = tokio::spawn(async move {
		let request = Request::builder()
			.method("POST")
			.uri("/kyc/callback/didit")
			.header("content-type", "application/json")
			.header("x-timestamp", at.to_string())
			.header("x-signature", sign_body(SECRET, &raw))
			.body(Body::from(raw))
			.unwrap();
		router.oneshot(request).await.expect("router answered").status()
	});

	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	assert!(
		!webhook.is_finished(),
		"the approval must block on the user row — a comparison taken outside the lock is the race this guards"
	);

	// The human decision lands first, granting a tier no vendor may reach.
	let operator = h.users.clone();
	let grant = tokio::spawn(async move { operator.set_kyc_level(user, 3, &AdminAction::system("kyc_level_set"), 0).await });
	holder.rollback().await.unwrap();

	let webhook_status = tokio::time::timeout(std::time::Duration::from_secs(10), webhook)
		.await
		.expect("the webhook completes")
		.expect("join");
	tokio::time::timeout(std::time::Duration::from_secs(10), grant)
		.await
		.expect("the grant completes")
		.expect("join")
		.expect("the operator grant succeeds");

	assert_eq!(webhook_status, StatusCode::OK, "the approval is still handled, whichever order it landed in");
	assert_eq!(h.kyc_level(user).await, 3, "a vendor approval must never pull a human's tier 3 back down");
}

/// Arrival order is not send order, and a decided case must not be reopened by a straggler.
///
/// Didit retries at roughly one and four minutes, so an `in_review` retry landing after
/// the `approved` that superseded it is ordinary. Judged only by "the status differs", it
/// would win: the case would go back to `in_review`, `decision_at` would be cleared, and
/// the row explaining why this user holds tier 2 would stop claiming any decision at all.
#[tokio::test]
async fn a_stale_verdict_never_reopens_a_decided_case() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	// The approval the vendor sent second and we received first.
	let decided_at = now();
	let approval = body(&session_id, "Approved", &case_id.to_string(), decided_at, json!({}));
	let (status, _) = h.post(approval.clone(), signed(&approval), decided_at).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(h.kyc_level(user).await, 1);

	// The earlier `in_review`, retried into the window and arriving late. Signed, fresh
	// enough to pass the replay check, and genuinely older than the verdict on file.
	let sent_at = decided_at - 60;
	let straggler = body(&session_id, "In Review", &case_id.to_string(), sent_at, json!({}));
	let (status, answer) = h.post(straggler.clone(), signed(&straggler), now()).await;

	assert_eq!(status, StatusCode::OK, "the delivery is genuine, so there is nothing for the vendor to retry");
	assert_eq!(answer["ignored"], "superseded");
	let (case_status, decided, _) = h.case_row(case_id).await;
	assert_eq!(case_status, "approved", "the case still holds the verdict it was decided on");
	assert!(decided, "and it still records WHEN it was decided");
	assert_eq!(h.case_event_at(case_id).await, Some(decided_at), "the ordering key is the approval's, not the straggler's");
	assert_eq!(h.kyc_level(user).await, 1);
	assert_eq!(h.kyc_changed_count(user).await, 1, "an out-of-order delivery emits nothing");
}

/// The ordering rule must not freeze a case at its first verdict.
///
/// `Kyc Expired` after `Approved` is a real Didit transition — a verification that aged
/// out at the vendor — and it is strictly LATER, so it applies. What it does not do is
/// move a level: only an approval grants one, and taking one away is a human act under
/// `KycManage`. A guard that refused this would trade a lost audit trail for the
/// out-of-order fix.
#[tokio::test]
async fn a_later_verdict_still_moves_a_decided_case() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	let approved_at = now() - 120;
	let approval = body(&session_id, "Approved", &case_id.to_string(), approved_at, json!({}));
	let (status, _) = h.post(approval.clone(), signed(&approval), now()).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(h.kyc_level(user).await, 1);

	let expired_at = now();
	let expiry = body(&session_id, "Kyc Expired", &case_id.to_string(), expired_at, json!({}));
	let (status, _) = h.post(expiry.clone(), signed(&expiry), expired_at).await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(h.case_row(case_id).await.0, "kyc_expired", "a genuinely later verdict is recorded");
	assert_eq!(h.case_event_at(case_id).await, Some(expired_at));
	assert_eq!(h.kyc_level(user).await, 1, "but a vendor still never takes a level away");
	assert_eq!(h.kyc_changed_count(user).await, 1);
}

/// The verdict and the level are two writes, and only the first is under the case lock.
///
/// So there is a real window where `kyc_cases` says `approved` and the account is still
/// at zero: the level write lost its connection, the pod rolled, Postgres dropped the
/// session. The vendor's retry is the ONLY thing that ever revisits a decided case — and
/// this handler used to spend it, answering 200 to the redelivery and returning before
/// the level was touched. That made the split state permanent, because every later
/// delivery is a redelivery too. The user stays unverified while their case row says
/// otherwise, and nothing in the system disagrees loudly enough for anyone to notice.
#[tokio::test]
async fn a_verdict_recorded_without_its_level_is_repaired_by_the_redelivery() {
	let h = harness!();
	let user = h.user().await;
	let (case_id, session_id) = h.case(user, 1).await;

	// Exactly the halfway state: `record_decision` committed, the level write never ran.
	let at = now();
	let decision = KycDecision {
		provider_ref: session_id.clone(),
		status: KycStatus::Approved,
		vendor_data: case_id.to_string(),
		metadata: json!({}),
		signed_at: at,
	};
	h.cases.record_decision(PROVIDER, &decision).await.expect("record the verdict");
	assert_eq!(h.case_row(case_id).await.0, "approved", "the case is decided...");
	assert_eq!(h.kyc_level(user).await, 0, "...and the account has not caught up");

	// The vendor retries, as it does. This delivery is a REDELIVERY — the stored status
	// already equals the incoming one — and it must still finish the job.
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let (status, answer) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(answer["duplicate"], true, "it is still a duplicate, and still answered 2xx");
	assert_eq!(h.kyc_level(user).await, 1, "the retry is what repairs a verdict whose level never landed");
	assert_eq!(h.kyc_changed_count(user).await, 1, "and it emits the ONE event the original attempt owed the money plane");
}

/// THE CONTRACT of `GET /kyc/status`, asserted as whole JSON documents rather than field
/// by field.
///
/// The cabinet stops guessing here. Until this route existed its only signal was
/// `kyc_level === 0`, which cannot tell "never started" from "waiting on the vendor" —
/// so the screen offered Start to a user already mid-flow and bought a second BILLED
/// session for the attempt they were in (#190). Everything that replaces that inference
/// is a name in these documents, which is why the assertions compare the whole body: a
/// field quietly renamed, added or dropped is a cabinet that silently reverts to
/// guessing, and the failure would otherwise surface as a user being charged for a
/// duplicate case rather than as a red test.
#[tokio::test]
async fn the_status_route_publishes_the_pinned_shape() {
	let h = harness!();
	let user = h.user().await;
	let Some((cookie, _csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	// Nobody signed in: one machine-readable code, no prose. This route answers JSON for
	// every outcome — the cabinet parses one shape inside one feature.
	let (status, answer) = h.status(None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(answer, json!({ "error": "unauthenticated" }));

	// A signed-in user who has never started. `case: null` is the whole difference from
	// tier 0 alone, and it is what makes offering Start correct.
	let (status, answer) = h.status(Some(&cookie)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(answer, json!({ "level": 0, "case": null }), "the never-started shape, verbatim");

	// Mid-flow. `resumable` is what sends the browser back into the session already paid
	// for instead of opening a second one.
	let (case_id, session_id) = h.case(user, 1).await;
	let (status, answer) = h.status(Some(&cookie)).await;
	assert_eq!(status, StatusCode::OK);
	let created_at = answer["case"]["created_at"].as_i64().expect("created_at is a number");
	assert!((created_at - now()).abs() < 300, "created_at is unix seconds, not milliseconds or a string: {created_at}");
	assert_eq!(
		answer,
		json!({ "level": 0, "case": { "status": "pending", "requested_tier": 1, "created_at": created_at, "resumable": true } }),
		"the running-case shape, verbatim — keys, nesting and the persisted status vocabulary"
	);

	// A case opened before `kyc_cases.redirect_url` existed still holds the start gate,
	// but there is nowhere to send the browser back to, and the cabinet must be told so
	// rather than rendering a dead link.
	sqlx::query("UPDATE kyc_cases SET redirect_url = NULL WHERE id = $1")
		.bind(case_id)
		.execute(&h.pool)
		.await
		.expect("clear redirect_url");
	let (_, answer) = h.status(Some(&cookie)).await;
	assert_eq!(answer["case"]["resumable"], false, "a case with no vendor URL is live but not resumable");

	// The verdict lands. The level moves and the case leaves the answer entirely: a
	// decided case is history, and history is not what this route reports.
	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	assert_eq!(h.post(raw.clone(), signed(&raw), at).await.0, StatusCode::OK);

	let (status, answer) = h.status(Some(&cookie)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(answer, json!({ "level": 1, "case": null }), "the verified shape, verbatim");
}

/// The status route must not depend on the vendor being configured.
///
/// With `DIDIT_*` unset `/kyc/start` answers 503, and a cabinet that could not read the
/// level or the running case in that state would fall back to exactly the guesswork this
/// route removes — on the day verification is already broken.
#[tokio::test]
async fn status_answers_while_verification_itself_is_unavailable() {
	let Some(h) = setup_with(None).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let (start_status, start_answer) = h.start(&cookie, Some(&csrf), "").await;
	assert_eq!(start_status, StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(start_answer, unavailable_body());

	let (status, answer) = h.status(Some(&cookie)).await;
	assert_eq!(status, StatusCode::OK, "the level is a fact of this plane, not of the vendor's");
	assert_eq!(answer, json!({ "level": 0, "case": null }));
}

/// The polled route must leave the browser holding the token the SERVER holds.
///
/// Reading a session is not a read: inside `ACCESS_SKEW_SECS` of expiry
/// `WebSessions::fresh` renews the access token, rotates the refresh token and saves the
/// new pair. A handler that takes the caller out of that and drops the rest leaves the
/// store with the new pair and the browser with a JWT expiring inside the half-minute —
/// after which every `/api/*` call the cabinet makes eats a 401 and a round trip through
/// `/api/auth/session` before it works. On a route the cabinet POLLS, that window is not
/// a corner case: it is most polls.
///
/// Pinned on both KYC routes, because both read the session through the same reader.
#[tokio::test]
async fn reading_the_session_hands_the_refreshed_access_cookie_back() {
	let h = harness!();
	let user = h.user().await;
	// Inside the 30-second skew, so `fresh` takes its refresh path.
	let Some((cookie, csrf)) = signed_in_for(user, 10).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	let (status, headers, _) = h.status_response(Some(&cookie)).await;
	assert_eq!(status, StatusCode::OK);
	let cookies: Vec<&str> = headers.get_all("set-cookie").iter().map(|v| v.to_str().expect("ascii cookie")).collect();
	assert!(
		cookies.iter().any(|c| c.starts_with("ev_access=")),
		"the access cookie the store now holds must come back with the answer, got {cookies:?}"
	);

	// `/kyc/start` reaches the session through the same reader and owes the same cookie.
	let (status, headers, _) = h.start_response(&cookie, Some(&csrf), "").await;
	assert_eq!(status, StatusCode::OK);
	let cookies: Vec<&str> = headers.get_all("set-cookie").iter().map(|v| v.to_str().expect("ascii cookie")).collect();
	assert!(cookies.iter().any(|c| c.starts_with("ev_access=")), "start rotates the same pair, got {cookies:?}");
}

/// A per-user document on a polled route says so to every cache between here and the
/// browser.
///
/// This answer names one person's verification level. It leaves the pod through the
/// shell's `/api/kyc/:path*` rewrite and a CDN, and unlike `/auth/session` it does not
/// always carry a `Set-Cookie` an intermediary might take as a hint. Without directives
/// of its own, a 200 here is something a shared cache is entitled to store and replay.
#[tokio::test]
async fn status_is_never_cacheable() {
	let h = harness!();
	let user = h.user().await;
	let Some((cookie, _csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};

	for cookie in [Some(cookie.as_str()), None] {
		let (_, headers, _) = h.status_response(cookie).await;
		assert_eq!(
			headers.get("cache-control").and_then(|v| v.to_str().ok()),
			Some("no-store"),
			"hit and refusal are equally personal"
		);
		assert_eq!(headers.get("vary").and_then(|v| v.to_str().ok()), Some("Cookie"));
	}
}

/// With no vendor configured, a stored URL is not something the cabinet may offer.
///
/// `/kyc/start` refuses with 503 BEFORE it reaches the branch that hands a running
/// case's `redirect_url` back, so `resumable: true` here would put a Continue button on
/// screen whose every click is an outage — on precisely the day this route exists to
/// stop the cabinet from guessing.
#[tokio::test]
async fn a_running_case_is_not_resumable_while_the_vendor_is_unconfigured() {
	let Some(h) = setup_with(None).await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = h.user().await;
	let Some((cookie, csrf)) = signed_in(user).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};
	// A case WITH a redirect_url, exactly as a start before the outage left it.
	h.case(user, 1).await;

	let (_, answer) = h.status(Some(&cookie)).await;
	assert_eq!(answer["case"]["status"], "pending", "the attempt is still reported — it is a fact of this plane");
	assert_eq!(answer["case"]["resumable"], false, "nothing the cabinet may offer: start cannot run at all");

	// And that is not a guess about start — it is what start does.
	assert_eq!(h.start(&cookie, Some(&csrf), "").await.0, StatusCode::SERVICE_UNAVAILABLE);
}
