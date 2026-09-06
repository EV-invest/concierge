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

use std::sync::Arc;

use axum::{
	Router,
	body::Body,
	http::{Request, StatusCode},
};
use concierge::{
	infrastructure::{
		db,
		kyc::{cases::PgKycCases, didit::sign_body, stub::StubKyc},
		notifications::PgNotifications,
		users::PgUsers,
	},
	ports::{KYC_CALLBACK_WINDOW_SECS, KycCaseRepository, UserDirectoryRepository},
	web::{self, KycDeps},
};
use domain::users::{AuthSubject, Email, UserId};
use evconcierge_auth::AuthService;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const SECRET: &str = "kyc-integration-secret";
const PROVIDER: &str = "stub";

struct Harness {
	router: Router,
	users: Arc<PgUsers>,
	cases: Arc<PgKycCases>,
	pool: PgPool,
}

async fn setup() -> Option<Harness> {
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
			provider: Some(Arc::new(StubKyc::new(SECRET.to_string(), "https://evinvest.test/cabinet".to_string()))),
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
		self.cases.open_case(id, user, PROVIDER, &provider_ref, tier).await.expect("open case");
		(id, provider_ref)
	}

	async fn post(&self, body: Vec<u8>, signature: String, timestamp: i64) -> (StatusCode, Value) {
		let request = Request::builder()
			.method("POST")
			.uri("/kyc/callback/didit")
			.header("content-type", "application/json")
			.header("x-signature", signature)
			.header("x-timestamp", timestamp.to_string())
			.body(Body::from(body))
			.unwrap();
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
	let (case_id, session_id) = h.case(user, 2).await;
	assert_eq!(h.kyc_level(user).await, 0);

	let at = now();
	let raw = body(&session_id, "Approved", &case_id.to_string(), at, json!({}));
	let (status, answer) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::OK, "a correctly signed approval is accepted: {answer}");
	assert_eq!(
		h.kyc_level(user).await,
		2,
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
	let (case_id, session_id) = h.case(attacker, 2).await;

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
	assert_eq!(h.kyc_level(attacker).await, 2, "and the tier is the CASE's, not the body's — 3 is a human-only decision");
}

#[tokio::test]
async fn a_failed_attempt_never_lowers_an_existing_level() {
	let h = harness!();
	let user = h.user().await;
	// An operator granted tier 2 by hand.
	h.users.set_kyc_level(user, 2).await.expect("manual grant");
	let manual_events = h.kyc_changed_count(user).await;

	// Every way an attempt can fail, one after another, on cases asking for tier 2.
	for failure in ["Declined", "Abandoned", "Expired", "Not Finished", "KYC Expired"] {
		let (case_id, session_id) = h.case(user, 2).await;
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
	let (case_id, session_id) = h.case(user, 2).await;

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
	let (case_id, session_id) = h.case(user, 2).await;
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
	let (case_id, session_id) = h.case(user, 2).await;

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
	let (_case_id, session_id) = h.case(user, 2).await;

	let at = now();
	let raw = body(&session_id, "Approved", &Uuid::new_v4().to_string(), at, json!({}));
	let (status, _) = h.post(raw.clone(), signed(&raw), at).await;

	assert_eq!(status, StatusCode::BAD_REQUEST, "vendor_data is a cross-check; a mismatch means the two ends disagree");
	assert_eq!(h.kyc_level(user).await, 0);
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

/// The signed-in half. It needs the session locker to be SHARED with the router's own
/// instance, which only Redis gives us — the in-process fallback is per-instance by
/// design (see `web_sessions.rs`).
#[tokio::test]
async fn start_opens_a_case_and_hands_back_a_redirect() {
	let h = harness!();
	if std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()).is_none() {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	}
	let user = h.user().await;
	let sessions = web::WebSessions::from_env().await.expect("session store");
	let now_s = now();
	let (session_id, csrf, _) = sessions
		.put(evconcierge_contracts::concierge::v1::TokenResponse {
			access_token: "access".into(),
			access_expires_at: now_s + 900,
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

	let start = |cookie: String, header: Option<String>, body: &'static str| {
		let mut request = Request::builder()
			.method("POST")
			.uri("/kyc/start")
			.header("content-type", "application/json")
			.header("cookie", cookie);
		if let Some(token) = header {
			request = request.header("x-ev-csrf", token);
		}
		h.router.clone().oneshot(request.body(Body::from(body)).unwrap())
	};

	let cookie = format!("ev_session={session_id}; ev_csrf={csrf}");
	// Without the double-submit header this is an ordinary cookie-authenticated POST and
	// must be refused, exactly as /auth/logout is.
	let refused = start(cookie.clone(), None, r#"{"tier":2}"#).await.unwrap();
	assert_eq!(refused.status(), StatusCode::FORBIDDEN);

	// Tier 3 is a human decision; no provider may be asked for it.
	let too_high = start(cookie.clone(), Some(csrf.clone()), r#"{"tier":3}"#).await.unwrap();
	assert_eq!(too_high.status(), StatusCode::BAD_REQUEST);

	let response = start(cookie, Some(csrf), r#"{"tier":2}"#).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
	let answer: Value = serde_json::from_slice(&bytes).unwrap();
	let case_id: Uuid = answer["case_id"].as_str().expect("case_id").parse().expect("a uuid");
	assert!(answer["redirect_url"].as_str().is_some_and(|u| u.starts_with("https://evinvest.test/cabinet")));

	let (status, decided, _) = h.case_row(case_id).await;
	assert_eq!(status, "pending");
	assert!(!decided);
	let owner: Uuid = sqlx::query_scalar("SELECT user_id FROM kyc_cases WHERE id = $1").bind(case_id).fetch_one(&h.pool).await.unwrap();
	assert_eq!(owner, user.raw(), "the case belongs to the session's user");
}
