//! The identity-verification routes: the signed-in start, and the provider's webhook.
//!
//! These two handlers sit at opposite ends of the trust spectrum and are written that
//! way on purpose.
//!
//! `POST /kyc/start` is an ordinary session route — cookie, CSRF, the user id taken from
//! the session locker exactly as `/auth/sessions` takes it.
//!
//! `POST /kyc/callback/didit` is the first PUBLIC, non-OAuth entry point in this plane.
//! Nothing about the caller is known but the shared webhook secret, so:
//!   * the HMAC is checked in constant time and an unconfigured secret fails CLOSED;
//!   * deliveries outside a 300-second window are refused, and a body carrying no
//!     signed timestamp is refused outright rather than falling back on the unsigned
//!     `X-Timestamp` header;
//!   * the identity acted on comes from the STORED `kyc_cases` row, looked up by the
//!     provider's session id, and never from the request body. `vendor_data` is a
//!     cross-check and nothing more — treating it as identity would turn this route
//!     into "POST yourself tier 2" — and it is checked inside the write transaction, so a
//!     delivery that fails it leaves the case where it was;
//!   * no cookie is read and no CSRF token is expected: there is no browser here, and a
//!     CSRF check on a server-to-server call is a check that can only ever be wrong.
//!
//! When verification cannot be run at all — no vendor configured, or a vendor that will
//! not open a session — `/kyc/start` DEGRADES rather than errors: one 503, one stable
//! body, one support address (see [`StartError`]). The user is never shown a technical
//! failure and never given the impression they did something wrong.
//!
//! `/kyc/start` also decides ALL of that before it dials the vendor, because opening a
//! session is billed and the balance behind it is shared by every user on the platform.
//! A caller already mid-flow is handed the case they are in, and a caller past
//! [`START_MAX_PER_WINDOW`] is refused — both without a vendor call. What sits on the
//! other side of that balance is not a degraded feature: it is the fail-closed 503 above,
//! for everyone, which arrives as silence.

use axum::{
	Json,
	body::Bytes,
	extract::State,
	http::{HeaderMap, HeaderName, StatusCode, header},
	response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
	ports::{CallbackHeaders, CaseDecision, KycCallbackError, KycCase, KycLevelChange, KycStatus},
	web::{WebState, now_secs, routes::verify_csrf},
};

/// The topic a verification decision is announced on. Emitting is a no-op for anyone who
/// has not subscribed, so this never becomes unsolicited mail.
const TOPIC: &str = "account:verification";

/// The one error code `/kyc/start` publishes. The cabinet switches on THIS, never on the
/// prose beside it, so the wording can change without breaking a screen.
const KYC_UNAVAILABLE: &str = "kyc_unavailable";

/// What every answer from `GET /kyc/status` carries, hit or refusal.
///
/// `Vary: Cookie` alone would be enough for a cache that honours it; `no-store` is here
/// because the answer is keyed to a cookie a shared cache has no business keying on at
/// all, and it costs one header to stop guessing which intermediary is well behaved.
const NO_STORE: [(HeaderName, &str); 2] = [(header::CACHE_CONTROL, "no-store"), (header::VARY, "Cookie")];

/// What `/kyc/start` can answer with.
///
/// Everything except [`StartError::Unavailable`] keeps the plain-text
/// `(StatusCode, &'static str)` shape the rest of this surface answers in — a `From`
/// impl lets `?` carry those through untouched, so `/kyc/start` refuses a bad CSRF token
/// or an absent session exactly the way `/auth/logout` does.
pub(super) enum StartError {
	/// Verification cannot be run right now — and the caller is told no more than that.
	///
	/// BOTH causes collapse here: no vendor configured, and a configured vendor that
	/// would not open a session (out of balance, over quota, down, timing out, answering
	/// nonsense). Which of the two it is, is ours to fix and not the user's to read
	/// about, so on the wire they are indistinguishable and the cabinet needs one screen
	/// rather than two.
	///
	/// Deliberately NOT a taxonomy of vendor status codes. We do not know what Didit
	/// returns for an exhausted balance and the documentation does not say, so a `match`
	/// on 402/403/429 would be at its most brittle exactly where being wrong costs the
	/// most: the arm that decides whether a user sees a support address or a stack of
	/// technical noise.
	Unavailable {
		contact: String,
	},
	Plain(StatusCode, &'static str),
}

impl StartError {
	fn unavailable(st: &super::Inner) -> Self {
		Self::Unavailable { contact: st.support_email.clone() }
	}
}

impl From<(StatusCode, &'static str)> for StartError {
	fn from((status, message): (StatusCode, &'static str)) -> Self {
		Self::Plain(status, message)
	}
}

/// The session locker could not be read. The ONE failure [`session_user`] has that is
/// not "nobody is signed in" — kept as its own type so each route renders it in its own
/// body shape without either of them having to guess what an absent session means.
pub(super) struct SessionStoreDown;

impl From<SessionStoreDown> for StartError {
	fn from(_: SessionStoreDown) -> Self {
		Self::Plain(StatusCode::INTERNAL_SERVER_ERROR, "session store unavailable")
	}
}

/// The signed-in caller, plus the access token their browser must be left holding.
///
/// The token half is not incidental. Reading a session ROTATES it (see
/// [`session_user`]), so a handler that takes the caller and drops the rest signs the
/// browser out from under itself.
pub(super) struct Caller {
	id: UserId,
	access_token: String,
	remaining_secs: i64,
}

impl Caller {
	/// Put the refreshed access token back in the browser, the way `/auth/session` does.
	fn refreshed(self, st: &super::Inner, jar: CookieJar) -> CookieJar {
		jar.add(st.cookies.server_cookie(st.cookies.access.clone(), self.access_token, self.remaining_secs))
	}
}

/// The signed-in caller behind the session cookie, or `None` when there is no live
/// session to read one from.
///
/// One reader for BOTH KYC routes. `/kyc/status` answers "is this person mid-flow?" and
/// `/kyc/start` acts on it; a second copy of "take the cookie, refresh the session,
/// parse the id" is a second place for those two to stop agreeing about who is asking.
///
/// This READ WRITES. `WebSessions::fresh` renews an access token inside
/// `ACCESS_SKEW_SECS` of expiry: it calls `AuthRpc::refresh`, rotates the refresh token
/// and saves the new pair, and past the refresh deadline it deletes the session
/// outright. So the returned [`Caller`] carries the new access token, and every caller
/// of this function owes the browser a `Set-Cookie` — otherwise the server holds the
/// rotated pair and the browser holds a JWT that expires within the half-minute. On a
/// polled route that is not a corner case; it is most polls that land in the window.
async fn session_user(st: &super::Inner, jar: &CookieJar) -> Result<Option<Caller>, SessionStoreDown> {
	let Some(session_id) = jar.get(&st.cookies.session).map(|c| c.value().to_string()) else {
		return Ok(None);
	};
	let fresh = st.sessions.fresh(&session_id, &st.auth).await.map_err(|e| {
		tracing::error!(error = ?e, "kyc: the web session store failed");
		SessionStoreDown
	})?;
	// A cookie whose stored pair no longer carries a parsable user is the same answer as
	// no cookie at all: there is nobody to act for.
	Ok(fresh.and_then(|f| {
		Uuid::parse_str(&f.user.user_id).map(UserId::from_raw).ok().map(|id| Caller {
			id,
			access_token: f.access_token,
			remaining_secs: f.remaining_secs,
		})
	}))
}

impl IntoResponse for StartError {
	fn into_response(self) -> Response {
		match self {
			// 503 because the condition is TEMPORARY, and a stable machine-readable body
			// so the cabinet never has to parse prose. The vendor's own words never
			// reach it: "insufficient balance on the Didit account" is a fact about our
			// business, and it belongs in the log line, not in a browser.
			Self::Unavailable { contact } => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": KYC_UNAVAILABLE, "contact": contact }))).into_response(),
			Self::Plain(status, message) => (status, message).into_response(),
		}
	}
}

/// The tier a case is opened for, and the only one this route can produce.
///
/// The applicant used to name it in the request body. Nothing downstream ever read it —
/// `KycProvider::start_session` took the tier and dropped it, and the vendor was asked
/// for the same single workflow either way — so `{"tier":2}` bought level 2, meaning
/// "proof of address and source of funds" in `banking`'s `users.proto`, for a document
/// and a selfie. The field is gone rather than validated: there is nothing here that
/// could honour it, and the cabinet never sent it (see `kyc-client.ts`, "No body on
/// purpose"). A body carrying it is accepted and ignored, which is what makes removing it
/// safe for anything already in flight.
const ENTRY_TIER: u32 = 1;

/// How far back [`START_MAX_PER_WINDOW`] counts.
const START_WINDOW_SECS: i64 = 24 * 60 * 60;

/// How many cases one user may open inside [`START_WINDOW_SECS`].
///
/// Five, because honest use is bounded and cheap to picture: a rejected document, a
/// session left open until it expired, a phone that ran out of battery mid-flow, a
/// retry. Someone genuinely trying to get verified is not on their sixth attempt in a
/// day; someone on their fiftieth is spending the platform's Didit balance, and past
/// zero the route fails closed for EVERY user. A number this side of honest use costs a
/// rare user one day's wait; a number the other side costs everyone verification.
///
/// A constant and not configuration: an env var here is a knob nobody would ever be in a
/// position to turn correctly at 3am, and one more value to carry through the deploy
/// chain for no decision it would help anyone make.
pub const START_MAX_PER_WINDOW: i64 = 5;

#[derive(Serialize)]
pub struct StartResponse {
	/// Where to send the browser to perform the verification.
	redirect_url: String,
	case_id: String,
}

/// `POST /kyc/start` — open a verification case for the signed-in caller and hand back
/// the provider's URL.
///
/// Takes NO body. It used to take a tier and act on it; see [`ENTRY_TIER`].
pub async fn start(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Result<(CookieJar, Json<StartResponse>), StartError> {
	let st = &st.inner;
	let Some(provider) = st.kyc.as_ref() else {
		// `debug!`, not `error!`: an unconfigured vendor is a SUPPORTED state that the
		// boot already announced once, and paging on every request would bury the real
		// incident below in noise.
		tracing::debug!("kyc: start refused — no provider is configured");
		return Err(StartError::unavailable(st));
	};
	// State-changing POST behind a cookie ⇒ the same double-submit check `/auth/logout`
	// and `DELETE /auth/sessions` run.
	if !verify_csrf(st, &jar, &headers).await? {
		return Err((StatusCode::FORBIDDEN, "csrf check failed").into());
	}

	let Some(caller) = session_user(st, &jar).await? else {
		return Err((StatusCode::UNAUTHORIZED, "unauthenticated").into());
	};
	let user_id = caller.id;
	// Same rotation as on `/kyc/status`, and the same obligation: this read may have
	// renewed the pair, so the browser leaves with the token the store now holds.
	let jar = caller.refreshed(st, jar);

	// One start per user at a time, from the gate read to the row write. The gate below
	// is a READ: two requests arriving together would both see "no live case", both
	// dial the vendor and both insert — two billed sessions, one of which the user can
	// never finish (#56). Held here, in process, rather than as a database lock, because
	// what it spans is the vendor round trip, and a transaction kept open across a
	// network call was the property #55 refused to buy. The second caller waits at most
	// the vendor timeout, then re-reads the gate and is handed the case the first one
	// opened — the same answer a sequential second call gets. Across replicas this does
	// not reach, and there the window cap is still what bounds the spend.
	let _flight = st.kyc_starts.acquire(user_id).await;

	// EVERYTHING below this line happens before the vendor is dialled, and that ordering is
	// the whole point: `POST /v3/session/` is billed, and the platform's balance is a shared
	// resource one signed-in account could otherwise drain in a loop. What is behind that
	// balance is not a feature degrading — it is a fail-closed 503 on every user's
	// verification, arriving as silence, because a polite "try later" is not something
	// anyone files a ticket about.
	let gate = st.kyc_cases.start_gate(user_id, START_WINDOW_SECS).await.map_err(|e| {
		// Refusing here rather than proceeding: an unreadable gate is exactly the state in
		// which we do not know whether spending a session is safe.
		tracing::error!(error = %e, "kyc: could not read the start gate");
		StartError::unavailable(st)
	})?;

	// An attempt already running gets handed back, not replaced. The user is mid-flow —
	// they refreshed, came back from the vendor, or clicked twice — and buying a second
	// session would charge us to give them a worse version of what they have: two open
	// cases, one of which they will abandon and which will then read as a user who gave up.
	if let Some(live) = &gate.live {
		if let Some(redirect_url) = &live.redirect_url {
			tracing::debug!(case_id = %live.id, "kyc: start reused the caller's running case");
			return Ok((
				jar,
				Json(StartResponse {
					redirect_url: redirect_url.clone(),
					case_id: live.id.to_string(),
				}),
			));
		}
		// A case opened before `kyc_cases.redirect_url` existed. There is no URL to hand
		// back and no way to fetch one, so the choice is a new session or a dead end — and
		// stranding a user who did nothing wrong is the worse of the two. The window cap
		// below still applies, so this cannot be looped.
		tracing::info!(case_id = %live.id, "kyc: the caller's running case predates redirect_url — opening a fresh session");
	}

	if gate.recent >= START_MAX_PER_WINDOW {
		// 429 and not the `Unavailable` 503: this one IS about the caller, it is not a
		// failure on our side, and telling them so is honest. Plain text like every other
		// refusal on this route — the cabinet has no screen keyed to this and adding a
		// second machine-readable code for a state honest use does not reach would be
		// contract surface bought for nothing.
		tracing::warn!(%user_id, opened = gate.recent, "kyc: start refused — the caller is over the per-user window cap");
		return Err((StatusCode::TOO_MANY_REQUESTS, "too many verification attempts today").into());
	}

	// The vendor is called BEFORE the row is written, because the row's identity key is
	// the vendor's session id and there is no meaningful case without one. The cost is a
	// vendor session nobody claims when the insert fails; its webhook then finds no case
	// and is refused, which is the safe direction. The reverse order would need either a
	// placeholder `provider_ref` (colliding on the uniqueness that IS the idempotency
	// key) or an open transaction held across a network call.
	//
	// This ordering is also what keeps a failed vendor call from leaving a `pending` row
	// behind. A dangling `pending` would later read as "the user started and walked
	// away", which is a lie about a person who never got the chance, and it would poison
	// every funnel number computed off these rows.
	let case_id = Uuid::new_v4();
	let session = provider.start_session(case_id, ENTRY_TIER).await.map_err(|e| {
		// `error!` — NOT `warn!` — and the reason is the whole point of this arm. From
		// the user's side an exhausted vendor balance looks like silence: they simply
		// cannot verify, and nobody files a ticket about a screen that politely says to
		// try later. `error!` is what `error_monitoring::tracing_layer()` (wired in
		// `main::init_tracing`) forwards to Sentry, so this line is the only thing that
		// will wake a human. The vendor's own text goes here and nowhere else.
		tracing::error!(error = %e, provider = provider.name(), %case_id, tier = ENTRY_TIER, "kyc: the provider would not open a session — verification is unavailable to users");
		StartError::unavailable(st)
	})?;
	st.kyc_cases
		.open_case(case_id, user_id, provider.name(), &session.provider_ref, ENTRY_TIER, &session.redirect_url)
		.await
		.map_err(|e| {
			// Same screen as a vendor outage: our store being unreachable is no more the
			// user's business than the vendor's balance, and it is just as temporary.
			tracing::error!(error = %e, %case_id, "kyc: failed to record the opened case");
			StartError::unavailable(st)
		})?;

	tracing::info!(%case_id, tier = ENTRY_TIER, provider = provider.name(), "kyc: case opened");
	Ok((
		jar,
		Json(StartResponse {
			redirect_url: session.redirect_url,
			case_id: case_id.to_string(),
		}),
	))
}

/// What `GET /kyc/status` publishes.
///
/// PINNED by an integration test, field name for field name. Until this route existed
/// the cabinet had one signal — `kyc_level === 0` — and inferred everything else from
/// it: a user mid-flow was indistinguishable from one who had never started, so the
/// screen offered "Start verification" again and bought a second BILLED vendor session
/// for an attempt already running (#190). The names below are what replaces that
/// inference, which makes renaming one a user-visible regression rather than a
/// refactor.
#[derive(Serialize)]
pub struct StatusResponse {
	level: u32,
	case: Option<CaseView>,
}

/// The caller's RUNNING attempt.
///
/// `null` when they are in none. A finished case is history, and history is not what
/// this route is for — the question it answers is "may the cabinet offer Start?", and
/// only something in flight changes that answer. An operator's per-user case history is
/// a different surface with a different audience.
#[derive(Serialize)]
pub struct CaseView {
	/// The persisted vocabulary (`pending`, `in_progress`, `in_review`, `resubmitted`),
	/// not a prose label: the cabinet renders its own wording in five locales.
	status: String,
	requested_tier: u32,
	/// Unix seconds, like every other instant this plane publishes.
	created_at: i64,
	/// Whether the browser can be sent back into the vendor session this case opened.
	///
	/// `false` for a row written before `kyc_cases.redirect_url` existed: the attempt is
	/// real and still holds the start gate, but there is nowhere to resume it — the
	/// cabinet must offer a fresh start rather than a dead link.
	///
	/// `false` too while no vendor is configured, for the same reason read from the other
	/// end: what this field promises is not "a URL exists" but "Continue will work", and
	/// `/kyc/start` refuses 503 before it ever reaches the branch that would hand that URL
	/// back. The two causes are one answer on purpose — a cabinet that had to tell them
	/// apart would be back to inferring, which is what this route removes.
	resumable: bool,
}

/// Why `GET /kyc/status` could not answer.
///
/// JSON from the outset. `/kyc/start` grew plain-text refusals before there was a
/// cabinet screen keyed to any of them; a client that has to parse two body shapes
/// inside one feature is a client that will eventually parse one of them wrong.
pub(super) enum StatusError {
	Unauthenticated,
	Internal,
}

impl From<SessionStoreDown> for StatusError {
	fn from(_: SessionStoreDown) -> Self {
		Self::Internal
	}
}

impl IntoResponse for StatusError {
	fn into_response(self) -> Response {
		let (status, code) = match self {
			Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
			Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
		};
		// A refusal is as personal as a hit: "you are not signed in" cached and replayed
		// to somebody who is would be the same mistake wearing a different status code.
		(status, NO_STORE, Json(json!({ "error": code }))).into_response()
	}
}

/// `GET /kyc/status` — the caller's verification level and the attempt they are in, if
/// any.
///
/// A READ, and deliberately independent of the vendor: with `DIDIT_*` unset `/kyc/start`
/// answers 503, but the level a user already holds and the case they already opened are
/// facts of this plane, and a screen that cannot read them degrades into the guesswork
/// this route exists to remove.
///
/// No CSRF token: this route changes nothing the CALLER asked to change, and a
/// double-submit check on a GET is a check that can only ever be wrong. It is not
/// side-effect free, though — reading the session rotates its tokens (see
/// [`session_user`]), which is why the jar comes back out.
///
/// `Cache-Control: no-store` and `Vary: Cookie` because this is a per-user document on
/// the first route of this surface a browser POLLS. Everything between here and the user
/// — the shell's `/api/kyc/:path*` rewrite and the CDN behind it — is otherwise free to
/// read a 200 with no cache directives as cacheable, and one user's verification level
/// served to another is the worst shape that mistake can take.
pub async fn status(State(st): State<WebState>, jar: CookieJar) -> Result<(CookieJar, [(HeaderName, &'static str); 2], Json<StatusResponse>), StatusError> {
	let st = &st.inner;
	let Some(caller) = session_user(st, &jar).await? else {
		return Err(StatusError::Unauthenticated);
	};
	let user_id = caller.id;

	// The level comes from the directory, never from the session's cached summary: a
	// verdict applied while this session was open would otherwise be invisible until the
	// user signed in again, and polling this route is exactly how the cabinet learns a
	// verification landed.
	let Some(user) = st.users.find_by_id(user_id).await.map_err(|e| {
		tracing::error!(error = %e, %user_id, "kyc: could not read the caller's level");
		StatusError::Internal
	})?
	else {
		// The session names somebody the directory no longer holds. Same answer as an
		// absent cookie: there is nobody to report on.
		return Err(StatusError::Unauthenticated);
	};

	let live = st.kyc_cases.live_case(user_id).await.map_err(|e| {
		tracing::error!(error = %e, %user_id, "kyc: could not read the caller's running case");
		StatusError::Internal
	})?;

	let body = Json(StatusResponse {
		level: user.kyc_level(),
		case: live.map(|c| CaseView {
			// A stored URL is only resumable if the route that hands it back can run at
			// all. With no vendor configured `/kyc/start` is 503 BEFORE it reaches the
			// reuse branch, so `true` here would put a Continue button on screen whose
			// every click is an outage — on the exact day this route exists to be honest
			// about.
			resumable: st.kyc.is_some() && c.redirect_url.is_some(),
			status: c.status.as_str().to_owned(),
			requested_tier: c.requested_tier,
			created_at: c.created_at,
		}),
	});
	Ok((caller.refreshed(st, jar), NO_STORE, body))
}

/// `POST /kyc/callback/didit` — the provider's webhook. Public and unauthenticated
/// except for the signature over the body.
///
/// `Bytes` must stay the last extractor: it consumes the body, and it gives us the bytes
/// exactly as they arrived, which is what the raw signature is computed over.
///
/// BUDGET: the vendor gives this handler 5 seconds before it calls the delivery failed.
/// Everything on the path is local Postgres — one short transaction (`SELECT … FOR
/// UPDATE` plus an `UPDATE`), then the level write and its outbox row, then a
/// best-effort notification that only ENQUEUES (SMTP lives in the dispatcher loop, never
/// here). Nothing waits on a network hop. Keep it that way: anything slower added here
/// turns every verdict into a retry.
pub async fn callback(State(st): State<WebState>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, (StatusCode, &'static str)> {
	let st = &st.inner;
	let Some(provider) = st.kyc.as_ref() else {
		// Fails closed: with no secret there is nothing to verify against, and accepting
		// an unverifiable verdict is the one outcome worse than dropping it.
		return Err((StatusCode::SERVICE_UNAVAILABLE, "kyc not configured"));
	};

	let callback_headers = CallbackHeaders {
		signature: header_str(&headers, "x-signature"),
		signature_v2: header_str(&headers, "x-signature-v2"),
		timestamp: header_str(&headers, "x-timestamp").and_then(|v| v.trim().parse::<i64>().ok()),
	};
	// Matched rather than `map_err`-ed because one arm is not a rejection: an unknown
	// status is ACCEPTED and ignored.
	let decision = match provider.parse_callback(&callback_headers, &body, now_secs()) {
		Ok(decision) => decision,
		// Deliberately terse to the caller and detailed to the log: a rejected caller
		// learns only that it was rejected.
		Err(KycCallbackError::BadSignature) => {
			tracing::warn!(provider = provider.name(), "kyc callback: signature rejected");
			return Err((StatusCode::UNAUTHORIZED, "invalid signature"));
		}
		Err(KycCallbackError::StaleTimestamp) => {
			tracing::warn!(provider = provider.name(), "kyc callback: outside the replay window");
			return Err((StatusCode::BAD_REQUEST, "stale delivery"));
		}
		Err(KycCallbackError::Malformed(detail)) => {
			tracing::warn!(provider = provider.name(), %detail, "kyc callback: unusable body");
			return Err((StatusCode::BAD_REQUEST, "malformed callback"));
		}
		// 200, because the delivery is genuine, in-window and well-formed — we simply do
		// not know the word. The vendor's vocabulary grows; answering 4xx to a status we
		// merely have not been taught would turn "Didit shipped a new state" into an
		// endpoint that rejects deliveries, and a 5xx would put it in a retry loop that
		// can never succeed. Nothing is written and no level moves.
		//
		// `error!`, though — NOT `warn!`. If the new word turns out to mean an approval,
		// every user hitting it is verified at the vendor and stuck at their old level
		// here, and nobody reports that. This line (via `error_monitoring::tracing_layer`)
		// is the only thing that will bring a human to add the arm.
		Err(KycCallbackError::UnknownStatus(word)) => {
			tracing::error!(provider = provider.name(), status = %word, "kyc callback: the vendor sent a status this build does not know — accepted, but no level was moved");
			return Ok(Json(json!({ "ok": true, "ignored": "unknown status" })));
		}
	};

	let (case, duplicate) = match st.kyc_cases.record_decision(provider.name(), &decision).await.map_err(|e| {
		tracing::error!(error = %e, "kyc callback: could not record the decision");
		(StatusCode::INTERNAL_SERVER_ERROR, "could not record the decision")
	})? {
		CaseDecision::Recorded(case) => (case, false),
		// At-least-once delivery is normal, not an error — answering anything but 2xx
		// would make the provider retry a message we have already acted on.
		//
		// It still goes through `apply`, and that is the point rather than an oversight.
		// Recording the status and raising the level are two writes, and only the first is
		// covered by the row lock: a delivery that stored `approved` and then died — the
		// pod rolled, the level write lost its connection — leaves a case that says
		// verified and a user who is not. Skipping the retry, as this handler used to,
		// made that state PERMANENT, because every later delivery of the same verdict is
		// a redelivery too. Applying again is safe by construction: `raise_kyc_level_to`
		// compares under the row lock and writes nothing when the level is already held,
		// so the second pass emits no second `KYC_CHANGED`.
		CaseDecision::Redelivered(case) => {
			tracing::debug!(case_id = %case.id, status = case.status.as_str(), "kyc callback: redelivery — re-asserting the recorded verdict");
			(case, true)
		}
		// Genuine, but describing a verdict the case has already moved past. 200: the
		// delivery was handled correctly and there is nothing for the vendor to retry.
		// NOT applied — a superseded verdict must not reach `apply`.
		CaseDecision::Ignored(case) => {
			tracing::info!(case_id = %case.id, held = case.status.as_str(), superseded = decision.status.as_str(), "kyc callback: out-of-order delivery ignored");
			return Ok(Json(json!({ "ok": true, "ignored": "superseded", "status": case.status.as_str() })));
		}
		// Also the shape of the legitimate race where the webhook overtakes the insert
		// that opens the case.
		//
		// DO NOT "fix" this to 200. Didit retries on 5xx AND on 404, twice — at roughly
		// one minute and four minutes — so this 404 IS the recovery path for that race,
		// not a lost delivery. Answering 200 would tell the vendor the message was
		// handled and permanently drop a verdict for a case that existed a second later.
		CaseDecision::Unknown => {
			tracing::warn!(provider = provider.name(), "kyc callback: no case for this session");
			return Err((StatusCode::NOT_FOUND, "unknown session"));
		}
		// The delivery's echoed correlation value names some other case. Refused, and —
		// unlike before — refused before it wrote anything: the comparison now happens
		// inside the transaction holding the row, so the 400 the caller reads and the row
		// they can go and look at finally say the same thing.
		CaseDecision::Mismatch(case) => {
			tracing::error!(case_id = %case.id, echoed = %decision.vendor_data, "kyc callback: vendor_data does not match the case it names");
			return Err((StatusCode::BAD_REQUEST, "callback does not match its case"));
		}
	};

	apply(st, &case).await?;
	Ok(Json(json!({ "ok": true, "status": case.status.as_str(), "duplicate": duplicate })))
}

/// Turn a recorded verdict into a level, if it is one that moves the level at all.
///
/// FALLIBLE ON PURPOSE. This used to swallow every failure and let the caller answer 200,
/// which told the vendor the verdict was handled and stopped the retries — for a user
/// whose level had NOT moved. The case row said `approved`, the account said tier 0, and
/// nothing would ever reconcile the two: the vendor had been told to stop, and no other
/// path re-reads decided cases. An `Err` here means "the verdict is recorded but not
/// applied", the caller turns it into a 5xx, and the vendor's retry is what repairs it.
///
/// A notification failure is NOT one of those errors and stays best-effort below: the
/// level is already written by then, and retrying a delivery to re-send an email would
/// re-run this whole path for a decision that has fully landed.
async fn apply(st: &super::Inner, case: &KycCase) -> Result<(), (StatusCode, &'static str)> {
	let Some(target) = case.status.grants_tier(case.requested_tier) else {
		// Declined, abandoned, expired, unfinished, aged-out, still running: the case row
		// now says so and the level is untouched. Someone who holds tier 2 and fails an
		// attempt at 3 keeps their 2 — a downgrade is a human act under `KycManage`, and
		// there is no path to one from here.
		if case.status == KycStatus::InReview {
			notify(
				st,
				case,
				"kyc_in_review",
				"Your verification is being reviewed",
				"A reviewer is looking at the documents you submitted. We will let you know as soon as there is a decision.",
			)
			.await;
		}
		return Ok(());
	};

	// THE shared point, and a MONOTONIC one. The comparison that decides whether this is
	// a raise happens inside the same transaction as the write, under the user row's
	// lock — an approval for a tier the user already exceeds must never pull them down to
	// it, and read on a separate connection that check is a race the operator console can
	// lose: a human revoking a level under `KycManage` commits between our read and our
	// write, and the vendor silently restores what they had just taken away.
	//
	// The aggregate call underneath is the one the operator RPC uses, so the `KYC_CHANGED`
	// event, the `user_outbox` row and the money plane's mirror come out identical whether
	// a person or a vendor decided — banking still never learns a vendor exists.
	match st.users.raise_kyc_level_to(case.user_id, target).await {
		Ok(KycLevelChange::Raised { from, to }) => {
			tracing::info!(case_id = %case.id, from, to, "kyc callback: level raised");
			notify(
				st,
				case,
				"kyc_approved",
				"Your identity is verified",
				"Your verification was approved and your account level has been updated.",
			)
			.await;
			Ok(())
		}
		// Not a failure and not a retry: an approval for a tier already held is a correct
		// delivery whose correct effect is nothing. Notably this is also the redelivery
		// path, which is why re-applying costs no second event.
		Ok(KycLevelChange::AlreadyHolds(current)) => {
			tracing::info!(case_id = %case.id, current, target, "kyc callback: approval does not raise the level");
			Ok(())
		}
		// Includes the case naming a user that no longer exists (`DomainError::NotFound`
		// out of the `FOR UPDATE` load). A retry will not resurrect them, but 200 here
		// would file the verdict as applied, and it is not — the log line, not a silent
		// success, is what gets a human to look.
		Err(e) => {
			tracing::error!(error = %e, case_id = %case.id, target, "kyc callback: could not apply the approved level");
			Err((StatusCode::INTERNAL_SERVER_ERROR, "could not apply the decision"))
		}
	}
}

/// Best-effort in-app/e-mail notice. A user who never subscribed to the topic gets
/// nothing (that is `emit`'s contract), and a notification failure must not turn a
/// successfully applied decision into a retry the provider will resend.
async fn notify(st: &super::Inner, case: &KycCase, kind: &str, title: &str, body: &str) {
	let dedupe_key = format!("kyc:{}:{}", case.id, case.status.as_str());
	if let Err(e) = st.notifications.emit(case.user_id.raw(), TOPIC, kind, title, body, "", &dedupe_key, now_secs()).await {
		tracing::warn!(error = %e, case_id = %case.id, "kyc callback: could not emit the decision notice");
	}
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
	headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}
