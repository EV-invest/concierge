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
//!     into "POST yourself tier 2";
//!   * no cookie is read and no CSRF token is expected: there is no browser here, and a
//!     CSRF check on a server-to-server call is a check that can only ever be wrong.
//!
//! When verification cannot be run at all — no vendor configured, or a vendor that will
//! not open a session — `/kyc/start` DEGRADES rather than errors: one 503, one stable
//! body, one support address (see [`StartError`]). The user is never shown a technical
//! failure and never given the impression they did something wrong.

use axum::{
	Json,
	body::Bytes,
	extract::State,
	http::{HeaderMap, StatusCode},
	response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
	ports::{CallbackHeaders, CaseDecision, KycCallbackError, KycCase, KycLevelChange, KycStatus, PROVIDER_MAX_TIER},
	web::{
		WebState, now_secs,
		routes::{store_err, verify_csrf},
	},
};

/// The topic a verification decision is announced on. Emitting is a no-op for anyone who
/// has not subscribed, so this never becomes unsolicited mail.
const TOPIC: &str = "account:verification";

/// The one error code `/kyc/start` publishes. The cabinet switches on THIS, never on the
/// prose beside it, so the wording can change without breaking a screen.
const KYC_UNAVAILABLE: &str = "kyc_unavailable";

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

#[derive(Deserialize, Default)]
pub struct StartRequest {
	/// The tier being applied for. 0/absent ⇒ 1, the entry tier.
	#[serde(default)]
	tier: u32,
}

#[derive(Serialize)]
pub struct StartResponse {
	/// Where to send the browser to perform the verification.
	redirect_url: String,
	case_id: String,
}

/// `POST /kyc/start` — open a verification case for the signed-in caller and hand back
/// the provider's URL.
pub async fn start(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, body: Option<Json<StartRequest>>) -> Result<Json<StartResponse>, StartError> {
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

	let Some(session_id) = jar.get(&st.cookies.session).map(|c| c.value().to_string()) else {
		return Err((StatusCode::UNAUTHORIZED, "unauthenticated").into());
	};
	let Some(fresh) = st.sessions.fresh(&session_id, &st.auth).await.map_err(store_err)? else {
		return Err((StatusCode::UNAUTHORIZED, "unauthenticated").into());
	};
	let user_id = Uuid::parse_str(&fresh.user.user_id)
		.map(UserId::from_raw)
		.map_err(|_| (StatusCode::UNAUTHORIZED, "unauthenticated"))?;

	let requested = body.map(|Json(b)| b.tier).unwrap_or_default();
	let tier = if requested == 0 { 1 } else { requested };
	if tier > PROVIDER_MAX_TIER {
		// Refused rather than clamped: silently applying for a lower tier than the caller
		// asked for would look like an approval for the one they wanted.
		return Err((StatusCode::BAD_REQUEST, "requested tier is above what a provider may grant").into());
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
	let session = provider.start_session(case_id, tier).await.map_err(|e| {
		// `error!` — NOT `warn!` — and the reason is the whole point of this arm. From
		// the user's side an exhausted vendor balance looks like silence: they simply
		// cannot verify, and nobody files a ticket about a screen that politely says to
		// try later. `error!` is what `error_monitoring::tracing_layer()` (wired in
		// `main::init_tracing`) forwards to Sentry, so this line is the only thing that
		// will wake a human. The vendor's own text goes here and nowhere else.
		tracing::error!(error = %e, provider = provider.name(), %case_id, tier, "kyc: the provider would not open a session — verification is unavailable to users");
		StartError::unavailable(st)
	})?;
	st.kyc_cases.open_case(case_id, user_id, provider.name(), &session.provider_ref, tier).await.map_err(|e| {
		// Same screen as a vendor outage: our store being unreachable is no more the
		// user's business than the vendor's balance, and it is just as temporary.
		tracing::error!(error = %e, %case_id, "kyc: failed to record the opened case");
		StartError::unavailable(st)
	})?;

	tracing::info!(%case_id, tier, provider = provider.name(), "kyc: case opened");
	Ok(Json(StartResponse {
		redirect_url: session.redirect_url,
		case_id: case_id.to_string(),
	}))
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
	};

	// A cross-check, never a lookup: `vendor_data` is what WE handed the vendor, echoed
	// back through a body an attacker also controls. It cannot select a case — it can
	// only disagree with the one `provider_ref` already found, and a disagreement means
	// the two ends are talking about different things.
	if !decision.vendor_data.is_empty() && decision.vendor_data != case.id.to_string() {
		tracing::error!(case_id = %case.id, echoed = %decision.vendor_data, "kyc callback: vendor_data does not match the case it names");
		return Err((StatusCode::BAD_REQUEST, "callback does not match its case"));
	}

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
