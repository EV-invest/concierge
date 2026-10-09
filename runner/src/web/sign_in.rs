//! The sign-in methods this plane checks itself — an emailed code, a password — and
//! proving the signed-in account's own address later.
//!
//! Every answer is JSON, `{"ok":true}` or `{"error":"<code>"}` from one closed vocabulary,
//! so the sign-in dialog maps codes and never parses prose.
//!
//! The credential POSTs are reachable with no session, so the session's double-submit
//! check cannot guard them. Two things do instead: the `Origin` header must be this
//! plane's public origin (a cross-site form cannot sign a browser into an account of the
//! attacker's choosing), and the ones that cost us a mail or test a password carry a
//! Turnstile token checked here.

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, StatusCode},
	response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use domain::{auth::ProvenIdentity, users::Email};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	ports::{CodeIssue, CodePurpose, CodeRefusal, VerifyRefusal},
	web::{
		WebState, now_secs,
		routes::{Caller, CsrfOutcome, client_ip, csrf_outcome, open_session, session_user},
	},
};

/// A refusal, as the dialog reads it.
pub struct Refusal(StatusCode, &'static str);

impl IntoResponse for Refusal {
	fn into_response(self) -> Response {
		(self.0, Json(json!({ "error": self.1 }))).into_response()
	}
}

const INTERNAL: Refusal = Refusal(StatusCode::INTERNAL_SERVER_ERROR, "internal");

fn ok() -> Json<Value> {
	Json(json!({ "ok": true }))
}

fn internal(context: &'static str, err: impl std::fmt::Display) -> Refusal {
	tracing::error!(error = %err, "{context}");
	INTERNAL
}

/// Same-origin, and — when `turnstile` is given — a human.
async fn guard(st: &super::Inner, headers: &HeaderMap, turnstile: Option<&str>) -> Result<(), Refusal> {
	if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(st.public_origin.as_str()) {
		return Err(Refusal(StatusCode::FORBIDDEN, "origin"));
	}
	let Some(token) = turnstile else { return Ok(()) };
	match st.turnstile.passes(token, &client_ip(headers)).await {
		Ok(true) => Ok(()),
		Ok(false) => Err(Refusal(StatusCode::FORBIDDEN, "captcha")),
		Err(e) => {
			tracing::error!(error = %e, "turnstile siteverify unreachable");
			Err(Refusal(StatusCode::SERVICE_UNAVAILABLE, "captcha_unavailable"))
		}
	}
}

fn email(raw: &str) -> Result<Email, Refusal> {
	Email::parse(raw).map_err(|_| Refusal(StatusCode::BAD_REQUEST, "invalid_email"))
}

fn code_refusal(refusal: CodeRefusal) -> Refusal {
	match refusal {
		CodeRefusal::Missing | CodeRefusal::Wrong => Refusal(StatusCode::BAD_REQUEST, "invalid_code"),
		CodeRefusal::Expired => Refusal(StatusCode::BAD_REQUEST, "code_expired"),
		CodeRefusal::Exhausted => Refusal(StatusCode::BAD_REQUEST, "attempts_exceeded"),
	}
}

async fn sent(st: &super::Inner, issue: CodeIssue) -> Result<Json<Value>, Refusal> {
	match issue {
		CodeIssue::Sent => {
			st.mail_wake.notify_one();
			Ok(ok())
		}
		CodeIssue::Throttled => Err(Refusal(StatusCode::TOO_MANY_REQUESTS, "throttled")),
	}
}

/// The caller behind a state-changing request with a session: CSRF first, as everywhere.
async fn signed_in(st: &super::Inner, jar: &CookieJar, headers: &HeaderMap) -> Result<Caller, Refusal> {
	match csrf_outcome(st, jar, headers).await.map_err(|_| INTERNAL)? {
		CsrfOutcome::Ok => {}
		CsrfOutcome::NoSession => return Err(Refusal(StatusCode::UNAUTHORIZED, "unauthenticated")),
		CsrfOutcome::Mismatch => return Err(Refusal(StatusCode::FORBIDDEN, "csrf")),
	}
	session_user(st, jar).await.map_err(|_| INTERNAL)?.ok_or(Refusal(StatusCode::UNAUTHORIZED, "unauthenticated"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeRequest {
	email: String,
	turnstile_token: String,
}

/// `POST /auth/code/request` — mail a sign-in code. Answers the same for an address no
/// account holds: whether one does is decided only once the code proves the mailbox.
pub async fn request_code(State(st): State<WebState>, headers: HeaderMap, Json(body): Json<CodeRequest>) -> Result<Json<Value>, Refusal> {
	let st = &st.inner;
	guard(st, &headers, Some(&body.turnstile_token)).await?;
	let email = email(&body.email)?;
	let issue = st
		.credentials
		.issue_code(CodePurpose::Login(email), now_secs())
		.await
		.map_err(|e| internal("sign-in code not issued", e))?;
	sent(st, issue).await
}

#[derive(Deserialize)]
pub struct CodeVerify {
	email: String,
	code: String,
}

/// `POST /auth/code/verify` — spend the code and sign in to the account the mailbox opens
/// (`UserDirectoryRepository::resolve`), creating it when there is none.
pub async fn verify_code(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<CodeVerify>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, None).await?;
	let email = email(&body.email)?;
	st.credentials
		.redeem_login_code(&email, &body.code, now_secs())
		.await
		.map_err(|e| internal("sign-in code not redeemed", e))?
		.map_err(code_refusal)?;
	let identity = ProvenIdentity {
		provider: None,
		email,
		email_proven: true,
	};
	let user = st.users.resolve(identity, now_secs()).await.map_err(|e| internal("code sign-in: account resolution failed", e))?;
	signed_in_as(st, jar, &headers, user.id()).await
}

/// Open the session and answer the way every method here does.
pub(super) async fn signed_in_as(st: &super::Inner, jar: CookieJar, headers: &HeaderMap, user: domain::users::UserId) -> Result<(CookieJar, Json<Value>), Refusal> {
	match open_session(st, jar, headers, user).await {
		Ok(jar) => Ok((jar, ok())),
		Err((_, "disabled")) => Err(Refusal(StatusCode::FORBIDDEN, "disabled")),
		Err(_) => Err(INTERNAL),
	}
}

/// A signed-in route's answer. Reading the session may have rotated it, so the refreshed
/// access cookie goes back with a refusal too.
type Answered = Result<(CookieJar, Result<Json<Value>, Refusal>), Refusal>;

/// `POST /auth/email/verify/request` — mail the signed-in account a code for its own
/// address.
pub async fn request_verification(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match st.credentials.issue_code(CodePurpose::Verify(id), now_secs()).await {
		Ok(issue) => sent(st, issue).await,
		Err(e) => Err(internal("verification code not issued", e)),
	};
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct CodeOnly {
	code: String,
}

/// `POST /auth/email/verify/confirm` — spend it: the account's address is verified.
pub async fn confirm_verification(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<CodeOnly>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match st.credentials.verify_email(id, &body.code, now_secs()).await {
		Ok(Ok(_)) => Ok(ok()),
		Ok(Err(VerifyRefusal::Code(refusal))) => Err(code_refusal(refusal)),
		Ok(Err(VerifyRefusal::Taken)) => Err(Refusal(StatusCode::CONFLICT, "email_taken")),
		Err(e) => Err(internal("email not verified", e)),
	};
	Ok((jar, answer))
}
