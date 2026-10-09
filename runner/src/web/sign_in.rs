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
use domain::{
	auth::ProvenIdentity,
	error::DomainError,
	users::{Email, Username},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	ports::{CodeIssue, CodePurpose, CodeRefusal, SignUp, VerifyRefusal},
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

/// Long enough to resist guessing behind the lockout, short enough that argon2 never
/// hashes a megabyte on a stranger's behalf.
const PASSWORD_CHARS: std::ops::RangeInclusive<usize> = 8..=128;

fn acceptable(password: &str) -> Result<(), Refusal> {
	match PASSWORD_CHARS.contains(&password.chars().count()) {
		true => Ok(()),
		false => Err(Refusal(StatusCode::BAD_REQUEST, "weak_password")),
	}
}

/// argon2id with the crate's defaults (OWASP's m=19 MiB, t=2, p=1), off the async
/// workers: one hash is tens of milliseconds of CPU.
async fn hash(password: String) -> Result<String, Refusal> {
	tokio::task::spawn_blocking(move || {
		use argon2::password_hash::{PasswordHasher, SaltString};
		let mut salt = [0u8; 16];
		getrandom::fill(&mut salt).expect("CSPRNG unavailable");
		let salt = SaltString::encode_b64(&salt).expect("16 bytes is a valid salt");
		argon2::Argon2::default().hash_password(password.as_bytes(), &salt).map(|phc| phc.to_string())
	})
	.await
	.expect("hashing does not panic")
	.map_err(|e| internal("password not hashed", e))
}

async fn matches(phc: String, password: String) -> Result<bool, Refusal> {
	tokio::task::spawn_blocking(move || {
		use argon2::password_hash::{PasswordHash, PasswordVerifier};
		let parsed = PasswordHash::new(&phc).map_err(|e| e.to_string())?;
		Ok::<_, String>(argon2::Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
	})
	.await
	.expect("verifying does not panic")
	.map_err(|e| internal("stored password hash does not parse", e))
}

/// Verified when a handle names no password, so that answer costs what a wrong password
/// costs and the timing says nothing about who has an account.
static DECOY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
	use argon2::password_hash::{PasswordHasher, SaltString};
	let salt = SaltString::encode_b64(b"concierge-decoy!").expect("16 bytes is a valid salt");
	argon2::Argon2::default().hash_password(b"no account has this password", &salt).expect("decoy hashes").to_string()
});

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequest {
	email: String,
	password: String,
	/// "Verify my email now": mail a code as the account is made.
	verify: bool,
	turnstile_token: String,
}

/// `POST /auth/password/signup` — a new account behind an email and a password, signed in
/// at once and working unverified. Refused `email_taken` when the address already backs a
/// password or is verified on an account: that person signs in, with a code if they forgot.
/// Saying so tells the caller an account exists, which a sign-up by email cannot avoid.
pub async fn sign_up(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SignUpRequest>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, Some(&body.turnstile_token)).await?;
	let email = email(&body.email)?;
	acceptable(&body.password)?;
	let phc = hash(body.password).await?;
	let user = match st.credentials.sign_up(&email, phc, now_secs()).await.map_err(|e| internal("sign-up failed", e))? {
		SignUp::Created(user) => user,
		SignUp::Taken => return Err(Refusal(StatusCode::CONFLICT, "email_taken")),
	};
	let verification = match body.verify {
		false => "skipped",
		true => match st.credentials.issue_code(CodePurpose::Verify(user.id()), now_secs()).await {
			Ok(CodeIssue::Sent) => {
				st.mail_wake.notify_one();
				"sent"
			}
			Ok(CodeIssue::Throttled) => "throttled",
			Err(e) => {
				tracing::error!(error = %e, "sign-up: verification code not issued");
				"failed"
			}
		},
	};
	let (jar, _) = signed_in_as(st, jar, &headers, user.id()).await?;
	Ok((jar, Json(json!({ "ok": true, "verification": verification }))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInRequest {
	/// An email or a username.
	identifier: String,
	password: String,
	turnstile_token: String,
}

/// `POST /auth/password/signin`. One refusal, `invalid_credentials`, for every handle and
/// password that do not match — except a locked password, which says so: the dialog then
/// offers a code, which the lock never blocks.
pub async fn sign_in(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SignInRequest>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, Some(&body.turnstile_token)).await?;
	let invalid = Refusal(StatusCode::UNAUTHORIZED, "invalid_credentials");
	let Some(stored) = st.credentials.password_named(&body.identifier).await.map_err(|e| internal("password lookup failed", e))? else {
		matches(DECOY.clone(), body.password).await?;
		return Err(invalid);
	};
	let now = now_secs();
	if stored.locked_until.is_some_and(|until| until > now) {
		return Err(Refusal(StatusCode::TOO_MANY_REQUESTS, "password_locked"));
	}
	let right = matches(stored.phc, body.password).await?;
	st.credentials
		.record_password_attempt(stored.user, right, now)
		.await
		.map_err(|e| internal("password attempt not recorded", e))?;
	if !right {
		return Err(invalid);
	}
	signed_in_as(st, jar, &headers, stored.user).await
}

#[derive(Deserialize)]
pub struct SetPassword {
	password: String,
	code: String,
}

/// `POST /auth/password/set` — set or replace the password with a verification code
/// mailed by `/auth/email/verify/request`. "Forgot password" is a code sign-in, then this.
pub async fn set_password(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SetPassword>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		acceptable(&body.password)?;
		let phc = hash(body.password).await?;
		match st.credentials.set_password(id, &body.code, phc, now_secs()).await.map_err(|e| internal("password not set", e))? {
			Ok(()) => Ok(ok()),
			Err(VerifyRefusal::Code(refusal)) => Err(code_refusal(refusal)),
			Err(VerifyRefusal::Taken) => Err(Refusal(StatusCode::CONFLICT, "email_taken")),
		}
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct SetUsername {
	username: String,
}

/// `POST /auth/username` — the signed-in account's chosen handle.
pub async fn set_username(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SetUsername>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match Username::parse(&body.username) {
		Err(_) => Err(Refusal(StatusCode::BAD_REQUEST, "invalid_username")),
		Ok(username) => match st.users.set_username(id, username).await {
			Ok(user) => Ok(Json(json!({ "ok": true, "username": user.username().map(Username::as_str) }))),
			Err(DomainError::Conflict(_)) => Err(Refusal(StatusCode::CONFLICT, "username_taken")),
			Err(e) => Err(internal("username not set", e)),
		},
	};
	Ok((jar, answer))
}

/// `GET /auth/methods` — how the signed-in account can sign in, for its settings.
pub async fn methods(State(st): State<WebState>, jar: CookieJar) -> Answered {
	let st = &st.inner;
	let caller = session_user(st, &jar).await.map_err(|_| INTERNAL)?.ok_or(Refusal(StatusCode::UNAUTHORIZED, "unauthenticated"))?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match (st.credentials.methods(id).await, st.users.find_by_id(id).await) {
		(Ok(methods), Ok(Some(user))) => Ok(Json(json!({
			"email": user.email().as_str(),
			"emailVerified": user.email_verified(),
			"username": user.username().map(Username::as_str),
			"password": methods.password,
			"providers": methods.providers,
		}))),
		(Ok(_), Ok(None)) => Err(Refusal(StatusCode::UNAUTHORIZED, "unauthenticated")),
		(Err(e), _) | (_, Err(e)) => Err(internal("sign-in methods not read", e)),
	};
	Ok((jar, answer))
}
