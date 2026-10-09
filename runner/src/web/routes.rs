//! The auth route handlers. Shapes mirror the cabinet BFF's former
//! `/api/auth/*` surface byte-for-byte (`SessionInfo` with a camelCase user,
//! `SessionList` snake_case), so the zone frontends only changed the URL.

use axum::{
	Json,
	extract::{Path, Query, State},
	http::{HeaderMap, StatusCode},
	response::Redirect,
};
use axum_extra::extract::cookie::CookieJar;
use domain::{
	auth::{ProvenIdentity, Provider},
	authz::{Role, SEAT_GUEST},
	users::{Email, UserId},
};
use evconcierge_auth::oauth::OAuthProvider;
use evconcierge_contracts::concierge::v1::{self as cc, auth_service_server::AuthService as AuthRpc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::web::{
	WebState, now_secs,
	oauth::{Challenge, OAUTH_TX_TTL, safe_return_to},
};

#[derive(Deserialize)]
pub struct LoginQuery {
	#[serde(rename = "returnTo")]
	return_to: Option<String>,
	provider: Option<String>,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
	code: Option<String>,
	state: Option<String>,
	error: Option<String>,
}

#[derive(Serialize)]
pub struct SessionInfo {
	authenticated: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	user: Option<SessionUser>,
	/// What the caller's seat holds, concrete — a guest's when nobody is signed in. What a
	/// zone shows or walls off is decided from this; its backend still decides what runs.
	permissions: &'static [&'static str],
}
impl SessionInfo {
	fn authenticated(user: cc::UserSummary) -> Self {
		let is_admin = !user.role.is_empty() && user.role != "investor";
		let seat = Role::parse(&user.role).expect("the directory reports only Role strings");
		Self {
			permissions: seat.permissions(),
			authenticated: true,
			user: Some(SessionUser {
				user_id: user.user_id,
				email: user.email,
				email_verified: user.email_verified,
				username: Some(user.username).filter(|u| !u.is_empty()),
				status: user.status,
				role: user.role,
				is_admin,
				role_is_break_glass: user.role_is_break_glass,
			}),
		}
	}

	fn anonymous() -> Self {
		Self {
			authenticated: false,
			user: None,
			permissions: SEAT_GUEST.members,
		}
	}
}

/// `GET /auth/login?provider=&returnTo=` — mint PKCE/state/nonce, stash the
/// transaction server-side, and redirect the browser to the provider's consent screen.
pub async fn login(State(st): State<WebState>, jar: CookieJar, Query(q): Query<LoginQuery>) -> Result<(CookieJar, Redirect), (StatusCode, &'static str)> {
	let st = &st.inner;
	// A link that names no provider predates the choice, and meant Google.
	let provider = st
		.provider(q.provider.as_deref().unwrap_or("google"))
		.ok_or((StatusCode::SERVICE_UNAVAILABLE, "sign-in method not configured"))?;
	let return_to = safe_return_to(q.return_to.as_deref());
	let ch = Challenge::new();
	let tx_id = st.oauth.put(provider.name(), ch.state.clone(), ch.nonce.clone(), ch.code_verifier.clone(), return_to).await;
	let url = provider.authorize_url(&st.redirect_uri(provider.name()), &ch.state, &ch.nonce, &ch.code_challenge);
	let jar = jar.add(st.cookies.server_cookie(st.cookies.oauth_tx.clone(), tx_id, OAUTH_TX_TTL));
	Ok((jar, Redirect::to(&url)))
}
/// `GET /callback/auth/{provider}` — validate the state against the stored transaction,
/// redeem the code with the provider, resolve the account it opens, open a session, and
/// redirect back to where the user came from.
pub async fn callback(State(st): State<WebState>, Path(name): Path<String>, jar: CookieJar, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> (CookieJar, Redirect) {
	let st = &st.inner;
	// The transaction is keyed by the HttpOnly tx cookie, so only the browser that
	// started the flow holds it; `state` must then match the stored tx.
	let tx = match jar.get(&st.cookies.oauth_tx).map(|c| c.value().to_string()) {
		Some(id) => st.oauth.take(&id).await,
		None => None,
	};
	let return_to = tx.as_ref().map(|t| t.return_to.clone()).unwrap_or_else(|| "/".to_string());
	if q.error.is_some() {
		return fail(st, jar, &return_to, "denied");
	}
	let (Some(code), Some(state_param), Some(tx)) = (q.code, q.state, tx) else {
		return fail(st, jar, &return_to, "invalid");
	};
	let Some(provider) = st.provider(&name).filter(|p| p.name() == tx.provider) else {
		return fail(st, jar, &return_to, "invalid");
	};
	if tx.state != state_param {
		return fail(st, jar, &return_to, "invalid");
	}

	let identity = match provider.exchange_code(&code, &tx.code_verifier, &st.redirect_uri(provider.name()), &tx.nonce).await {
		Ok(identity) => identity,
		Err(e) => {
			// The callback is outside the reporting interceptor: an incident is reported here or never.
			evconcierge_auth::telemetry::report_unexpected(&e);
			tracing::warn!(provider = provider.name(), error = %e, "auth callback: provider exchange failed");
			return fail(st, jar, &return_to, "exchange");
		}
	};
	let Ok(email) = Email::parse(&identity.email) else {
		tracing::warn!(provider = provider.name(), "auth callback: provider answered an unusable email");
		return fail(st, jar, &return_to, "exchange");
	};
	let provider_kind: Provider = provider.name().parse().expect("every OAuthProvider name is a domain Provider");
	let proven = ProvenIdentity {
		provider: Some((provider_kind, identity.subject)),
		email,
		email_proven: identity.email_verified,
	};
	let user = match st.users.resolve(proven, now_secs()).await {
		Ok(user) => user,
		Err(e) => {
			tracing::error!(error = %e, "auth callback: account resolution failed");
			return fail(st, jar, &return_to, "session");
		}
	};
	match open_session(st, jar, &headers, user.id()).await {
		Ok(jar) => (clear_tx(st, jar), Redirect::to(&safe_return_to(Some(&tx.return_to)))),
		Err((jar, reason)) => fail(st, jar, &return_to, reason),
	}
}

/// Sign the browser in as `user`: close whatever session it held, open a new one, and
/// set the session, CSRF and zone-shared access cookies. The one place every sign-in
/// method ends. Errs with the jar untouched and a machine-readable reason.
pub(super) async fn open_session(st: &super::Inner, jar: CookieJar, headers: &HeaderMap, user: UserId) -> Result<CookieJar, (CookieJar, &'static str)> {
	let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
	let tokens = match st.auth.open_session(&user.to_string(), user_agent, client_ip(headers)).await {
		Ok(tokens) => tokens,
		Err(e) if e.code() == tonic::Code::PermissionDenied => return Err((jar, "disabled")),
		Err(e) => {
			tracing::error!(code = ?e.code(), detail = %e.message(), "sign-in: session issuance failed");
			return Err((jar, "session"));
		}
	};
	// Signed in again, perhaps as another account: the browser's previous session ends here.
	if let Some(previous) = jar.get(&st.cookies.session).map(|c| c.value().to_string())
		&& let Err(e) = close(st, &previous).await
	{
		tracing::error!(error = ?e, "sign-in: previous session not closed");
		return Err((jar, "session"));
	}
	let access_token = tokens.access_token.clone();
	let (id, csrf, max_age) = match st.sessions.put(tokens).await {
		Ok(Some(opened)) => opened,
		Ok(None) => return Err((jar, "session")),
		Err(e) => {
			tracing::error!(error = ?e, "sign-in: session store put failed");
			return Err((jar, "session"));
		}
	};
	Ok(jar
		.add(st.cookies.server_cookie(st.cookies.session.clone(), id, max_age))
		.add(st.cookies.readable_cookie(st.cookies.csrf.clone(), csrf, max_age))
		// The zone-shared credential: every same-origin request carries it, and a zone
		// backend verifies it locally against this plane's JWKS. The JWT inside expires
		// on its own short TTL; `/auth/session` re-sets it.
		.add(st.cookies.server_cookie(st.cookies.access.clone(), access_token, max_age)))
}
/// `GET /auth/session` — who-am-I for the browser, refreshing the access token (and
/// its zone-shared cookie) transparently. Never returns a token in the body.
///
/// The `user` block (role, `isAdmin`, status) is read LIVE from the directory on every
/// call, not served from the login-time copy in the session: a role granted from the
/// console is visible on the next page load, with no wait for the refresh rotation
/// and no re-login. Only when the directory is down does the stored copy answer.
pub async fn session(State(st): State<WebState>, jar: CookieJar) -> Result<(CookieJar, Json<SessionInfo>), (StatusCode, &'static str)> {
	let st = &st.inner;
	let fresh = match jar.get(&st.cookies.session).map(|c| c.value().to_string()) {
		// A store failure means the session's fate is UNKNOWN — 500 and keep the
		// cookies, never sign the user out over a Redis blip.
		Some(id) => st.sessions.fresh(&id, &st.auth).await.map_err(store_err)?,
		None => None,
	};
	Ok(match fresh {
		Some(fresh) => {
			let jar = jar.add(st.cookies.server_cookie(st.cookies.access.clone(), fresh.access_token, fresh.remaining_secs));
			(jar, Json(SessionInfo::authenticated(fresh.user)))
		}
		// The session is gone but the browser may still hold the cookies — clear them
		// so zone middlewares stop treating requests as signed-in.
		None => (clear_session(st, jar), Json(SessionInfo::anonymous())),
	})
}
/// `POST /auth/logout` — CSRF-checked: drop the session, revoke the refresh family
/// upstream (best-effort), and clear the cookies.
pub async fn logout(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Result<(CookieJar, Json<Value>), (StatusCode, &'static str)> {
	let st = &st.inner;
	if !verify_csrf(st, &jar, &headers).await? {
		return Err((StatusCode::FORBIDDEN, "csrf check failed"));
	}
	if let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_string()) {
		close(st, &id).await.map_err(store_err)?;
	}
	Ok((clear_session(st, jar), Json(json!({ "ok": true }))))
}

/// Drop a session and revoke its refresh family upstream.
async fn close(st: &super::Inner, id: &str) -> color_eyre::Result<()> {
	if let Some(refresh) = st.sessions.forget(id).await? {
		// The session is already gone locally; an upstream blip must not keep it signed in here.
		let _ = AuthRpc::logout(
			&st.auth,
			tonic::Request::new(cc::LogoutRequest {
				refresh_token: refresh,
				revoke_all: false,
			}),
		)
		.await;
	}
	Ok(())
}
/// `GET /auth/sessions` — the caller's active sessions (refresh-token families),
/// proven by the server-side refresh token (never exposed to the browser).
pub async fn list_sessions(State(st): State<WebState>, jar: CookieJar) -> Result<Json<Value>, (StatusCode, &'static str)> {
	let st = &st.inner;
	let refresh = refresh_of(st, &jar).await?.ok_or((StatusCode::UNAUTHORIZED, "unauthenticated"))?;
	let response = AuthRpc::list_sessions(&st.auth, tonic::Request::new(cc::ListSessionsRequest { refresh_token: refresh }))
		.await
		.map_err(|_| (StatusCode::BAD_GATEWAY, "session listing failed"))?
		.into_inner();
	let sessions: Vec<SessionEntry> = response
		.sessions
		.into_iter()
		.map(|s| SessionEntry {
			id: s.id,
			user_agent: s.user_agent,
			ip: s.ip,
			created_at: s.created_at.to_string(),
			last_seen: s.last_seen.to_string(),
			current: s.current,
		})
		.collect();
	Ok(Json(json!({ "sessions": sessions })))
}
/// `DELETE /auth/sessions` — CSRF-checked: revoke one session by id (must belong to
/// the caller; revoking the current one acts like a sign-out of this device).
pub async fn revoke_session(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Json<Value>, (StatusCode, &'static str)> {
	let st = &st.inner;
	if !verify_csrf(st, &jar, &headers).await? {
		return Err((StatusCode::FORBIDDEN, "csrf check failed"));
	}
	let refresh = refresh_of(st, &jar).await?.ok_or((StatusCode::UNAUTHORIZED, "unauthenticated"))?;
	let session_id = body.as_ref().and_then(|Json(v)| v.get("session_id")).and_then(|x| x.as_str()).unwrap_or("").to_string();
	if session_id.is_empty() {
		return Err((StatusCode::BAD_REQUEST, "session_id required"));
	}
	AuthRpc::revoke_session(&st.auth, tonic::Request::new(cc::RevokeSessionRequest { refresh_token: refresh, session_id }))
		.await
		.map_err(|_| (StatusCode::BAD_GATEWAY, "session revoke failed"))?;
	Ok(Json(json!({ "ok": true })))
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionUser {
	user_id: String,
	email: String,
	email_verified: bool,
	username: Option<String>,
	status: String,
	role: String,
	is_admin: bool,
	/// `role` came from the `OWNER_SUBJECTS` emergency allowlist, not from `users.role`.
	/// A zone showing an admin surface on that authority must say so — it is temporary
	/// by construction and it seats nobody.
	role_is_break_glass: bool,
}

#[derive(Serialize)]
struct SessionEntry {
	id: String,
	user_agent: String,
	ip: String,
	created_at: String,
	last_seen: String,
	current: bool,
}

impl super::Inner {
	/// The one redirect URI registered with a provider: its callback on the user-facing origin.
	fn redirect_uri(&self, provider: &str) -> String {
		format!("{}/api/callback/auth/{provider}", self.public_origin)
	}

	fn provider(&self, name: &str) -> Option<&OAuthProvider> {
		self.providers.iter().find(|p| p.name() == name)
	}
}

/// A session-store failure is a 500, never an auth verdict: the session may well
/// still exist, so neither cookies nor upstream state may be touched off it.
pub(super) fn store_err(e: color_eyre::Report) -> (StatusCode, &'static str) {
	tracing::error!(error = ?e, "web session store failed");
	(StatusCode::INTERNAL_SERVER_ERROR, "session store unavailable")
}

async fn refresh_of(st: &super::Inner, jar: &CookieJar) -> Result<Option<String>, (StatusCode, &'static str)> {
	let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_string()) else {
		return Ok(None);
	};
	st.sessions.refresh_token(&id).await.map_err(store_err)
}

/// CSRF double-submit, hardened with the server-side session copy: the `x-ev-csrf`
/// header must equal the readable csrf cookie AND the value stored on the session.
///
/// Both comparisons are constant time. Neither is a plausible oracle on its own — a
/// `memcmp` would have to be timed across the network and the whole token guessed anyway
/// — but this plane compares the bridge token (`support::authenticate_service`), the
/// webhook signature (`infrastructure::kyc::didit`) and the consilium code
/// (`infrastructure::governance`) that way, and a token check that quietly does not is
/// the kind of exception a reader takes for the rule.
///
/// The order matters more than the timing does and is deliberate: the header is matched
/// against the cookie and the SERVER-SIDE copy, and the whole check runs BEFORE the
/// session is read, so a request that fails it never touches session state.
pub(super) async fn verify_csrf(st: &super::Inner, jar: &CookieJar, headers: &HeaderMap) -> Result<bool, (StatusCode, &'static str)> {
	Ok(matches!(csrf_outcome(st, jar, headers).await?, CsrfOutcome::Ok))
}

/// Why the double-submit check did not pass — for the routes that answer the two causes
/// differently.
///
/// Every refusal here used to be one 403. That reads as "your token is stale, reload the
/// page", and for a caller who is not signed in AT ALL it is simply wrong: they have no
/// CSRF cookie because they have no session, so the check they failed is not the one
/// they need told about. The cabinet keys its "reload" screen off that 403 and would
/// send somebody whose session expired to reload a page that will expire again.
pub(super) enum CsrfOutcome {
	Ok,
	/// There is nobody signed in to check a token against: no session cookie, or a
	/// session the locker no longer holds (expired, revoked, signed out elsewhere).
	NoSession,
	/// Somebody IS signed in and the token does not match — the genuine CSRF refusal,
	/// and the one a reload actually fixes.
	Mismatch,
}

/// The check itself. Ordering is the invariant, not an implementation detail: the
/// header is matched against the readable cookie and the SERVER-SIDE copy, and the
/// locker is not read until both of those have passed, so a request that fails the
/// double-submit never touches session state. The session COOKIE is read before that —
/// its presence is not session state, and it is what separates "not signed in" from
/// "signed in with the wrong token" without looking anything up.
pub(super) async fn csrf_outcome(st: &super::Inner, jar: &CookieJar, headers: &HeaderMap) -> Result<CsrfOutcome, (StatusCode, &'static str)> {
	let Some(session_id) = jar.get(&st.cookies.session).map(|c| c.value().to_string()) else {
		return Ok(CsrfOutcome::NoSession);
	};
	let Some(cookie) = jar.get(&st.cookies.csrf).map(|c| c.value().to_string()) else {
		return Ok(CsrfOutcome::Mismatch);
	};
	let Some(header) = headers.get("x-ev-csrf").and_then(|v| v.to_str().ok()) else {
		return Ok(CsrfOutcome::Mismatch);
	};
	if !ct_str_eq(&cookie, header) {
		return Ok(CsrfOutcome::Mismatch);
	}
	match st.sessions.csrf(&session_id).await.map_err(store_err)? {
		Some(stored) if ct_str_eq(&stored, header) => Ok(CsrfOutcome::Ok),
		// The cookie names a session the locker does not hold: it lapsed, it was revoked,
		// or the user signed out in another tab. Nobody is signed in, and saying so is
		// what sends them to a sign-in rather than to a reload.
		None => Ok(CsrfOutcome::NoSession),
		Some(_) => Ok(CsrfOutcome::Mismatch),
	}
}

/// The session locker could not be read. The ONE failure [`session_user`] has that is
/// not "nobody is signed in" — kept as its own type so each route renders it in its own
/// body shape without either of them having to guess what an absent session means.
pub(super) struct SessionStoreDown;

/// The signed-in caller, plus the access token their browser must be left holding.
///
/// The token half is not incidental. Reading a session ROTATES it (see
/// [`session_user`]), so a handler that takes the caller and drops the rest signs the
/// browser out from under itself.
pub(super) struct Caller {
	pub(super) id: UserId,
	access_token: String,
	remaining_secs: i64,
}

impl Caller {
	/// Put the refreshed access token back in the browser, the way `/auth/session` does.
	pub(super) fn refreshed(self, st: &super::Inner, jar: CookieJar) -> CookieJar {
		jar.add(st.cookies.server_cookie(st.cookies.access.clone(), self.access_token, self.remaining_secs))
	}
}

/// The signed-in caller behind the session cookie, or `None` when there is no live
/// session to read one from.
///
/// One reader for every route that acts for the signed-in caller: a second copy of "take
/// the cookie, refresh the session, parse the id" is a second place to stop agreeing
/// about who is asking.
///
/// This READ WRITES. `WebSessions::fresh` renews an access token inside
/// `ACCESS_SKEW_SECS` of expiry: it calls `AuthRpc::refresh`, rotates the refresh token
/// and saves the new pair, and past the refresh deadline it deletes the session
/// outright. So the returned [`Caller`] carries the new access token, and every caller
/// of this function owes the browser a `Set-Cookie` — otherwise the server holds the
/// rotated pair and the browser holds a JWT that expires within the half-minute. On a
/// polled route that is not a corner case; it is most polls that land in the window.
pub(super) async fn session_user(st: &super::Inner, jar: &CookieJar) -> Result<Option<Caller>, SessionStoreDown> {
	let Some(session_id) = jar.get(&st.cookies.session).map(|c| c.value().to_string()) else {
		return Ok(None);
	};
	let fresh = st.sessions.fresh(&session_id, &st.auth).await.map_err(|e| {
		tracing::error!(error = ?e, "web session store failed");
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

/// Constant-time string equality.
///
/// The length guard is what keeps `ct_eq` meaningful: `subtle` answers "not equal"
/// immediately on a length mismatch, so without it a wrong-length token would be
/// indistinguishable from a wrong one of the right length. Length is not the secret here
/// — CSRF tokens are minted at one fixed width — so leaking it costs nothing.
///
/// Local rather than shared with the identical helpers in `evconcierge_auth` and the
/// Didit adapter: it is two lines, and a crate-crossing home for it would be an
/// abstraction layer bought to avoid typing them.
fn ct_str_eq(a: &str, b: &str) -> bool {
	a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Clear the OAuth transaction cookie.
fn clear_tx(st: &super::Inner, jar: CookieJar) -> CookieJar {
	jar.add(st.cookies.removal(st.cookies.oauth_tx.clone(), true))
}

/// Clear the session + csrf + access cookies (sign-out / dead session).
fn clear_session(st: &super::Inner, jar: CookieJar) -> CookieJar {
	jar.add(st.cookies.removal(st.cookies.session.clone(), true))
		.add(st.cookies.removal(st.cookies.csrf.clone(), false))
		.add(st.cookies.removal(st.cookies.access.clone(), true))
}

/// Abort the callback: clear the tx cookie and land the user back where they came
/// from, signed out, with a machine-readable reason.
fn fail(st: &super::Inner, jar: CookieJar, return_to: &str, reason: &str) -> (CookieJar, Redirect) {
	let base = safe_return_to(Some(return_to));
	let sep = if base.contains('?') { '&' } else { '?' };
	(clear_tx(st, jar), Redirect::to(&format!("{base}{sep}auth_error={reason}")))
}

/// Best-effort client IP for the device metadata stored on the refresh-token family.
pub(super) fn client_ip(headers: &HeaderMap) -> String {
	if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
		let first = xff.split(',').next().unwrap_or("").trim();
		if !first.is_empty() {
			return first.to_string();
		}
	}
	headers.get("x-real-ip").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}
