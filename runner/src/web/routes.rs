//! The auth route handlers. Shapes mirror the cabinet BFF's former
//! `/api/auth/*` surface byte-for-byte (`SessionInfo` with a camelCase user,
//! `SessionList` snake_case), so the zone frontends only changed the URL.

use axum::{
	Json,
	extract::{Query, State},
	http::{HeaderMap, StatusCode},
	response::Redirect,
};
use axum_extra::extract::cookie::CookieJar;
use evconcierge_contracts::concierge::v1::{self as cc, auth_service_server::AuthService as AuthRpc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::web::{
	WebState,
	oauth::{Challenge, OAUTH_TX_TTL, authorize_url, safe_return_to},
};

#[derive(Deserialize)]
pub struct LoginQuery {
	#[serde(rename = "returnTo")]
	return_to: Option<String>,
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
}
impl SessionInfo {
	fn authenticated(user: cc::UserSummary) -> Self {
		let is_admin = !user.role.is_empty() && user.role != "investor";
		Self {
			authenticated: true,
			user: Some(SessionUser {
				user_id: user.user_id,
				email: user.email,
				status: user.status,
				role: user.role,
				is_admin,
			}),
		}
	}

	fn anonymous() -> Self {
		Self { authenticated: false, user: None }
	}
}

/// `GET /auth/login?returnTo=` — mint PKCE/state/nonce, stash the transaction
/// server-side, and redirect the browser to Google's consent screen.
pub async fn login(State(st): State<WebState>, jar: CookieJar, Query(q): Query<LoginQuery>) -> Result<(CookieJar, Redirect), (StatusCode, &'static str)> {
	let st = &st.inner;
	let Some(client_id) = st.google_client_id.clone() else {
		return Err((StatusCode::SERVICE_UNAVAILABLE, "auth not configured"));
	};
	let return_to = safe_return_to(q.return_to.as_deref());
	let ch = Challenge::new();
	let tx_id = st.oauth.put(ch.state.clone(), ch.nonce.clone(), ch.code_verifier.clone(), return_to).await;
	let url = authorize_url(&client_id, &st.redirect_uri(), &ch.state, &ch.nonce, &ch.code_challenge);
	let jar = jar.add(st.cookies.server_cookie(st.cookies.oauth_tx.clone(), tx_id, OAUTH_TX_TTL));
	Ok((jar, Redirect::to(&url)))
}
/// `GET /callback/auth/google` — validate the state against the stored transaction,
/// exchange the code for this plane's tokens (in-process), open a session, and
/// redirect back to where the user came from.
pub async fn callback(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> (CookieJar, Redirect) {
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
	if tx.state != state_param {
		return fail(st, jar, &return_to, "invalid");
	}

	let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
	let ip = client_ip(&headers);
	let req = cc::ExchangeRequest {
		auth_code: code,
		code_verifier: tx.code_verifier,
		redirect_uri: st.redirect_uri(),
		nonce: tx.nonce,
		user_agent,
		ip,
	};
	match AuthRpc::exchange(&st.auth, tonic::Request::new(req)).await {
		Ok(response) => {
			let tokens = response.into_inner();
			let access_token = tokens.access_token.clone();
			let (id, csrf, max_age) = match st.sessions.put(tokens).await {
				Ok(Some(opened)) => opened,
				Ok(None) => return fail(st, jar, &return_to, "exchange"),
				Err(e) => {
					tracing::error!(error = ?e, "auth callback: session store put failed");
					return fail(st, jar, &return_to, "session");
				}
			};
			let jar = jar
				.add(st.cookies.server_cookie(st.cookies.session.clone(), id, max_age))
				.add(st.cookies.readable_cookie(st.cookies.csrf.clone(), csrf, max_age))
				// The zone-shared credential: every same-origin request carries it, and a
				// zone backend verifies it locally against this plane's JWKS. The JWT
				// inside expires on its own short TTL; `/auth/session` re-sets it.
				.add(st.cookies.server_cookie(st.cookies.access.clone(), access_token, max_age));
			let jar = clear_tx(st, jar);
			(jar, Redirect::to(&safe_return_to(Some(&tx.return_to))))
		}
		Err(e) => {
			// Surface the upstream status server-side; the user only sees `?auth_error=`.
			tracing::error!(code = ?e.code(), detail = %e.message(), "auth callback token exchange failed");
			fail(st, jar, &return_to, "exchange")
		}
	}
}
/// `GET /auth/session` — who-am-I for the browser, refreshing the access token (and
/// its zone-shared cookie) transparently. Never returns a token in the body.
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
	if let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_string())
		&& let Some(refresh) = st.sessions.forget(&id).await.map_err(store_err)?
	{
		// The session is already gone locally; an upstream blip must not block logout.
		let _ = AuthRpc::logout(
			&st.auth,
			tonic::Request::new(cc::LogoutRequest {
				refresh_token: refresh,
				revoke_all: false,
			}),
		)
		.await;
	}
	Ok((clear_session(st, jar), Json(json!({ "ok": true }))))
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
	status: String,
	role: String,
	is_admin: bool,
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
	/// The one redirect URI registered with Google: the callback on the user-facing origin.
	fn redirect_uri(&self) -> String {
		format!("{}/api/callback/auth/google", self.public_origin)
	}
}

/// A session-store failure is a 500, never an auth verdict: the session may well
/// still exist, so neither cookies nor upstream state may be touched off it.
fn store_err(e: color_eyre::Report) -> (StatusCode, &'static str) {
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
async fn verify_csrf(st: &super::Inner, jar: &CookieJar, headers: &HeaderMap) -> Result<bool, (StatusCode, &'static str)> {
	let Some(cookie) = jar.get(&st.cookies.csrf).map(|c| c.value().to_string()) else {
		return Ok(false);
	};
	let Some(header) = headers.get("x-ev-csrf").and_then(|v| v.to_str().ok()) else {
		return Ok(false);
	};
	if cookie != header {
		return Ok(false);
	}
	match jar.get(&st.cookies.session).map(|c| c.value().to_string()) {
		Some(id) => Ok(st.sessions.csrf(&id).await.map_err(store_err)?.as_deref() == Some(header)),
		None => Ok(false),
	}
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
fn client_ip(headers: &HeaderMap) -> String {
	if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
		let first = xff.split(',').next().unwrap_or("").trim();
		if !first.is_empty() {
			return first.to_string();
		}
	}
	headers.get("x-real-ip").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}
