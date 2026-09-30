//! `GET /auth/authorize` — the browser-facing half of the relying-party code flow
//! (publicly `evinvest.ltd/api/auth/authorize`, through the conductor's existing
//! `/api/auth/*` rewrite).
//!
//! The ONE property this route exists to keep: it never sends a browser to an address
//! that is not registered, byte for byte, for the client named. So the client and the
//! redirect_uri are settled FIRST, and anything wrong with either is answered with a page
//! on this origin, never a redirect. Only once the redirect_uri is known to be the
//! client's own does an error travel back to it (`error=…&state=…`), the way OAuth
//! clients expect to receive one.
//!
//! Signing in is not re-implemented: a browser with no session is sent to the ordinary
//! `/api/auth/login` with `returnTo` pointing back here, which `safe_return_to` already
//! admits (a same-origin path). The Google client never learns a relying party exists.

use axum::{
	extract::{Query, State},
	http::{HeaderMap, HeaderValue, StatusCode, header},
	response::{Html, IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
	relying_party::{Admission, Requester, is_s256_challenge},
	web::{WebState, routes::client_ip},
};

/// The public path of this route — what `returnTo` must name for the login to come back.
const PUBLIC_PATH: &str = "/api/auth/authorize";
/// The public path of the ordinary login.
const LOGIN_PATH: &str = "/api/auth/login";
/// OAuth `state` is the client's opaque value; bounded so it stays a value.
const MAX_STATE_LEN: usize = 512;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
	client_id: Option<String>,
	redirect_uri: Option<String>,
	response_type: Option<String>,
	state: Option<String>,
	code_challenge: Option<String>,
	code_challenge_method: Option<String>,
	/// Set by the login callback when the sign-in itself failed or was cancelled.
	auth_error: Option<String>,
}

pub async fn authorize(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Query(q): Query<AuthorizeQuery>) -> Response {
	let st = &st.inner;
	let Some(relying_parties) = st.relying_parties.as_ref() else {
		return page(StatusCode::SERVICE_UNAVAILABLE, "Sign-in for this application is not available right now.");
	};
	let (Some(client_id), Some(redirect_uri)) = (q.client_id.as_deref(), q.redirect_uri.as_deref()) else {
		return page(StatusCode::BAD_REQUEST, "This sign-in link is incomplete.");
	};
	let client = match relying_parties.resolve(client_id, redirect_uri).await {
		Ok(Some(client)) => client,
		Ok(None) => {
			tracing::warn!(client_id = %client_id.chars().take(32).collect::<String>(), "relying party: authorize refused an unregistered client or redirect_uri");
			return page(StatusCode::BAD_REQUEST, "This sign-in link is not valid.");
		}
		Err(err) => {
			tracing::error!(%err, "relying party: registry unreadable at authorize");
			return page(StatusCode::SERVICE_UNAVAILABLE, "Sign-in for this application is not available right now.");
		}
	};

	// The redirect_uri is the client's own from here on.
	let back = Back {
		redirect_uri,
		state: q.state.as_deref().filter(|s| s.len() <= MAX_STATE_LEN),
	};
	if q.state.as_deref().is_some_and(|s| s.len() > MAX_STATE_LEN) {
		return back.error("invalid_request");
	}
	if q.response_type.as_deref().is_some_and(|t| t != "code") {
		return back.error("unsupported_response_type");
	}
	let Some(code_challenge) = q.code_challenge.as_deref().filter(|c| is_s256_challenge(c)) else {
		return back.error("invalid_request");
	};
	if q.code_challenge_method.as_deref() != Some("S256") {
		return back.error("invalid_request");
	}

	let fresh = match jar.get(&st.cookies.session).map(|c| c.value().to_string()) {
		Some(id) => match st.sessions.fresh(&id, &st.auth).await {
			Ok(fresh) => fresh,
			Err(err) => {
				tracing::error!(error = ?err, "relying party: session store failed at authorize");
				return back.error("temporarily_unavailable");
			}
		},
		None => None,
	};
	let Some(fresh) = fresh else {
		// Coming back from a sign-in that failed or was cancelled: send the refusal to the
		// client rather than start the login again, which would loop.
		if q.auth_error.is_some() {
			return back.error("access_denied");
		}
		return redirect(&login_url(client_id, redirect_uri, q.state.as_deref(), code_challenge, q.response_type.as_deref()));
	};

	let Ok(user) = Uuid::parse_str(&fresh.user.user_id).map(UserId::from_raw) else {
		return back.error("access_denied");
	};
	let token_version = match relying_parties.admit(user, &client).await {
		Ok(Admission::Admitted { token_version }) => token_version,
		Ok(Admission::Denied) => {
			tracing::info!(client_id = %client.client_id, user_id = %user, "relying party: authorize denied by the access policy");
			return back.error("access_denied");
		}
		Err(err) => {
			tracing::error!(%err, "relying party: policy unreadable at authorize");
			return back.error("temporarily_unavailable");
		}
	};
	let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
	let ip = client_ip(&headers);
	match relying_parties
		.issue_code(&client, redirect_uri, code_challenge, user, token_version, Requester { client_ip: &ip, user_agent })
		.await
	{
		Ok(code) => back.with(&[("code", &code)]),
		Err(err) => {
			tracing::error!(%err, "relying party: code store failed at authorize");
			back.error("temporarily_unavailable")
		}
	}
}

/// The client's redirect_uri, once it is known to be registered.
struct Back<'a> {
	redirect_uri: &'a str,
	state: Option<&'a str>,
}

impl Back<'_> {
	fn error(&self, error: &str) -> Response {
		self.with(&[("error", error)])
	}

	fn with(&self, params: &[(&str, &str)]) -> Response {
		let mut query = form_urlencoded::Serializer::new(String::new());
		for (key, value) in params {
			query.append_pair(key, value);
		}
		if let Some(state) = self.state {
			query.append_pair("state", state);
		}
		let sep = if self.redirect_uri.contains('?') { '&' } else { '?' };
		redirect(&format!("{}{sep}{}", self.redirect_uri, query.finish()))
	}
}

/// The login URL that brings the browser back to this exact authorize request. Rebuilt
/// from the parsed parameters, never copied from the raw query, so nothing the caller
/// added rides along.
fn login_url(client_id: &str, redirect_uri: &str, state: Option<&str>, code_challenge: &str, response_type: Option<&str>) -> String {
	let mut back = form_urlencoded::Serializer::new(String::new());
	back.append_pair("client_id", client_id).append_pair("redirect_uri", redirect_uri);
	if let Some(response_type) = response_type {
		back.append_pair("response_type", response_type);
	}
	if let Some(state) = state {
		back.append_pair("state", state);
	}
	back.append_pair("code_challenge", code_challenge).append_pair("code_challenge_method", "S256");
	let return_to = format!("{PUBLIC_PATH}?{}", back.finish());
	let login = form_urlencoded::Serializer::new(String::new()).append_pair("returnTo", &return_to).finish();
	format!("{LOGIN_PATH}?{login}")
}

/// A 302 that no cache keeps: the Location carries a one-time code.
fn redirect(location: &str) -> Response {
	let Ok(location) = HeaderValue::from_str(location) else {
		return page(StatusCode::BAD_REQUEST, "This sign-in link is not valid.");
	};
	(StatusCode::FOUND, [(header::LOCATION, location), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))]).into_response()
}

/// An error page on THIS origin. The text is fixed: nothing from the request is echoed.
fn page(status: StatusCode, message: &'static str) -> Response {
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign-in</title></head>\
		 <body><main><h1>Sign-in could not continue</h1><p>{message}</p><p><a href=\"/\">Go to evinvest.ltd</a></p></main></body></html>"
	);
	(status, [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))], Html(body)).into_response()
}
