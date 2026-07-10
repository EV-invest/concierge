//! The site-level auth HTTP surface — the one plain-HTTP seam of the plane.
//!
//! Auth is shell-owned: the site conductor rewrites `evinvest.ltd/api/auth/*` and
//! `/api/callback/auth/*` here, so the browser only ever sees the shared origin and
//! every zone (cabinet, REA, …) receives the same two cookies first-party:
//!
//!   - `__Host-ev_session` — opaque id for the server-held token pair (refresh
//!     rotation stays server-side, never in the browser).
//!   - `__Host-ev_access`  — the short-TTL access JWT, `Path=/`, so a zone's own
//!     backend authenticates a request by verifying it locally against this
//!     plane's JWKS (`evconcierge_auth::Verifier`) — no per-request round trip and
//!     no zone-side OAuth. A zone signs a user in by linking to
//!     `/api/auth/login?returnTo=<path>`; that is the entire zone-side contract.
//!
//! Ported from the cabinet BFF's token-handler (its `oauth`/`cookies`/`session`
//! modules) minus everything banking: the money-plane pair is the cabinet's own
//! concern, minted zone-side from the verified access token.

mod oauth;
mod routes;
mod session;

use std::sync::Arc;

use axum::{
	Router,
	routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use evconcierge_auth::AuthService;
use time::Duration;

use crate::web::{oauth::OAuthTxStore, session::WebSessions};

/// An opaque identifier: `n` bytes of CSPRNG entropy, base64url-encoded (no padding).
fn random_token(n: usize) -> String {
	use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
	let mut buf = vec![0u8; n];
	getrandom::fill(&mut buf).expect("CSPRNG unavailable");
	URL_SAFE_NO_PAD.encode(buf)
}

/// Current unix time in seconds (matches the proto `*_expires_at` fields).
fn now_secs() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Cookie names + shared attributes. `__Host-` prefixed when secure (production);
/// bare in http dev, since the prefix requires `Secure`.
pub struct CookieNames {
	pub session: String,
	pub csrf: String,
	pub access: String,
	pub oauth_tx: String,
	secure: bool,
}

impl CookieNames {
	pub fn new(secure: bool) -> Self {
		let prefix = if secure { "__Host-" } else { "" };
		Self {
			session: format!("{prefix}ev_session"),
			csrf: format!("{prefix}ev_csrf"),
			access: format!("{prefix}ev_access"),
			oauth_tx: format!("{prefix}ev_oauth_tx"),
			secure,
		}
	}

	/// A server-side (HttpOnly) cookie carrying the shared base attributes.
	pub fn server_cookie(&self, name: String, value: String, max_age: i64) -> Cookie<'static> {
		self.build(name, value, max_age, true)
	}

	/// The CSRF cookie — NOT HttpOnly, so client JS can read it for the double-submit header.
	pub fn readable_cookie(&self, name: String, value: String, max_age: i64) -> Cookie<'static> {
		self.build(name, value, max_age, false)
	}

	/// An expiring cookie that clears `name` (empty value, `Max-Age=0`, same attributes).
	pub fn removal(&self, name: String, http_only: bool) -> Cookie<'static> {
		self.build(name, String::new(), 0, http_only)
	}

	fn build(&self, name: String, value: String, max_age: i64, http_only: bool) -> Cookie<'static> {
		let mut c = Cookie::new(name, value);
		c.set_path("/");
		c.set_http_only(http_only);
		c.set_secure(self.secure);
		c.set_same_site(SameSite::Lax);
		c.set_max_age(Duration::seconds(max_age));
		c
	}
}

/// Shared state for the auth HTTP routes. Cheaply cloneable.
#[derive(Clone)]
pub struct WebState {
	inner: Arc<Inner>,
}

struct Inner {
	/// The issuance service, called IN-PROCESS through its gRPC trait — the web
	/// layer is just another (local) client of the same `Exchange`/`Refresh`/
	/// `Logout` surface, so issuance semantics live in exactly one place.
	auth: AuthService,
	oauth: OAuthTxStore,
	sessions: WebSessions,
	cookies: CookieNames,
	/// Public OAuth client id; `None` ⇒ login answers 503 (mirrors the inert plane).
	google_client_id: Option<String>,
	/// The user-facing origin the conductor serves (e.g. `https://evinvest.ltd`).
	/// Builds the redirect_uri: `{public_origin}/api/callback/auth/google`.
	public_origin: String,
}

impl WebState {
	pub fn new(auth: AuthService, public_origin: String, secure_cookies: bool) -> Self {
		Self {
			inner: Arc::new(Inner {
				auth,
				oauth: OAuthTxStore::new(),
				sessions: WebSessions::new(),
				cookies: CookieNames::new(secure_cookies),
				google_client_id: std::env::var("GOOGLE_CLIENT_ID").ok().filter(|v| !v.is_empty()),
				public_origin: public_origin.trim_end_matches('/').to_string(),
			}),
		}
	}
}

/// The auth surface, mounted behind the conductor's `/api` prefix rewrites:
/// `/api/auth/:rest*` → `/auth/:rest*`, `/api/callback/auth/*` → `/callback/auth/*`.
pub fn router(state: WebState) -> Router {
	Router::new()
		// k8s liveness/readiness probe target — the only unauthenticated route.
		.route("/health", get(|| async { "ok" }))
		.route("/auth/login", get(routes::login))
		.route("/callback/auth/google", get(routes::callback))
		.route("/auth/session", get(routes::session))
		.route("/auth/logout", post(routes::logout))
		.route("/auth/sessions", get(routes::list_sessions).delete(routes::revoke_session))
		.with_state(state)
}
