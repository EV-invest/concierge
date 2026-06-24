//! Google OAuth2 confidential-client flow (the only outbound HTTP this hub makes).
//!
//! The auth service exchanges the browser's authorization code (with its PKCE
//! verifier) for Google's tokens, verifies the returned `id_token` against Google's
//! JWKS, checks the `nonce`, and extracts the stable `sub` + verified email.
//! Google's token is then **discarded** — it is never forwarded inward; the hub
//! mints its own first-party token instead, and the plane's `sub` is the hub user
//! id, never Google's `sub`.
//!
//! Scaffold: [`GoogleOauth::exchange_code`] is a stub returning
//! [`AuthError::NotConfigured`]. The canonical implementation (id_token verify +
//! throttled certs refresh) lives in the banking twin (`piggybank/auth/src/google.rs`);
//! this module exists to keep the verify-then-discard contract and the `reqwest`
//! outbound seam visible before the concierge flow is wired.

use crate::{AuthError, config::GoogleConfig};

/// The verified identity extracted from a Google `id_token`.
#[derive(Debug, Clone)]
pub struct GoogleIdentity {
	pub subject: String,
	pub email: String,
	pub email_verified: bool,
}

/// A configured Google OAuth2 client.
pub struct GoogleOauth {
	#[allow(dead_code)]
	http: reqwest::Client,
	#[allow(dead_code)]
	client_id: String,
	#[allow(dead_code)]
	client_secret: String,
}

impl GoogleOauth {
	pub fn new(config: &GoogleConfig) -> Self {
		Self {
			http: reqwest::Client::new(),
			client_id: config.client_id.clone(),
			client_secret: config.client_secret.clone(),
		}
	}

	/// Exchange an authorization code for Google's tokens and return the verified
	/// identity. `nonce` must equal the one the BFF placed in the authorize request.
	///
	/// Scaffold stub — returns [`AuthError::NotConfigured`]. The real body posts to
	/// Google's token endpoint, verifies the `id_token` locally (RS256, audience =
	/// our client id, issuer = accounts.google.com, matching `nonce`), then discards
	/// the Google token.
	pub async fn exchange_code(&self, _auth_code: &str, _code_verifier: &str, _redirect_uri: &str, _nonce: &str) -> Result<GoogleIdentity, AuthError> {
		Err(AuthError::NotConfigured)
	}
}
