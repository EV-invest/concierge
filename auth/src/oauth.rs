//! The OAuth identity providers a browser may sign in through — a closed set, so a
//! provider's endpoints, scopes and claim rules sit in its own arm rather than behind
//! a trait object. Every arm runs authorization code + PKCE (S256) and answers the same
//! [`OAuthIdentity`]; what an identity opens is the directory's decision, not this one's.

use crate::{AuthError, config::OAuthClientConfig, github::GithubOauth, google::GoogleOauth};

/// What a provider vouched for. Primitive on purpose: this crate stays free of `domain`.
#[derive(Clone, Debug)]
pub struct OAuthIdentity {
	/// The provider's immutable id for the person.
	pub subject: String,
	pub email: String,
	/// The provider says it verified the mailbox.
	pub email_verified: bool,
}

pub enum OAuthProvider {
	Google(GoogleOauth),
	Github(GithubOauth),
}

impl OAuthProvider {
	pub fn google(config: &OAuthClientConfig) -> Self {
		Self::Google(GoogleOauth::new(config))
	}

	pub fn github(config: &OAuthClientConfig) -> Self {
		Self::Github(GithubOauth::new(config))
	}

	/// GitHub at stand-in endpoints, for suites that drive a whole sign-in offline.
	#[cfg(feature = "test-support")]
	pub fn github_at(config: &OAuthClientConfig, token_endpoint: &str, api: &str) -> Self {
		Self::Github(GithubOauth::with_endpoints(config, token_endpoint, api))
	}

	/// The `user_identities.provider` / `?provider=` / callback path segment.
	pub fn name(&self) -> &'static str {
		match self {
			Self::Google(_) => "google",
			Self::Github(_) => "github",
		}
	}

	/// Where to send the browser. `nonce` is bound into the provider's answer where the
	/// protocol has one (OpenID Connect); the PKCE challenge always is.
	pub fn authorize_url(&self, redirect_uri: &str, state: &str, nonce: &str, code_challenge: &str) -> String {
		match self {
			Self::Google(google) => google.authorize_url(redirect_uri, state, nonce, code_challenge),
			Self::Github(github) => github.authorize_url(redirect_uri, state, code_challenge),
		}
	}

	/// Redeem the callback's code. Errors keep the plane's split: [`AuthError::Provider`]
	/// is the provider refusing THIS sign-in, [`AuthError::ProviderUnavailable`] an
	/// incident nobody fixes by signing in again.
	pub async fn exchange_code(&self, code: &str, code_verifier: &str, redirect_uri: &str, nonce: &str) -> Result<OAuthIdentity, AuthError> {
		match self {
			Self::Google(google) => google.exchange_code(code, code_verifier, redirect_uri, nonce).await,
			Self::Github(github) => github.exchange_code(code, code_verifier, redirect_uri).await,
		}
	}
}
