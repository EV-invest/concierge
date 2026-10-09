//! GitHub OAuth app flow — the [`OAuthProvider::Github`] arm.
//!
//! [`OAuthProvider::Github`]: crate::oauth::OAuthProvider::Github
//!
//! GitHub speaks plain OAuth2, not OpenID Connect: there is no id_token to verify, so the
//! identity is read with the access token from the API — the numeric user id (stable
//! across renames, unlike the login) and the PRIMARY email, verified or not as GitHub
//! says. The access token is used for those two reads and dropped.

use serde::Deserialize;

use crate::{AuthError, config::OAuthClientConfig, oauth::OAuthIdentity};

const AUTHORIZE_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
const API: &str = "https://api.github.com";

pub struct GithubOauth {
	client_id: String,
	client_secret: String,
	http: reqwest::Client,
	token_endpoint: String,
	api: String,
}

impl GithubOauth {
	pub fn new(config: &OAuthClientConfig) -> Self {
		Self::with_endpoints(config, TOKEN_ENDPOINT, API)
	}

	pub(crate) fn with_endpoints(config: &OAuthClientConfig, token_endpoint: &str, api: &str) -> Self {
		Self {
			client_id: config.client_id.clone(),
			client_secret: config.client_secret.clone(),
			// GitHub refuses API calls without a User-Agent.
			http: reqwest::Client::builder().user_agent("evinvest-concierge").build().expect("a static reqwest client builds"),
			token_endpoint: token_endpoint.to_owned(),
			api: api.trim_end_matches('/').to_owned(),
		}
	}

	pub fn authorize_url(&self, redirect_uri: &str, state: &str, code_challenge: &str) -> String {
		let query = form_urlencoded::Serializer::new(String::new())
			.append_pair("client_id", &self.client_id)
			.append_pair("redirect_uri", redirect_uri)
			.append_pair("scope", "read:user user:email")
			.append_pair("state", state)
			.append_pair("code_challenge", code_challenge)
			.append_pair("code_challenge_method", "S256")
			.append_pair("prompt", "select_account")
			.finish();
		format!("{AUTHORIZE_ENDPOINT}?{query}")
	}

	pub async fn exchange_code(&self, code: &str, code_verifier: &str, redirect_uri: &str) -> Result<OAuthIdentity, AuthError> {
		let unavailable = |what: &str, e: reqwest::Error| AuthError::ProviderUnavailable(format!("github {what} failed: {e}"));
		let response = self
			.http
			.post(&self.token_endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.form(&[
				("client_id", self.client_id.as_str()),
				("client_secret", self.client_secret.as_str()),
				("code", code),
				("redirect_uri", redirect_uri),
				("code_verifier", code_verifier),
			])
			.send()
			.await
			.map_err(|e| unavailable("token request", e))?;
		if !response.status().is_success() {
			return Err(AuthError::ProviderUnavailable(format!("github token endpoint returned {}", response.status())));
		}
		// A refused grant comes back 200 with `error` set (bad_verification_code, a PKCE
		// mismatch): the caller's sign-in, not an incident.
		let token: TokenResponse = response.json().await.map_err(|e| unavailable("token response", e))?;
		let access_token = match (token.access_token, token.error) {
			(Some(token), None) => token,
			(_, Some(error)) => return Err(AuthError::Provider(format!("github refused the code: {error}"))),
			(None, None) => return Err(AuthError::ProviderUnavailable("github token response had neither a token nor an error".into())),
		};

		let user: User = self.get(&access_token, "/user").await?;
		let emails: Vec<EmailEntry> = self.get(&access_token, "/user/emails").await?;
		let primary = emails
			.into_iter()
			.find(|e| e.primary)
			.ok_or_else(|| AuthError::Provider("github account has no primary email".into()))?;
		Ok(OAuthIdentity {
			subject: user.id.to_string(),
			email: primary.email,
			email_verified: primary.verified,
		})
	}

	async fn get<T: for<'de> Deserialize<'de>>(&self, token: &str, path: &str) -> Result<T, AuthError> {
		let response = self
			.http
			.get(format!("{}{path}", self.api))
			.bearer_auth(token)
			.header(reqwest::header::ACCEPT, "application/vnd.github+json")
			.send()
			.await
			.map_err(|e| AuthError::ProviderUnavailable(format!("github {path} failed: {e}")))?;
		if !response.status().is_success() {
			return Err(AuthError::ProviderUnavailable(format!("github {path} returned {}", response.status())));
		}
		response.json().await.map_err(|e| AuthError::ProviderUnavailable(format!("malformed github {path}: {e}")))
	}
}

#[derive(Deserialize)]
struct TokenResponse {
	access_token: Option<String>,
	error: Option<String>,
}

#[derive(Deserialize)]
struct User {
	id: u64,
}

#[derive(Deserialize)]
struct EmailEntry {
	email: String,
	primary: bool,
	verified: bool,
}
