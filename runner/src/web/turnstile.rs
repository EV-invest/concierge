//! Cloudflare Turnstile, checked on this side: a credential endpoint a script can call
//! freely is a mail cannon and a password oracle. There is no arm that skips it —
//! development configures Cloudflare's always-pass test secret instead.

use std::time::Duration;

use serde::Deserialize;

pub const SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

pub struct Turnstile {
	secret: String,
	endpoint: String,
	http: reqwest::Client,
}

#[derive(Deserialize)]
struct Verdict {
	success: bool,
}

impl Turnstile {
	/// `endpoint` is [`SITEVERIFY`] outside a test.
	pub fn new(secret: String, endpoint: String) -> Self {
		Self {
			secret,
			endpoint,
			http: reqwest::Client::builder().timeout(Duration::from_secs(5)).build().expect("a static reqwest client builds"),
		}
	}

	/// `Ok(false)` is Cloudflare saying no; `Err` is not being able to ask, which the
	/// caller refuses too — fail closed.
	pub(super) async fn passes(&self, token: &str, remote_ip: &str) -> Result<bool, reqwest::Error> {
		if token.is_empty() {
			return Ok(false);
		}
		let mut form = vec![("secret", self.secret.as_str()), ("response", token)];
		if !remote_ip.is_empty() {
			form.push(("remoteip", remote_ip));
		}
		let verdict: Verdict = self.http.post(&self.endpoint).form(&form).send().await?.error_for_status()?.json().await?;
		Ok(verdict.success)
	}
}
