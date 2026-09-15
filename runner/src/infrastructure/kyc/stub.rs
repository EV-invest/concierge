//! A no-network [`KycProvider`] so the whole flow — start, redirect, signed callback,
//! level change, outbox row — runs on a laptop and in CI with no vendor account.
//!
//! It stubs the ONE thing that needs a vendor (opening a session) and delegates
//! callback verification to [`super::didit::parse_webhook`] verbatim. That is the point:
//! a stub with its own, laxer signature check would make every local and CI run a test
//! of code that never ships.

use async_trait::async_trait;
use domain::error::DomainError;
use uuid::Uuid;

use crate::{
	infrastructure::kyc::origin_of,
	ports::{CallbackHeaders, KycCallbackError, KycDecision, KycProvider, KycSession},
};

pub const PROVIDER: &str = "stub";

pub struct StubKyc {
	secret: String,
	return_url: String,
}

impl StubKyc {
	pub fn new(secret: String, return_url: String) -> Self {
		Self { secret, return_url }
	}

	/// The secret a caller signs a simulated delivery with (`didit::sign_body`).
	pub fn secret(&self) -> &str {
		&self.secret
	}
}

#[async_trait]
impl KycProvider for StubKyc {
	fn name(&self) -> &'static str {
		PROVIDER
	}

	/// The cabinet itself: the stub's "vendor page" is a cabinet URL carrying a fake
	/// session ref, so `CABINET_URL` is both what it composes and what it answers with.
	///
	/// Its scheme is taken as given rather than forced to `https`, because the stub is
	/// refused in production (`build_kyc_provider`) and the machine it does run on
	/// serves the cabinet over `http://localhost`. Requiring `https` here would turn
	/// every local start into the 503 that "arrives as silence".
	fn session_origins(&self) -> Vec<String> {
		origin_of(&self.return_url).into_iter().collect()
	}

	/// Derives the session id from the case id rather than minting one, so a local
	/// driver can construct the callback body without having to read the case back.
	async fn start_session(&self, case_id: Uuid, _requested_tier: u32) -> Result<KycSession, DomainError> {
		let provider_ref = format!("stub-{case_id}");
		let redirect_url = format!("{}?kyc_session={provider_ref}", self.return_url.trim_end_matches('/'));
		Ok(KycSession { provider_ref, redirect_url })
	}

	fn parse_callback(&self, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
		super::didit::parse_webhook(&self.secret, headers, body, now)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The stub's vendor IS the cabinet, so `CABINET_URL` decides what a redirect may be
	/// — and its scheme is taken as given. A developer serving the cabinet on
	/// `http://localhost:3000` must not meet the 503 that "arrives as silence"; the stub
	/// is refused in production, so nothing prod-facing inherits that latitude.
	#[test]
	fn the_stub_trusts_the_cabinet_it_was_built_from() {
		assert_eq!(
			StubKyc::new("s".into(), "https://evinvest.test/cabinet".into()).session_origins(),
			vec!["https://evinvest.test".to_string()]
		);
		assert_eq!(
			StubKyc::new("s".into(), "http://localhost:3000/cabinet".into()).session_origins(),
			vec!["http://localhost:3000".to_string()]
		);
	}

	/// A `CABINET_URL` with no origin leaves the adapter unable to say where its vendor
	/// is. The empty answer refuses every redirect, and the boot refuses to mount it at
	/// all — the one shape this must NOT take is degrading to "any https will do".
	#[test]
	fn an_originless_cabinet_url_declares_nothing() {
		assert!(StubKyc::new("s".into(), "not a url".into()).session_origins().is_empty());
	}
}
