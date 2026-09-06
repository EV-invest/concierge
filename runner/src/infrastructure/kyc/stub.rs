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

use crate::ports::{CallbackHeaders, KycCallbackError, KycDecision, KycProvider, KycSession};

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
