//! The relying-party seam: what [`AuthService`](crate::AuthService) needs from the
//! plane to serve `ExchangeCode` / `RefreshClientToken`, stated as a port.
//!
//! This crate owns the signing key and nothing else about a client: the registry, the
//! one-time codes, the refresh families and the access policy (which reads the user
//! directory and the scoped grants) are Postgres state in the runner. So the split is
//! the one `Exchange` already has with the directory — the runner decides WHO gets a
//! token pair and holds the refresh half; this crate mints the access JWT for the
//! decision it is handed.
//!
//! The futures are boxed by hand because the service holds the port as a trait object
//! and this crate has no `async-trait`; one allocation per token exchange is noise.

use std::{future::Future, pin::Pin};

/// A boxed, `Send` future — the return shape of every [`ClientGrants`] method.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// `ExchangeCode`'s inputs, as the client presented them.
pub struct CodeRedemption {
	pub client_id: String,
	pub client_secret: String,
	pub code: String,
	pub redirect_uri: String,
	pub code_verifier: String,
}

/// `RefreshClientToken`'s inputs, as the client presented them.
pub struct ClientRefresh {
	pub client_id: String,
	pub client_secret: String,
	pub refresh_token: String,
}

/// A decision to issue a relying party a token pair: the refresh half already exists
/// server-side, and the access JWT is minted from the rest.
pub struct ClientGrant {
	/// The concierge user id — the access token's `sub`.
	pub user_id: String,
	/// The client's registered audience — the access token's `aud`.
	pub audience: String,
	/// The user's `token_version` at this decision, stamped on the access token.
	pub token_version: u64,
	/// The refresh family, carried in the access token's `jti` so a revoked family ends
	/// its access tokens at the one RPC they reach instead of at their expiry.
	pub session_id: String,
	pub refresh_token: String,
	pub refresh_expires_at: u64,
}

/// Why a relying party got no token pair. Deliberately coarse on the wire: a client
/// learns "your credentials", "that grant" or "that user", never which check tripped.
#[derive(Debug, thiserror::Error)]
pub enum ClientGrantError {
	/// Unknown or disabled client, or a wrong/unset secret.
	#[error("invalid client")]
	InvalidClient,
	/// The code or refresh token is unknown, expired, spent, replayed, or bound to
	/// another client / redirect_uri / PKCE challenge.
	#[error("invalid grant")]
	InvalidGrant,
	/// The grant was genuine but the user no longer passes: suspended, tokens revoked,
	/// or outside the client's access policy.
	#[error("access denied")]
	AccessDenied,
	/// The plane could not decide (storage failure) — never the caller's fault.
	#[error("relying party store unavailable: {0}")]
	Unavailable(String),
}

impl From<ClientGrantError> for tonic::Status {
	fn from(err: ClientGrantError) -> Self {
		match err {
			ClientGrantError::InvalidClient => tonic::Status::unauthenticated("invalid client"),
			ClientGrantError::InvalidGrant => tonic::Status::unauthenticated("invalid grant"),
			ClientGrantError::AccessDenied => tonic::Status::permission_denied("access denied"),
			ClientGrantError::Unavailable(_) => tonic::Status::unavailable("relying party store unavailable"),
		}
	}
}

/// An `evinvest.ltd` sign-out that must also end the relying-party sessions it
/// authorized — single logout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpstreamRevocation {
	/// One refresh family of the user ended (Logout, RevokeSession).
	Family { user_id: String, family_id: String },
	/// Every family of the user ended (revoke-all, refresh reuse, a suspension, a
	/// `token_version` bump seen at refresh).
	User { user_id: String },
}

/// The runner's side of the relying-party flow. Implemented over Postgres by the runner
/// and handed to [`AuthService::with_client_grants`](crate::AuthService::with_client_grants).
pub trait ClientGrants: Send + Sync {
	/// Redeem a one-time code: authenticate the client, burn the code, re-check the
	/// user against the client's policy and open a refresh family.
	fn redeem(&self, redemption: CodeRedemption) -> BoxFuture<'_, Result<ClientGrant, ClientGrantError>>;

	/// Rotate a refresh token after re-checking the user against the client's policy.
	fn refresh(&self, refresh: ClientRefresh) -> BoxFuture<'_, Result<ClientGrant, ClientGrantError>>;

	/// End the client sessions (and outstanding codes) an upstream sign-out took the
	/// authority of.
	fn upstream_revoked(&self, revocation: UpstreamRevocation) -> BoxFuture<'_, Result<(), ClientGrantError>>;
}
