use serde::{Deserialize, Serialize};

/// The kind of first-party **JWT**, carried in the `typ` claim.
///
/// This keeps the two signed-token directions apart: a human-user `Access` token
/// can never stand in for an inter-service `Service` token (or vice versa) — even
/// before `aud` is checked. A verifier states the `typ`s it accepts in its
/// [`VerifyPolicy`](crate::jwks::VerifyPolicy). (Refresh tokens are **not** JWTs —
/// they are opaque, rotated, server-side handles — so they have no `typ`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
	/// A short-TTL access token for an http client (the cabinet's user), scoped to
	/// the concierge plane's audience.
	Access,
	/// An inter-service token: another backend authenticating its onward gRPC calls
	/// into the plane, scoped to the service audience.
	Service,
}

impl TokenType {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Access => "access",
			Self::Service => "service",
		}
	}
}

/// First-party token claims minted by the concierge auth service and verified
/// locally by every service against the published JWKS.
///
/// `sub` is the plane's canonical principal id — a user UUID for [`TokenType::Access`]
/// (never Google's `sub`), or a service name for [`TokenType::Service`]. It is a
/// plain `String` so this crate never needs to depend on `domain`; the plane parses
/// it into a typed id at the edge.
///
/// `token_version` lets the auth service invalidate all of a principal's tokens (a
/// "revoke all" bumps the stored version). It is checked where the authoritative
/// value is reachable — at refresh time by the auth service — not by stateless
/// downstream verifiers, which rely on the short access-token TTL instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
	/// Subject — the principal id (user UUID or service name).
	pub sub: String,
	/// Issuer — the concierge auth service. Enforced by [`verify_token`](crate::jwks::verify_token).
	pub iss: String,
	/// Audience — the service/group the token is scoped to.
	pub aud: String,
	/// Expiry (unix seconds). TTL is short (5–15 min for access tokens).
	pub exp: u64,
	/// Issued-at (unix seconds).
	#[serde(default)]
	pub iat: u64,
	/// Token kind — the access/service discriminator.
	pub typ: TokenType,
	/// Per-principal token version for coarse "revoke all" semantics.
	#[serde(default)]
	pub token_version: u64,
}

impl Claims {
	/// The common "is this an access token for a user" guard; parsing `sub` into a
	/// `Uuid` is left to the caller.
	pub fn is_access(&self) -> bool {
		matches!(self.typ, TokenType::Access)
	}
}
