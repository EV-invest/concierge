//! `auth` bounded context — identities (wasm-safe half).
//!
//! The pure, transport-free identity types shared across the plane. The
//! *server-only* token machinery — JWKS, signing, verification, the tonic layer —
//! lives in the `evconcierge_auth` crate, which is wasm-unsafe and therefore must
//! NOT be a dependency of this crate. Keep this module free of crypto and I/O so
//! `domain` stays wasm-safe for service frontends.

use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};

use crate::{error::DomainError, users::Email};

/// The account's opaque, immutable cross-plane subject: the key both planes correlate a
/// [`User`](crate::users::User) on, never reused and never changing. Accounts provisioned
/// before sign-in methods were split out carry their Google `sub`; later ones their own
/// [`UserId`](crate::users::UserId). Which provider subjects open an account is
/// [`ProvenIdentity`]'s business, not this one's.
///
/// Serializes transparently as the bare string so the wire/storage shape is just the
/// subject value.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuthSubject(String);

impl AuthSubject {
	/// Parse a provider subject, rejecting an empty value. Trimmed but otherwise
	/// opaque — the IdP owns its format.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		let trimmed = raw.trim();
		if trimmed.is_empty() {
			return Err(DomainError::Validation("auth subject must not be empty".into()));
		}
		Ok(Self(trimmed.to_owned()))
	}

	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl core::fmt::Display for AuthSubject {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.write_str(&self.0)
	}
}

/// An identity provider whose subject can open an account.
#[derive(Clone, Copy, Debug, EnumString, Eq, IntoStaticStr, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum Provider {
	Google,
	Github,
}

impl Provider {
	pub fn as_str(self) -> &'static str {
		self.into()
	}
}

/// What a sign-in proved about the person at the keyboard. Every method that is not a
/// password lands here, and one rule turns it into an account (the directory's `resolve`).
#[derive(Clone, Debug)]
pub struct ProvenIdentity {
	/// The provider subject, for an OAuth sign-in; `None` for an emailed code.
	pub provider: Option<(Provider, String)>,
	pub email: Email,
	/// Whether the mailbox itself was proven — by our own code, or by a provider that
	/// says it verified the address. Only a proven mailbox links to an existing account.
	pub email_proven: bool,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_trims_and_rejects_empty() {
		assert_eq!(AuthSubject::parse("  g-123 ").unwrap().as_str(), "g-123");
		assert!(AuthSubject::parse("   ").is_err());
	}

	#[test]
	fn serializes_as_bare_string() {
		let json = serde_json::to_string(&AuthSubject::parse("g-1").unwrap()).unwrap();
		assert_eq!(json, "\"g-1\"");
	}
}
