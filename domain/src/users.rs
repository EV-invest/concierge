//! `users` bounded context — the platform's canonical identity record.
//!
//! The [`User`] aggregate is `concierge`'s record of a person: provisioned on
//! first sign-in and kept in sync with the session-auth identity. It is
//! **identity-only** — it holds no money, balances, or subscriptions (those are
//! the banking money plane's concern, reached over the cross-plane bridge).
//!
//! Pure and wasm-safe: no crypto, no I/O, no clock reads. Identities are supplied
//! by the (host-only) application layer, so this stays compilable to wasm and
//! trivially testable.

use ev::architecture::{AggregateRoot, Entity, Id};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// The platform's canonical user id (a UUID). **This** value is the `sub` of the
/// first-party session JWT — never the IdP's `sub`.
pub type UserId = Id<UserTag>;
/// Phantom tag making [`UserId`] a distinct, incompatible identity type.
pub struct UserTag;

/// The minimal user lifecycle. `Disabled` freezes sign-in/refresh without deleting
/// the record (the audit trail must outlive a deactivation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
	Active,
	Disabled,
}

impl UserStatus {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Active => "active",
			Self::Disabled => "disabled",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"active" => Ok(Self::Active),
			"disabled" => Ok(Self::Disabled),
			other => Err(DomainError::Validation(format!("unknown user status: {other}"))),
		}
	}
}

/// The platform's canonical user identity. Construct it with [`User::rehydrate`]
/// (load from the store). Identity-only: email, lifecycle status, and the
/// `token_version` that backs stateless "revoke all".
#[derive(Debug, Clone)]
pub struct User {
	id: UserId,
	email: String,
	status: UserStatus,
	token_version: u64,
}

impl User {
	/// Reconstitute an existing user from the store.
	pub fn rehydrate(id: UserId, email: String, status: UserStatus, token_version: u64) -> Self {
		Self { id, email, status, token_version }
	}

	pub fn id(&self) -> UserId {
		self.id
	}

	pub fn email(&self) -> &str {
		&self.email
	}

	pub fn status(&self) -> UserStatus {
		self.status
	}

	pub fn is_active(&self) -> bool {
		self.status == UserStatus::Active
	}

	pub fn token_version(&self) -> u64 {
		self.token_version
	}
}

impl Entity for User {
	type Id = UserId;

	fn id(&self) -> UserId {
		self.id
	}
}

impl AggregateRoot for User {
	const NAME: &'static str = "user";
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn status_round_trips_through_str() {
		assert_eq!(UserStatus::parse(UserStatus::Active.as_str()).unwrap(), UserStatus::Active);
		assert_eq!(UserStatus::parse(UserStatus::Disabled.as_str()).unwrap(), UserStatus::Disabled);
		assert!(UserStatus::parse("nope").is_err());
	}

	#[test]
	fn rehydrate_exposes_identity_fields() {
		let user = User::rehydrate(UserId::new(), "ada@example.com".to_string(), UserStatus::Active, 0);
		assert_eq!(user.email(), "ada@example.com");
		assert!(user.is_active());
		assert_eq!(user.token_version(), 0);
	}
}
