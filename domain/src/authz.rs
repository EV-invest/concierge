//! Cross-cutting authorization — the shared role vocabulary and this plane's
//! permission matrix.
//!
//! [`Role`] is the identity plane's source-of-truth attribute on a
//! [`User`](crate::users::User): the platform grants it, persists it, and mirrors it
//! VERBATIM to the banking money plane over the one-way user-lifecycle bridge (only
//! the string crosses). The four discriminant strings are therefore a **cross-plane
//! contract** — keep them byte-identical with banking's `domain::authz::Role`
//! ([`role_strings_are_canonical`] guards this side; banking guards its own).
//!
//! A seat MEANS a set of permissions ([`Role::permissions`]): `concierge:*` and `iam:*`
//! enforced here, `bank:*` enforced by the money plane. Every check asks [`Role::may`];
//! nothing compares seats by rank.

use concierge_iam::{Permission, alias};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// The platform-wide seat. `Investor` is the default (every provisioned user). Written
/// only by governance; what a seat may do is [`Role::permissions`].
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
	#[default]
	Investor,
	Operator,
	Admin,
	Owner,
}

impl Role {
	/// The stored/wire discriminant. Part of the cross-plane bridge contract — do not
	/// diverge from banking's `Role::as_str`.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Investor => "investor",
			Self::Operator => "operator",
			Self::Admin => "admin",
			Self::Owner => "owner",
		}
	}

	/// Parse the stored form back into the enum (persistence + bridge adapters). An
	/// unrecognized value is a validation error rather than a silent default, so a bad
	/// row never quietly grants or drops privilege.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"investor" => Ok(Self::Investor),
			"operator" => Ok(Self::Operator),
			"admin" => Ok(Self::Admin),
			"owner" => Ok(Self::Owner),
			other => Err(DomainError::Validation(format!("unknown role: {other}"))),
		}
	}
}

/// `concierge:user:*` — list/read any user; suspend/reinstate; revoke sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
#[permission("concierge:user")]
pub enum Users {
	Read,
	Suspend,
	Revoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
#[permission("concierge:kyc")]
pub enum Kyc {
	Manage,
}

/// `concierge:role:grant` — `SetRole`, and voting in the consilia.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
#[permission("concierge:role")]
pub enum Roles {
	Grant,
}

/// Feature flags, maintenance, announcements, the client registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
#[permission("concierge:platform")]
pub enum Platform {
	Read,
	Manage,
}

/// `iam:tenants:grant` — grant and revoke anything inside any tenant's namespace. Seats
/// hold it and nothing can grant it, so who hands out access is decided by governance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
#[permission("iam:tenants")]
pub enum Iam {
	Grant,
}

/// The money plane's permissions. Defined here because a seat's meaning is this plane's to
/// state; banking enforces them.
pub mod bank {
	use concierge_iam::Permission;

	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:treasury")]
	pub enum Treasury {
		Read,
	}

	/// Any user's balance/wallet.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:user_balance")]
	pub enum UserBalance {
		Read,
	}

	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:valuation")]
	pub enum Valuation {
		Post,
	}

	/// Register an investable product and drive its lifecycle.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:allocation")]
	pub enum Allocation {
		Manage,
	}

	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:redemption")]
	pub enum Redemption {
		Settle,
		Fail,
	}

	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:withdrawal")]
	pub enum Withdrawal {
		Dispatch,
		Settle,
		Fail,
	}

	/// Seed fund capital / record an off-rail deposit.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:capital")]
	pub enum Capital {
		Manage,
	}

	/// The owners' governance of the platform's own money.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:consilium")]
	pub enum Consilium {
		Manage,
	}

	/// Open a payment order (a proposal, never a move), read payment history.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:payment")]
	pub enum Payment {
		Open,
	}

	/// The read-only kill switch.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:operations")]
	pub enum Operations {
		Manage,
	}

	/// Unpark a parked outbox event.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:outbox")]
	pub enum Outbox {
		Manage,
	}

	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:user")]
	pub enum Users {
		Revoke,
		Suspend,
	}

	/// `rotate` supersedes a provably dead key; `migrate` retires a healthy one into the
	/// enclave. Separate acts: holding one must not grant the other.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:deposit_address")]
	pub enum DepositAddress {
		Rotate,
		Migrate,
	}
}

use bank::*;

// What a seat means, as separation of duties: an operator views and never acts, an admin
// does every act except granting seats, an owner does everything.
alias!(SEAT_OPERATOR = "seat:operator", [Users::Read, Platform::Read, Treasury::Read, UserBalance::Read]);
alias!(
	SEAT_ADMIN = "seat:admin",
	[
		Users::Read,
		Users::Suspend,
		Users::Revoke,
		Kyc::Manage,
		Platform::Read,
		Platform::Manage,
		Iam::Grant,
		Treasury::Read,
		UserBalance::Read,
		Valuation::Post,
		Allocation::Manage,
		Redemption::Settle,
		Redemption::Fail,
		Withdrawal::Dispatch,
		Withdrawal::Settle,
		Withdrawal::Fail,
		Capital::Manage,
		Consilium::Manage,
		Payment::Open,
		Operations::Manage,
		Outbox::Manage,
		bank::Users::Revoke,
		bank::Users::Suspend,
		DepositAddress::Rotate,
		DepositAddress::Migrate,
	]
);
alias!(
	SEAT_OWNER = "seat:owner",
	[
		Users::Read,
		Users::Suspend,
		Users::Revoke,
		Kyc::Manage,
		Roles::Grant,
		Platform::Read,
		Platform::Manage,
		Iam::Grant,
		Treasury::Read,
		UserBalance::Read,
		Valuation::Post,
		Allocation::Manage,
		Redemption::Settle,
		Redemption::Fail,
		Withdrawal::Dispatch,
		Withdrawal::Settle,
		Withdrawal::Fail,
		Capital::Manage,
		Consilium::Manage,
		Payment::Open,
		Operations::Manage,
		Outbox::Manage,
		bank::Users::Revoke,
		bank::Users::Suspend,
		DepositAddress::Rotate,
		DepositAddress::Migrate,
	]
);

impl Role {
	pub const ALL: [Self; 4] = [Self::Investor, Self::Operator, Self::Admin, Self::Owner];

	/// The concrete permissions this seat holds: `concierge:*`, `iam:*` and `bank:*`.
	pub fn permissions(self) -> &'static [&'static str] {
		match self {
			Self::Investor => &[],
			Self::Operator => SEAT_OPERATOR.members,
			Self::Admin => SEAT_ADMIN.members,
			Self::Owner => SEAT_OWNER.members,
		}
	}

	pub fn may(self, permission: impl Permission) -> bool {
		self.permissions().contains(&permission.as_str())
	}

	/// The `bank:*` part of [`Self::permissions`]: what the money plane mirrors.
	pub fn bank_permissions(self) -> Vec<&'static str> {
		self.permissions().iter().copied().filter(|p| p.starts_with("bank:")).collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn role_strings_are_canonical() {
		// Cross-plane bridge contract: these four strings must match banking's Role
		// verbatim. If you change one, change banking's `domain::authz::Role` too.
		assert_eq!(Role::Investor.as_str(), "investor");
		assert_eq!(Role::Operator.as_str(), "operator");
		assert_eq!(Role::Admin.as_str(), "admin");
		assert_eq!(Role::Owner.as_str(), "owner");
	}

	#[test]
	fn role_round_trips_and_rejects_unknown() {
		for role in [Role::Investor, Role::Operator, Role::Admin, Role::Owner] {
			assert_eq!(Role::parse(role.as_str()).unwrap(), role);
		}
		assert!(Role::parse("superuser").is_err());
	}

	#[test]
	fn default_role_is_investor() {
		assert_eq!(Role::default(), Role::Investor);
		assert!(Role::Investor.permissions().is_empty());
	}

	#[test]
	fn seats_separate_duties() {
		assert!(Role::Operator.may(Users::Read));
		assert!(Role::Operator.may(Platform::Read));
		assert!(Role::Operator.may(Treasury::Read));
		assert!(!Role::Operator.may(Users::Suspend));
		assert!(!Role::Operator.may(Iam::Grant));
		assert!(!Role::Operator.may(Payment::Open), "an operator sees the treasury and never proposes from it");
		assert!(Role::Admin.may(Iam::Grant));
		assert!(Role::Admin.may(DepositAddress::Migrate));
		assert!(!Role::Admin.may(Roles::Grant), "an admin never grants seats");
		assert!(Role::Owner.may(Roles::Grant));
		let owner: Vec<_> = Role::Owner.permissions().iter().filter(|p| **p != Roles::Grant.as_str()).collect();
		assert_eq!(owner, Role::Admin.permissions().iter().collect::<Vec<_>>(), "an owner is an admin who also grants seats");
	}
}
