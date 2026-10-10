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
use strum::{EnumString, IntoStaticStr, VariantArray};

use crate::error::DomainError;

/// The platform-wide seat. `Investor` is the default (every provisioned user). Written
/// only by governance; what a seat may do is [`Role::permissions`].
#[derive(Clone, Copy, Debug, Default, Deserialize, EnumString, Eq, IntoStaticStr, PartialEq, Serialize, VariantArray)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
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
		self.into()
	}

	/// An unrecognized value is a validation error rather than a silent default, so a bad
	/// row never quietly grants or drops privilege.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		raw.parse().map_err(|_| DomainError::Validation(format!("unknown role: {raw}")))
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

/// What an account may do with its own record — one per cabinet section, so "this needs
/// an account" is a permission a guest lacks rather than a special case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
#[permission("concierge:self")]
pub enum Own {
	Profile,
	Notifications,
	Sessions,
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

	/// An account's own money: its wallet, its investments, its operations.
	#[derive(Clone, Copy, Debug, Eq, PartialEq, Permission)]
	#[permission("bank:self")]
	pub enum Own {
		Wallet,
		Invest,
		Operations,
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
// does every act except granting seats, an owner does everything. Every seat is an account
// first, so each holds what an investor does over its own record.
//
// A guest is nobody's seat — `Role` is the persisted, cross-plane word, and a guest has no
// row — but it is a principal all the same, and this is all it holds.
alias!(pub SEAT_GUEST = "seat:guest", []);
alias!(
	SEAT_INVESTOR = "seat:investor",
	[Own::Profile, Own::Notifications, Own::Sessions, bank::Own::Wallet, bank::Own::Invest, bank::Own::Operations]
);
alias!(
	SEAT_OPERATOR = "seat:operator",
	[
		Own::Profile,
		Own::Notifications,
		Own::Sessions,
		bank::Own::Wallet,
		bank::Own::Invest,
		bank::Own::Operations,
		Users::Read,
		Platform::Read,
		Treasury::Read,
		UserBalance::Read,
	]
);
alias!(
	SEAT_ADMIN = "seat:admin",
	[
		Own::Profile,
		Own::Notifications,
		Own::Sessions,
		bank::Own::Wallet,
		bank::Own::Invest,
		bank::Own::Operations,
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
		Own::Profile,
		Own::Notifications,
		Own::Sessions,
		bank::Own::Wallet,
		bank::Own::Invest,
		bank::Own::Operations,
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

/// Orders what each seat's `bank:*` set means across binaries: a running older binary must
/// not overwrite a newer meaning. Bump it whenever any [`Role::bank_permissions`] changes.
pub const SEAT_GENERATION: u32 = 2;

impl Role {
	/// The concrete permissions this seat holds: `concierge:*`, `iam:*` and `bank:*`.
	pub fn permissions(self) -> &'static [&'static str] {
		match self {
			Self::Investor => SEAT_INVESTOR.members,
			Self::Operator => SEAT_OPERATOR.members,
			Self::Admin => SEAT_ADMIN.members,
			Self::Owner => SEAT_OWNER.members,
		}
	}

	pub fn may(self, permission: impl Permission) -> bool {
		self.permissions().contains(&permission.as_str())
	}

	/// The `bank:*` part of [`Self::permissions`], sorted: what the money plane mirrors.
	pub fn bank_permissions(self) -> Vec<&'static str> {
		let mut bank: Vec<_> = self.permissions().iter().copied().filter(|p| p.starts_with("bank:")).collect();
		bank.sort_unstable();
		bank
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
		for &role in Role::VARIANTS {
			assert_eq!(Role::parse(role.as_str()).unwrap(), role);
		}
		assert!(Role::parse("superuser").is_err());
	}

	#[test]
	fn default_role_is_investor() {
		assert_eq!(Role::default(), Role::Investor);
		assert!(Role::Investor.may(Own::Profile) && Role::Investor.may(bank::Own::Wallet));
		assert!(!Role::Investor.may(Users::Read));
	}

	#[test]
	fn seat_bank_sets_are_pinned_to_their_generation() {
		let seats: Vec<(&str, Vec<&str>)> = Role::VARIANTS.iter().map(|r| (r.as_str(), r.bank_permissions())).collect();
		let own = vec!["bank:self:invest", "bank:self:operations", "bank:self:wallet"];
		let staff = vec![
			"bank:allocation:manage",
			"bank:capital:manage",
			"bank:consilium:manage",
			"bank:deposit_address:migrate",
			"bank:deposit_address:rotate",
			"bank:operations:manage",
			"bank:outbox:manage",
			"bank:payment:open",
			"bank:redemption:fail",
			"bank:redemption:settle",
			"bank:self:invest",
			"bank:self:operations",
			"bank:self:wallet",
			"bank:treasury:read",
			"bank:user:revoke",
			"bank:user:suspend",
			"bank:user_balance:read",
			"bank:valuation:post",
			"bank:withdrawal:dispatch",
			"bank:withdrawal:fail",
			"bank:withdrawal:settle",
		];
		let pinned = vec![
			("investor", own),
			(
				"operator",
				vec!["bank:self:invest", "bank:self:operations", "bank:self:wallet", "bank:treasury:read", "bank:user_balance:read"],
			),
			("admin", staff.clone()),
			("owner", staff),
		];
		assert_eq!(
			(SEAT_GENERATION, seats),
			(2, pinned),
			"a seat's bank:* set changed: bump SEAT_GENERATION, then pin the new sets and generation here"
		);
	}

	#[test]
	fn a_guest_holds_nothing_an_account_does() {
		assert!(SEAT_GUEST.members.is_empty());
		for &role in Role::VARIANTS {
			assert!(role.may(Own::Profile), "{role:?} is an account first");
		}
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
