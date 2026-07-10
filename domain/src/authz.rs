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
//! [`Permission`] is **local** to this plane: concierge enforces identity/platform
//! permissions, banking enforces money permissions — the two never share a set.
//! [`grants`] is the pure policy (the RBAC "matrix") mapping a role to the
//! permissions it holds; it carries the separation-of-duties intent (view ≠ act ≠
//! grant) and is the single place the matrix is defined.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// The platform-wide user role, ordered least→most privileged. `Investor` is the
/// default (every provisioned user); roles above it unlock the admin console and
/// `Owner` additionally manages roles.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

	/// Whether this role may open the admin console at all (any non-investor).
	pub fn is_operator(self) -> bool {
		self >= Role::Operator
	}
}

/// A capability in the IDENTITY/PLATFORM plane. Money capabilities live in the
/// banking plane's own `Permission` — the sets are deliberately disjoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permission {
	/// List/read any user (identities, KYC, sessions, roles).
	UserRead,
	/// Suspend / reinstate a user.
	UserSuspend,
	/// Revoke a user's sessions (bump `token_version`).
	UserRevoke,
	/// Set a user's KYC level.
	KycManage,
	/// Grant/change a user's role.
	RoleGrant,
	/// Read platform config (feature flags, maintenance, announcements, registry).
	PlatformRead,
	/// Mutate platform config.
	PlatformManage,
}

/// The role→permission policy (pure). The RBAC matrix, read as separation of duties:
/// - `Investor` holds nothing (no console).
/// - `Operator` may READ the console (users, platform config) but not mutate.
/// - `Admin` may perform every identity/platform mutation EXCEPT granting roles.
/// - `Owner` holds everything, including [`Permission::RoleGrant`].
pub fn grants(role: Role, permission: Permission) -> bool {
	use Permission::*;
	use Role::*;
	match role {
		Investor => false,
		Operator => matches!(permission, UserRead | PlatformRead),
		Admin => !matches!(permission, RoleGrant),
		Owner => true,
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
		assert!(!Role::Investor.is_operator());
		assert!(Role::Operator.is_operator());
	}

	#[test]
	fn matrix_enforces_separation_of_duties() {
		// Investor: nothing.
		assert!(!grants(Role::Investor, Permission::UserRead));
		// Operator: read only.
		assert!(grants(Role::Operator, Permission::UserRead));
		assert!(grants(Role::Operator, Permission::PlatformRead));
		assert!(!grants(Role::Operator, Permission::UserSuspend));
		assert!(!grants(Role::Operator, Permission::RoleGrant));
		// Admin: every mutation except granting roles.
		assert!(grants(Role::Admin, Permission::UserSuspend));
		assert!(grants(Role::Admin, Permission::KycManage));
		assert!(grants(Role::Admin, Permission::PlatformManage));
		assert!(!grants(Role::Admin, Permission::RoleGrant));
		// Owner: everything.
		assert!(grants(Role::Owner, Permission::RoleGrant));
	}
}
