//! `scopes` bounded context — access to ONE resource, granted per user.
//!
//! A [`Role`] is platform-wide: it opens the operator console and every identity
//! mutation it guards. A scoped grant is the opposite shape — a user holds a
//! [`ScopeRole`] over one named resource and nothing beyond it, so a vertical's panel
//! (Service-Arb, REA) can be handed to the people who run it without seating them in
//! the console. Only non-money access lives here: rights over an allocation's money are
//! the banking plane's own grants, and scopes are never mirrored across the bridge.
//!
//! Who may hand a scope out is [`ScopeAuthority`]: a global `admin`/`owner` may grant
//! anything, the `admin` of a scope may grant `operator`/`viewer` inside that scope and
//! never touch an `admin` grant, and everyone else may do nothing. The last clause is the
//! point of the whole matrix — a scope admin who could mint scope admins could hand the
//! scope to anyone and then be removed without the scope ever coming back.
//!
//! Pure and wasm-safe, like the rest of this crate.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
	authz::{Permission, Role, grants},
	error::DomainError,
};

/// The longest service id a scope may name. Bounded so a scope string is a key, not a
/// payload; mirrored by the `scoped_grants_scope_format` CHECK.
pub const MAX_SERVICE_ID_CHARS: usize = 64;

/// The identifier of an allocation's service (`service_arb`, `real_estate`): lowercase
/// ASCII letters, digits and `_`, 1-[`MAX_SERVICE_ID_CHARS`] characters.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServiceId(String);

impl ServiceId {
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		let valid = !raw.is_empty() && raw.len() <= MAX_SERVICE_ID_CHARS && raw.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
		if !valid {
			return Err(DomainError::Validation(format!("service id must be 1-{MAX_SERVICE_ID_CHARS} characters of [a-z0-9_]")));
		}
		Ok(Self(raw.to_owned()))
	}

	pub fn as_str(&self) -> &str {
		&self.0
	}
}

/// What a grant is over. One kind today; a closed enum rather than a free string so a
/// scope nobody reads can never be granted, and so a second kind has to be added here
/// on purpose.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Scope {
	/// `allocation:<service_id>` — a vertical's panel and admin surfaces.
	Allocation(ServiceId),
}

impl Scope {
	const ALLOCATION_PREFIX: &'static str = "allocation:";

	/// Parse the wire/stored form. No trimming and no case folding: a scope is an exact
	/// key, and `Allocation:X` quietly meaning `allocation:x` would let two spellings of
	/// one grant disagree about whether it exists.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw.strip_prefix(Self::ALLOCATION_PREFIX) {
			Some(service) => Ok(Self::Allocation(ServiceId::parse(service)?)),
			None => Err(DomainError::Validation("scope must be of the form allocation:<service_id>".into())),
		}
	}
}

impl fmt::Display for Scope {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Allocation(service) => write!(f, "{}{}", Self::ALLOCATION_PREFIX, service.as_str()),
		}
	}
}

/// The role a user holds inside one scope, least→most privileged. What each one may DO
/// inside the resource is the resource's own policy; this plane only decides who holds
/// which.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRole {
	Viewer,
	Operator,
	Admin,
}

impl ScopeRole {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Viewer => "viewer",
			Self::Operator => "operator",
			Self::Admin => "admin",
		}
	}

	/// An unknown value is refused rather than defaulted, so a bad request or a corrupt
	/// row never quietly grants or drops access.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"viewer" => Ok(Self::Viewer),
			"operator" => Ok(Self::Operator),
			"admin" => Ok(Self::Admin),
			// Echoed back to the caller, so bounded: the field is free input.
			other => Err(DomainError::Validation(format!("unknown scope role: {}", other.chars().take(32).collect::<String>()))),
		}
	}
}

/// How much say a caller has over the grants of ONE scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeAuthority {
	/// A global role holding [`Permission::ScopeManage`]: any scope, any role.
	Global,
	/// The `admin` of this scope: `operator`/`viewer` grants inside it, never an `admin` one.
	ScopeAdmin,
	/// Nothing.
	None,
}

impl ScopeAuthority {
	/// `held` must be the caller's grant on the scope being acted on — a grant on another
	/// scope says nothing about this one.
	pub fn resolve(global: Role, held: Option<ScopeRole>) -> Self {
		if grants(global, Permission::ScopeManage) {
			Self::Global
		} else if held == Some(ScopeRole::Admin) {
			Self::ScopeAdmin
		} else {
			Self::None
		}
	}

	/// Who sees a scope's roster: whoever can change it.
	pub fn may_list(self) -> bool {
		match self {
			Self::Global | Self::ScopeAdmin => true,
			Self::None => false,
		}
	}

	/// Whether the caller may give `target` the role `requested`, given the role they
	/// hold there now (`current`). A scope admin may neither create an admin nor move one:
	/// demoting another admin is as much "touching an admin grant" as minting one.
	pub fn may_grant(self, requested: ScopeRole, current: Option<ScopeRole>) -> bool {
		match self {
			Self::Global => true,
			Self::ScopeAdmin => requested != ScopeRole::Admin && current != Some(ScopeRole::Admin),
			Self::None => false,
		}
	}

	/// Whether the caller may take away a grant of role `current`.
	pub fn may_revoke(self, current: ScopeRole) -> bool {
		match self {
			Self::Global => true,
			Self::ScopeAdmin => current != ScopeRole::Admin,
			Self::None => false,
		}
	}

	/// Whether the caller may name a grant's target by user id. A scope admin may not:
	/// ids of other staff are visible (every grant carries `granted_by`), and granting a
	/// bare id and then reading the scope's roster would turn a scope admin into a
	/// lookup service for anyone's address. They name the person by the email they
	/// already know instead.
	pub fn may_address_by_id(self) -> bool {
		match self {
			Self::Global => true,
			Self::ScopeAdmin | Self::None => false,
		}
	}

	/// Whether the roster shows holders' legal names. A scope's team sees each other's
	/// email and chosen name; the legal name is KYC-grade data and stays with staff.
	pub fn sees_legal_names(self) -> bool {
		match self {
			Self::Global => true,
			Self::ScopeAdmin | Self::None => false,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const ALL_SCOPE_ROLES: [ScopeRole; 3] = [ScopeRole::Viewer, ScopeRole::Operator, ScopeRole::Admin];

	#[test]
	fn scope_admin_cannot_grant_admin() {
		let authority = ScopeAuthority::resolve(Role::Investor, Some(ScopeRole::Admin));
		assert_eq!(authority, ScopeAuthority::ScopeAdmin);
		assert!(!authority.may_grant(ScopeRole::Admin, None), "a scope admin must not mint another scope admin");
		assert!(!authority.may_grant(ScopeRole::Admin, Some(ScopeRole::Operator)), "nor promote an operator to admin");
	}

	#[test]
	fn only_a_global_manager_addresses_by_id_or_reads_legal_names() {
		assert!(ScopeAuthority::Global.may_address_by_id());
		assert!(!ScopeAuthority::ScopeAdmin.may_address_by_id(), "a scope admin addressing by id is a PII oracle");
		assert!(!ScopeAuthority::None.may_address_by_id());
		assert!(ScopeAuthority::Global.sees_legal_names());
		assert!(!ScopeAuthority::ScopeAdmin.sees_legal_names());
		assert!(!ScopeAuthority::None.sees_legal_names());
	}

	#[test]
	fn an_unknown_scope_role_is_echoed_bounded() {
		let Err(DomainError::Validation(message)) = ScopeRole::parse(&"x".repeat(10_000)) else {
			panic!("an unknown role is a validation error");
		};
		assert!(message.len() < 64, "{message}");
	}

	#[test]
	fn scope_admin_manages_operators_and_viewers_only() {
		let authority = ScopeAuthority::ScopeAdmin;
		for requested in [ScopeRole::Viewer, ScopeRole::Operator] {
			assert!(authority.may_grant(requested, None));
			assert!(authority.may_grant(requested, Some(ScopeRole::Viewer)));
			assert!(authority.may_grant(requested, Some(ScopeRole::Operator)));
			assert!(!authority.may_grant(requested, Some(ScopeRole::Admin)), "an admin grant is not a scope admin's to move");
		}
		assert!(authority.may_revoke(ScopeRole::Viewer));
		assert!(authority.may_revoke(ScopeRole::Operator));
		assert!(!authority.may_revoke(ScopeRole::Admin));
		assert!(authority.may_list());
	}

	#[test]
	fn global_admin_and_owner_manage_everything() {
		for role in [Role::Admin, Role::Owner] {
			let authority = ScopeAuthority::resolve(role, None);
			assert_eq!(authority, ScopeAuthority::Global);
			for requested in ALL_SCOPE_ROLES {
				assert!(authority.may_grant(requested, None));
				assert!(authority.may_grant(requested, Some(ScopeRole::Admin)));
				assert!(authority.may_revoke(requested));
			}
			assert!(authority.may_list());
		}
	}

	#[test]
	fn everyone_else_manages_nothing() {
		for global in [Role::Investor, Role::Operator] {
			for held in [None, Some(ScopeRole::Viewer), Some(ScopeRole::Operator)] {
				let authority = ScopeAuthority::resolve(global, held);
				assert_eq!(authority, ScopeAuthority::None, "{global:?} holding {held:?}");
				assert!(!authority.may_list());
				for requested in ALL_SCOPE_ROLES {
					assert!(!authority.may_grant(requested, None));
					assert!(!authority.may_revoke(requested));
				}
			}
		}
	}

	#[test]
	fn global_operator_is_not_a_scope_manager_but_a_scope_admin_grant_still_counts() {
		assert_eq!(ScopeAuthority::resolve(Role::Operator, Some(ScopeRole::Admin)), ScopeAuthority::ScopeAdmin);
	}

	#[test]
	fn scope_parses_and_round_trips() {
		let scope = Scope::parse("allocation:service_arb").unwrap();
		assert_eq!(scope, Scope::Allocation(ServiceId::parse("service_arb").unwrap()));
		assert_eq!(scope.to_string(), "allocation:service_arb");
		let longest = format!("allocation:{}", "a".repeat(MAX_SERVICE_ID_CHARS));
		assert_eq!(Scope::parse(&longest).unwrap().to_string(), longest);
	}

	#[test]
	fn scope_rejects_malformed_input() {
		for raw in [
			"",
			"allocation:",
			"allocation:Service_Arb",
			"allocation:service-arb",
			"allocation:service arb",
			" allocation:service_arb",
			"allocation:service_arb ",
			"Allocation:service_arb",
			"fund:service_arb",
			"service_arb",
			"allocation:ünicode",
			&format!("allocation:{}", "a".repeat(MAX_SERVICE_ID_CHARS + 1)),
		] {
			assert!(matches!(Scope::parse(raw), Err(DomainError::Validation(_))), "{raw:?} must be refused");
		}
	}

	#[test]
	fn scope_role_round_trips_and_rejects_unknown() {
		for role in ALL_SCOPE_ROLES {
			assert_eq!(ScopeRole::parse(role.as_str()).unwrap(), role);
		}
		assert!(ScopeRole::parse("owner").is_err());
		assert!(ScopeRole::parse("Admin").is_err());
	}
}
