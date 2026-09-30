//! `clients` bounded context — the relying parties this plane signs users into.
//!
//! A relying party is a first-party application on ANOTHER origin (the Service-Arb panel
//! on `sa.evinvest.ltd`) that runs the authorization-code flow against this plane instead
//! of sharing the `evinvest.ltd` cookies. What it may receive is decided here, per
//! client, by its [`AccessPolicy`]: who a code may be issued to at all. It is not an
//! allocation's property on the money plane, because who may SEE a service is not a
//! money question.
//!
//! Pure and wasm-safe, like the rest of this crate.

use std::fmt;

use crate::{authz::Role, error::DomainError, scopes::Scope};

/// Who may be signed into a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessPolicy {
	/// Every active user.
	Public,
	/// Holders of an active grant on the scope — any scope role, since both `operator`
	/// and `admin` work the service — plus the global `admin`/`owner`, who may grant
	/// themselves that scope anyway, so refusing them would be ceremony.
	Scope(Scope),
}

impl AccessPolicy {
	const SCOPE_PREFIX: &'static str = "scope:";

	/// Parse the stored form: `public` or `scope:<scope>`. Exact, like [`Scope::parse`]:
	/// a policy is a key, and two spellings of one must not disagree about who gets in.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		if raw == "public" {
			return Ok(Self::Public);
		}
		match raw.strip_prefix(Self::SCOPE_PREFIX) {
			Some(scope) => Ok(Self::Scope(Scope::parse(scope)?)),
			None => Err(DomainError::Validation("access policy must be `public` or `scope:<scope>`".into())),
		}
	}

	/// Whether a user holding the global `role` and the active scoped grants `scopes`
	/// passes. Account status and revocation are the caller's to check first: a policy
	/// says who a client is FOR, not whether an account is usable.
	pub fn admits(&self, role: Role, scopes: &[Scope]) -> bool {
		match self {
			Self::Public => true,
			Self::Scope(required) => role >= Role::Admin || scopes.contains(required),
		}
	}
}

impl fmt::Display for AccessPolicy {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Public => f.write_str("public"),
			Self::Scope(scope) => write!(f, "{}{scope}", Self::SCOPE_PREFIX),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn service_arb() -> Scope {
		Scope::parse("allocation:service_arb").unwrap()
	}

	#[test]
	fn policy_round_trips_its_stored_form() {
		for raw in ["public", "scope:allocation:service_arb"] {
			assert_eq!(AccessPolicy::parse(raw).unwrap().to_string(), raw);
		}
		for bad in ["", "Public", "scope:", "scope:Allocation:x", "allocation:service_arb", " public"] {
			assert!(AccessPolicy::parse(bad).is_err(), "{bad:?} must not parse");
		}
	}

	#[test]
	fn scope_policy_admits_grant_holders_and_global_admins_only() {
		let policy = AccessPolicy::Scope(service_arb());
		let other = Scope::parse("allocation:real_estate").unwrap();

		assert!(policy.admits(Role::Investor, &[service_arb()]));
		assert!(policy.admits(Role::Admin, &[]));
		assert!(policy.admits(Role::Owner, &[]));

		assert!(!policy.admits(Role::Investor, &[]));
		assert!(!policy.admits(Role::Investor, std::slice::from_ref(&other)));
		// A global operator runs the console, not every vertical's panel.
		assert!(!policy.admits(Role::Operator, &[other]));
	}

	#[test]
	fn public_policy_admits_everyone() {
		assert!(AccessPolicy::Public.admits(Role::Investor, &[]));
	}
}
