//! `iam` bounded context — what a user holds inside a tenant's namespace.
//!
//! A tenant (`sa`) owns one namespace and publishes its [`Catalog`]: the permissions and
//! aliases it defines. A grant names a [`Target`] inside a tenant namespace — an alias, a
//! permission or a `*` pattern — and is stored as named, so redefining an alias reaches
//! every holder. What a holder may do is resolved here against the current catalog;
//! clients only ever see the concrete result.
//!
//! Seats never live in a tenant namespace and are never granted: the namespaces below are
//! not a tenant's to claim, so no grant can reach a seat's permissions. A tenant's own
//! catalog may let the holders of an alias grant others (`Catalog::delegations`); nothing
//! else grants inside it but a seat holding [`Iam::Grant`], and nobody grants to themselves.

use std::collections::BTreeSet;

pub use concierge_iam::Catalog;
use concierge_iam::Pattern;

use crate::{
	authz::{Iam, Role},
	error::DomainError,
};

pub const RESERVED_NAMESPACES: [&str; 4] = ["iam", "concierge", "bank", "seat"];

/// What a grant names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
	/// `<namespace>:<name>`, defined by the tenant's catalog.
	Alias(String),
	/// A permission, or permissions by `*` segments.
	Pattern(Pattern),
}

impl Target {
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		let pattern = Pattern::parse(raw).map_err(DomainError::Validation)?;
		if RESERVED_NAMESPACES.contains(&pattern.namespace()) {
			return Err(DomainError::Validation(format!("`{}:*` is not grantable: only a tenant's namespace is", pattern.namespace())));
		}
		Ok(match raw.split(':').count() == 2 && !raw.contains('*') {
			true => Self::Alias(raw.to_owned()),
			false => Self::Pattern(pattern),
		})
	}

	pub fn as_str(&self) -> &str {
		match self {
			Self::Alias(name) => name,
			Self::Pattern(pattern) => pattern.as_str(),
		}
	}

	pub fn namespace(&self) -> &str {
		self.as_str().split(':').next().expect("parse refuses an empty target")
	}

	/// The permissions of `catalog` this target grants. None: the target is orphaned.
	pub fn grants<'c>(&self, catalog: &'c Catalog) -> BTreeSet<&'c str> {
		match self {
			Self::Alias(name) => catalog.aliases.get(name).into_iter().flatten().map(String::as_str).collect(),
			Self::Pattern(pattern) => catalog.permissions.iter().filter(|p| pattern.matches(p)).map(String::as_str).collect(),
		}
	}
}

/// Everything `seat` and `targets` let a user do inside `catalog`'s namespace. A seat that
/// may grant there holds all of it only in a tenant that says so
/// (`tenants.granting_seats_hold_all`); elsewhere it holds what someone else granted it.
pub fn resolve<'c>(seat: Role, granting_seats_hold_all: bool, targets: &[Target], catalog: &'c Catalog) -> BTreeSet<&'c str> {
	if granting_seats_hold_all && seat.may(Iam::Grant) {
		return catalog.permissions.iter().map(String::as_str).collect();
	}
	targets.iter().flat_map(|t| t.grants(catalog)).collect()
}

/// The aliases a holder of `targets` may grant and revoke in `catalog`'s namespace.
pub fn delegable<'c>(targets: &[Target], catalog: &'c Catalog) -> BTreeSet<&'c str> {
	targets.iter().filter_map(|t| catalog.delegations.get(t.as_str())).flatten().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn catalog() -> Catalog {
		serde_json::from_value(serde_json::json!({
			"version": 1,
			"permissions": ["sa:work:leads:read", "sa:work:leads:edit", "sa:admin:sources:manage"],
			"aliases": {
				"sa:operator": ["sa:work:leads:read", "sa:work:leads:edit"],
				"sa:admin": ["sa:admin:sources:manage"],
			},
			"delegations": { "sa:admin": ["sa:operator"] },
		}))
		.unwrap()
	}

	fn targets(raw: &[&str]) -> Vec<Target> {
		raw.iter().map(|t| Target::parse(t).unwrap()).collect()
	}

	fn check(seat: Role, raw: &[&str], expected: &[&str]) {
		let catalog = catalog();
		assert_eq!(resolve(seat, true, &targets(raw), &catalog), expected.iter().copied().collect(), "{seat:?} {raw:?}");
	}

	#[test]
	fn resolution() {
		check(Role::Investor, &[], &[]);
		check(Role::Investor, &["sa:operator"], &["sa:work:leads:edit", "sa:work:leads:read"]);
		check(Role::Investor, &["sa:work:*"], &["sa:work:leads:edit", "sa:work:leads:read"]);
		check(
			Role::Investor,
			&["sa:admin:sources:manage", "sa:work:leads:read"],
			&["sa:admin:sources:manage", "sa:work:leads:read"],
		);
		check(Role::Investor, &["sa:gone", "sa:work:gone:*"], &[]);
		check(Role::Operator, &[], &[]);
		check(Role::Admin, &[], &["sa:admin:sources:manage", "sa:work:leads:edit", "sa:work:leads:read"]);
		assert!(resolve(Role::Admin, false, &[], &catalog()).is_empty(), "a tenant that does not trust seats");
	}

	#[test]
	fn delegation() {
		let catalog = catalog();
		assert_eq!(delegable(&targets(&["sa:admin"]), &catalog), ["sa:operator"].into());
		assert!(
			delegable(&targets(&["sa:operator", "sa:admin:*", "sa:*"]), &catalog).is_empty(),
			"only the alias itself delegates"
		);
	}

	#[test]
	fn seats_and_their_namespaces_are_not_grantable() {
		for raw in [
			"iam:tenants:grant",
			"iam:*",
			"concierge:*",
			"concierge:role:grant",
			"bank:*",
			"bank:treasury:read",
			"seat:owner",
			"owner",
			"admin",
			"*",
			"",
		] {
			assert!(Target::parse(raw).is_err(), "{raw:?}");
		}
		assert!(Target::parse(&format!("sa:{}", "a".repeat(concierge_iam::MAX_NAME_CHARS))).is_err());
	}
}
