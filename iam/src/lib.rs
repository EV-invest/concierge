//! Permission scopes of the EV identity plane.
//!
//! A permission is `<namespace>:<resource…>:<action>`, declared as an enum variant with
//! `#[derive(Permission)]`; an alias is a named set of them, declared with [`alias!`]. A
//! service asks one question, [`PermissionSet::may`], of the concrete set concierge hands
//! out: wildcards and aliases are expanded there, never on the consumer.

use std::collections::{BTreeMap, BTreeSet};

pub use concierge_iam_derive::Permission;
use serde::{Deserialize, Serialize};

pub trait Permission: Copy {
	fn as_str(self) -> &'static str;
}

/// Longest permission, alias or pattern: long enough for any real name, short enough to stay a key.
pub const MAX_NAME_CHARS: usize = 128;
/// Bounds on one catalog: it is loaded and resolved on every `GetMe`.
pub const MAX_PERMISSIONS: usize = 1024;
pub const MAX_ALIASES: usize = 128;

/// A named set of permissions, `<namespace>:<name>`. Two segments, so an alias can never be
/// spelled like a permission, which has at least three. `delegates` are the aliases its
/// holders may grant and revoke to others.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
	pub name: &'static str,
	pub members: &'static [&'static str],
	pub delegates: &'static [&'static str],
}

/// `alias!(pub SA_OPERATOR = "sa:operator", [Leads::Read, Leads::Edit]);`
/// `alias!(pub SA_ADMIN = "sa:admin", [Sources::Manage], delegates [SA_OPERATOR]);`
#[macro_export]
macro_rules! alias {
	($vis:vis $ident:ident = $name:literal, [$($member:expr),* $(,)?] $(, delegates [$($delegate:expr),* $(,)?])?) => {
		$vis const $ident: $crate::Alias = $crate::Alias { name: $name, members: &[$($member.as_str()),*], delegates: &[$($($delegate.name),*)?] };
		$crate::__submit! { $crate::Entry::Alias($ident) }
	};
}

/// What concierge resolved a caller to hold, in one namespace: concrete permissions only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PermissionSet(BTreeSet<String>);

impl PermissionSet {
	pub fn may(&self, permission: impl Permission) -> bool {
		self.0.contains(permission.as_str())
	}

	pub fn iter(&self) -> impl Iterator<Item = &str> {
		self.0.iter().map(String::as_str)
	}
}

impl<S: Into<String>> FromIterator<S> for PermissionSet {
	fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
		Self(iter.into_iter().map(Into::into).collect())
	}
}

/// A permission, or a set of them by `*` segments: a `*` stands for one segment, a trailing
/// `*` for one or more. The namespace is always literal, so a pattern never spans two.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pattern(String);

impl Pattern {
	pub fn parse(raw: &str) -> Result<Self, String> {
		if raw.chars().count() > MAX_NAME_CHARS {
			return Err(format!("a permission pattern is at most {MAX_NAME_CHARS} characters"));
		}
		let segments: Vec<&str> = raw.split(':').collect();
		let valid = segments.len() >= 2 && is_segment(segments[0]) && segments[1..].iter().all(|s| *s == "*" || is_segment(s));
		match valid {
			true => Ok(Self(raw.to_owned())),
			false => Err(format!("`{}` is not a permission pattern", raw.chars().take(64).collect::<String>())),
		}
	}

	pub fn as_str(&self) -> &str {
		&self.0
	}

	pub fn namespace(&self) -> &str {
		self.0.split(':').next().expect("parse refuses an empty pattern")
	}

	pub fn matches(&self, permission: &str) -> bool {
		self.contains(&Pattern(permission.to_owned()))
	}

	/// Whether everything `other` matches, `self` matches too.
	pub fn contains(&self, other: &Pattern) -> bool {
		let mine: Vec<&str> = self.0.split(':').collect();
		let theirs: Vec<&str> = other.0.split(':').collect();
		for (i, seg) in mine.iter().enumerate() {
			let last = i + 1 == mine.len();
			if last && *seg == "*" {
				return theirs.len() > i;
			}
			let Some(their) = theirs.get(i) else { return false };
			if i + 1 == theirs.len() && *their == "*" && !last {
				return false;
			}
			if *seg != "*" && seg != their {
				return false;
			}
		}
		mine.len() == theirs.len()
	}
}

/// Everything one namespace defines, as a client publishes it to concierge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Catalog {
	/// Monotonic per publisher: concierge refuses one older than what it holds.
	pub version: u64,
	pub permissions: BTreeSet<String>,
	pub aliases: BTreeMap<String, BTreeSet<String>>,
	/// Alias → the aliases its holders may grant and revoke. Only aliases that delegate.
	pub delegations: BTreeMap<String, BTreeSet<String>>,
}

impl Catalog {
	/// Every permission is concrete and in `namespace`, every alias is `<namespace>:<name>`
	/// and names only permissions of this catalog, everything is within the size bounds,
	/// and a delegated alias delegates nothing itself: a holder can never mint a peer, nor
	/// someone who could mint them.
	pub fn check(&self, namespace: &str) -> Result<(), String> {
		if self.permissions.len() > MAX_PERMISSIONS || self.aliases.len() > MAX_ALIASES {
			return Err(format!("a catalog holds at most {MAX_PERMISSIONS} permissions and {MAX_ALIASES} aliases"));
		}
		let ours = |raw: &str| raw.chars().count() <= MAX_NAME_CHARS && raw.split(':').next() == Some(namespace);
		for p in &self.permissions {
			let segments: Vec<&str> = p.split(':').collect();
			if segments.len() < 3 || !segments.iter().all(|s| is_segment(s)) || !ours(p) {
				return Err(format!("`{p}` is not a permission of `{namespace}`"));
			}
		}
		for (name, members) in &self.aliases {
			let segments: Vec<&str> = name.split(':').collect();
			if segments.len() != 2 || !segments.iter().all(|s| is_segment(s)) || !ours(name) {
				return Err(format!("`{name}` is not an alias name of `{namespace}`"));
			}
			if let Some(stray) = members.iter().find(|m| !self.permissions.contains(*m)) {
				return Err(format!("alias `{name}` names `{stray}`, which this catalog does not define"));
			}
		}
		for (name, delegates) in &self.delegations {
			if !self.aliases.contains_key(name) || delegates.is_empty() {
				return Err(format!("`{name}` delegates, but is no alias of this catalog or delegates nothing"));
			}
			if let Some(stray) = delegates.iter().find(|d| !self.aliases.contains_key(*d) || self.delegations.contains_key(*d)) {
				return Err(format!("alias `{name}` delegates `{stray}`, which is no alias of this catalog or delegates itself"));
			}
		}
		Ok(())
	}

	/// Every derived permission and alias of `namespace` linked into this binary.
	#[cfg(feature = "catalog")]
	pub fn collect(namespace: &str, version: u64) -> Self {
		let mut permissions = BTreeSet::new();
		let mut aliases = BTreeMap::new();
		let mut delegations = BTreeMap::new();
		let ours = |raw: &str| raw.split(':').next() == Some(namespace);
		for entry in inventory::iter::<Entry> {
			match entry {
				Entry::Permission(p) if ours(p) => assert!(permissions.insert((*p).to_owned()), "`{p}` is derived twice"),
				Entry::Alias(a) if ours(a.name) => {
					assert!(
						aliases.insert(a.name.to_owned(), a.members.iter().map(|m| (*m).to_owned()).collect()).is_none(),
						"alias `{}` is declared twice",
						a.name
					);
					if !a.delegates.is_empty() {
						delegations.insert(a.name.to_owned(), a.delegates.iter().map(|d| (*d).to_owned()).collect());
					}
				}
				_ => {}
			}
		}
		let catalog = Self {
			version,
			permissions,
			aliases,
			delegations,
		};
		catalog.check(namespace).unwrap_or_else(|e| panic!("{e}"));
		catalog
	}

	/// `PERMISSIONS` / `Permission` and `ALIASES`, for a frontend that asks `may` by name.
	#[cfg(feature = "ts")]
	pub fn ts(&self) -> [ev::ts_gen::Ts; 2] {
		use ev::ts_gen::Ts;
		[
			Ts::Union {
				name: "PERMISSIONS",
				ty: "Permission",
				items: self.permissions.iter().map(|p| &*p.clone().leak()).collect(), // Ts::Union takes &'static str; one-shot generator, never call in a loop
			},
			Ts::Value {
				name: "ALIASES",
				value: serde_json::to_value(&self.aliases).expect("a map of strings serializes"),
			},
		]
	}
}

#[doc(hidden)]
pub enum Entry {
	Permission(&'static str),
	Alias(Alias),
}

#[cfg(feature = "catalog")]
inventory::collect!(Entry);

#[doc(hidden)]
#[cfg(feature = "catalog")]
pub use inventory;

#[doc(hidden)]
#[cfg(feature = "catalog")]
#[macro_export]
macro_rules! __submit {
	($entry:expr) => {
		$crate::inventory::submit! { $entry }
	};
}

#[doc(hidden)]
#[cfg(not(feature = "catalog"))]
#[macro_export]
macro_rules! __submit {
	($entry:expr) => {};
}

fn is_segment(s: &str) -> bool {
	!s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
	use super::*;

	fn contains(outer: &str, inner: &str) -> bool {
		Pattern::parse(outer).unwrap().contains(&Pattern::parse(inner).unwrap())
	}

	#[test]
	fn pattern_containment() {
		for (outer, inner, expected) in [
			("sa:*", "sa:work:leads:read", true),
			("sa:*", "sa:work:*", true),
			("sa:*", "sa:*", true),
			("sa:work:*", "sa:*", false),
			("sa:work:*", "sa:work:leads:read", true),
			("sa:work:*", "sa:analysis:experiments:read", false),
			("sa:*:leads:read", "sa:work:leads:read", true),
			("sa:*:leads:read", "sa:work:x:leads:read", false),
			("sa:*:leads:read", "sa:*:leads:read", true),
			("sa:work:leads:read", "sa:*:leads:read", false),
			("sa:work:leads:*", "sa:work:leads:read", true),
			("sa:work:leads:*", "sa:work:leads", false),
			("sa:work:leads:read", "sa:work:leads:read", true),
			("sa:work:leads:read", "sa:work:leads:edit", false),
			("sa:work:leads", "sa:work:leads:read", false),
			("bank:*", "sa:work:leads:read", false),
			("sa:*:read", "sa:*", false),
		] {
			assert_eq!(contains(outer, inner), expected, "{outer} ⊇ {inner}");
		}
	}

	#[test]
	fn pattern_namespace_is_literal() {
		for bad in ["*", "*:x", "sa", "", "sa::x", "Sa:x", "sa:x y", "sa:x*"] {
			assert!(Pattern::parse(bad).is_err(), "{bad:?}");
		}
	}

	fn named(pairs: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
		pairs.iter().map(|(n, m)| ((*n).to_owned(), m.iter().map(|p| (*p).to_owned()).collect())).collect()
	}

	fn catalog(permissions: &[&str], aliases: &[(&str, &[&str])]) -> Catalog {
		delegating(permissions, aliases, &[])
	}

	fn delegating(permissions: &[&str], aliases: &[(&str, &[&str])], delegations: &[(&str, &[&str])]) -> Catalog {
		Catalog {
			version: 1,
			permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
			aliases: named(aliases),
			delegations: named(delegations),
		}
	}

	#[test]
	fn catalog_is_bounded() {
		let many: Vec<String> = (0..=MAX_PERMISSIONS).map(|i| format!("sa:p:x{i}")).collect();
		assert!(catalog(&many.iter().map(String::as_str).collect::<Vec<_>>(), &[]).check("sa").is_err());
		let long = format!("sa:p:{}", "a".repeat(MAX_NAME_CHARS));
		assert!(catalog(&[&long], &[]).check("sa").is_err());
		assert!(Pattern::parse(&long).is_err());
	}

	#[test]
	fn a_delegate_cannot_delegate() {
		let p = &["sa:work:leads:read"][..];
		let aliases: &[(&str, &[&str])] = &[("sa:admin", p), ("sa:operator", p), ("sa:lead", p)];
		assert!(delegating(p, aliases, &[("sa:admin", &["sa:operator"]), ("sa:lead", &["sa:operator"])]).check("sa").is_ok());
		for bad in [
			delegating(p, aliases, &[("sa:admin", &["sa:admin"])]),
			delegating(p, aliases, &[("sa:admin", &["sa:lead"]), ("sa:lead", &["sa:operator"])]),
			delegating(p, aliases, &[("sa:admin", &["sa:gone"])]),
			delegating(p, aliases, &[("sa:gone", &["sa:operator"])]),
			delegating(p, aliases, &[("sa:admin", &[])]),
		] {
			assert!(bad.check("sa").is_err(), "{bad:?}");
		}
	}

	#[test]
	fn catalog_stays_in_its_namespace() {
		assert!(catalog(&["sa:work:leads:read"], &[("sa:operator", &["sa:work:leads:read"])]).check("sa").is_ok());
		for bad in [
			catalog(&["bank:treasury:read"], &[]),
			catalog(&["sa:leads"], &[]),
			catalog(&["sa:work:*"], &[]),
			catalog(&["sa:work:leads:read"], &[("sa:operator", &["bank:treasury:read"])]),
			catalog(&["sa:work:leads:read"], &[("bank:admin", &["sa:work:leads:read"])]),
			catalog(&["sa:work:leads:read"], &[("sa:ops:x", &["sa:work:leads:read"])]),
		] {
			assert!(bad.check("sa").is_err(), "{bad:?}");
		}
	}
}
