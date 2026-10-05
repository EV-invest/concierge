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

/// A named set of permissions, `<namespace>:<name>`. Two segments, so an alias can never be
/// spelled like a permission, which has at least three.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
	pub name: &'static str,
	pub members: &'static [&'static str],
}

/// `alias!(pub SA_OPERATOR = "sa:operator", [Leads::Read, Leads::Edit]);`
#[macro_export]
macro_rules! alias {
	($vis:vis $ident:ident = $name:literal, [$($member:expr),* $(,)?]) => {
		$vis const $ident: $crate::Alias = $crate::Alias { name: $name, members: &[$($member.as_str()),*] };
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
}

impl Catalog {
	/// Every permission is concrete and in `namespace`, every alias is `<namespace>:<name>`
	/// and names only permissions of this catalog.
	pub fn check(&self, namespace: &str) -> Result<(), String> {
		let ours = |raw: &str| raw.split(':').next() == Some(namespace);
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
		Ok(())
	}

	/// Every derived permission and alias of `namespace` linked into this binary.
	#[cfg(feature = "catalog")]
	pub fn collect(namespace: &str, version: u64) -> Self {
		let mut permissions = BTreeSet::new();
		let mut aliases = BTreeMap::new();
		let ours = |raw: &str| raw.split(':').next() == Some(namespace);
		for entry in inventory::iter::<Entry> {
			match entry {
				Entry::Permission(p) if ours(p) => assert!(permissions.insert((*p).to_owned()), "`{p}` is derived twice"),
				Entry::Alias(a) if ours(a.name) => assert!(
					aliases.insert(a.name.to_owned(), a.members.iter().map(|m| (*m).to_owned()).collect()).is_none(),
					"alias `{}` is declared twice",
					a.name
				),
				_ => {}
			}
		}
		let catalog = Self { version, permissions, aliases };
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

	fn catalog(permissions: &[&str], aliases: &[(&str, &[&str])]) -> Catalog {
		Catalog {
			version: 1,
			permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
			aliases: aliases.iter().map(|(n, m)| ((*n).to_owned(), m.iter().map(|p| (*p).to_owned()).collect())).collect(),
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
