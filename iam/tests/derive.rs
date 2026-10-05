use concierge_iam::{Permission, PermissionSet, alias};

#[derive(Clone, Copy, Permission)]
#[permission("sa:work:leads")]
enum Leads {
	Read,
	Edit,
}

#[derive(Clone, Copy, Permission)]
#[permission("sa:admin:sources")]
enum Sources {
	Manage,
}

alias!(SA_OPERATOR = "sa:operator", [Leads::Read, Leads::Edit]);

#[test]
fn derived_names_and_may() {
	assert_eq!(Leads::Edit.as_str(), "sa:work:leads:edit");
	assert_eq!(SA_OPERATOR.members, ["sa:work:leads:read", "sa:work:leads:edit"]);
	let held: PermissionSet = SA_OPERATOR.members.iter().copied().collect();
	assert!(held.may(Leads::Read));
	assert!(!held.may(Sources::Manage));
}

#[cfg(feature = "catalog")]
#[test]
fn catalog_collects_the_namespace() {
	let catalog = concierge_iam::Catalog::collect("sa", 7);
	assert_eq!(
		serde_json::to_value(&catalog).unwrap(),
		serde_json::json!({
			"version": 7,
			"permissions": ["sa:admin:sources:manage", "sa:work:leads:edit", "sa:work:leads:read"],
			"aliases": { "sa:operator": ["sa:work:leads:edit", "sa:work:leads:read"] },
		})
	);
	assert!(concierge_iam::Catalog::collect("bank", 1).permissions.is_empty());
}
