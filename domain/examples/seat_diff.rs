//! One-off check for the move from `grants(role, permission)` to seat aliases: the old
//! matrices of both planes, verbatim, against `Role::may`, for every (seat, permission).
//! Prints each difference and exits non-zero if there is one.
//!
//! `cargo run -p domain --example seat_diff`

use domain::authz::{Iam, Kyc, Platform, Role, Roles, Users, bank};

#[derive(Clone, Copy, Debug)]
enum Old {
	UserRead,
	UserSuspend,
	UserRevoke,
	KycManage,
	RoleGrant,
	PlatformRead,
	PlatformManage,
	ScopeManage,
}

fn old_concierge(role: Role, permission: Old) -> bool {
	use Old::*;
	match role {
		Role::Investor => false,
		Role::Operator => matches!(permission, UserRead | PlatformRead),
		Role::Admin => !matches!(permission, RoleGrant),
		Role::Owner => true,
	}
}

fn old_bank(role: Role, permission: &str) -> bool {
	match role {
		Role::Investor => false,
		Role::Operator => matches!(permission, "TreasuryRead" | "UserBalanceRead"),
		Role::Admin | Role::Owner => true,
	}
}

fn main() {
	let concierge: [(Old, &str); 8] = [
		(Old::UserRead, Users::Read.as_str()),
		(Old::UserSuspend, Users::Suspend.as_str()),
		(Old::UserRevoke, Users::Revoke.as_str()),
		(Old::KycManage, Kyc::Manage.as_str()),
		(Old::RoleGrant, Roles::Grant.as_str()),
		(Old::PlatformRead, Platform::Read.as_str()),
		(Old::PlatformManage, Platform::Manage.as_str()),
		(Old::ScopeManage, Iam::Grant.as_str()),
	];
	use bank::{Allocation, Capital, Consilium, DepositAddress, Operations, Outbox, Payment, Redemption, Treasury, UserBalance, Valuation, Withdrawal};
	let money: [(&str, &str); 18] = [
		("TreasuryRead", Treasury::Read.as_str()),
		("UserBalanceRead", UserBalance::Read.as_str()),
		("ValuationPost", Valuation::Post.as_str()),
		("AllocationManage", Allocation::Manage.as_str()),
		("RedemptionSettle", Redemption::Settle.as_str()),
		("RedemptionFail", Redemption::Fail.as_str()),
		("WithdrawalDispatch", Withdrawal::Dispatch.as_str()),
		("WithdrawalSettle", Withdrawal::Settle.as_str()),
		("WithdrawalFail", Withdrawal::Fail.as_str()),
		("CapitalManage", Capital::Manage.as_str()),
		("ConsiliumManage", Consilium::Manage.as_str()),
		("PaymentOpen", Payment::Open.as_str()),
		("OperationsManage", Operations::Manage.as_str()),
		("OutboxManage", Outbox::Manage.as_str()),
		("UserRevoke", bank::Users::Revoke.as_str()),
		("UserSuspend", bank::Users::Suspend.as_str()),
		("DepositAddressRotate", DepositAddress::Rotate.as_str()),
		("DepositAddressMigrate", DepositAddress::Migrate.as_str()),
	];
	let mut differences = 0;
	let mut checked = 0;
	for role in [Role::Investor, Role::Operator, Role::Admin, Role::Owner] {
		let new = |p: &str| role.permissions().contains(&p);
		for (old, p) in concierge {
			checked += 1;
			if old_concierge(role, old) != new(p) {
				differences += 1;
				println!("{role:?} {old:?} ({p}): old {} new {}", old_concierge(role, old), new(p));
			}
		}
		for (old, p) in money {
			checked += 1;
			if old_bank(role, old) != new(p) {
				differences += 1;
				println!("{role:?} bank {old} ({p}): old {} new {}", old_bank(role, old), new(p));
			}
		}
		let extra: Vec<_> = role
			.permissions()
			.iter()
			.filter(|p| !concierge.iter().any(|(_, c)| c == *p) && !money.iter().any(|(_, m)| m == *p))
			.collect();
		if !extra.is_empty() {
			differences += 1;
			println!("{role:?} holds permissions no old matrix named: {extra:?}");
		}
	}
	println!("{checked} (seat, permission) pairs, {differences} differences");
	std::process::exit(i32::from(differences > 0));
}
