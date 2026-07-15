//! Integration tests for the platform-config surface's authorization split and the
//! operator-gated config writes.
//!
//! Real Postgres (no mocks, per the project rules), `DATABASE_URL`-gated like the
//! other suites. The read is open to ANY authenticated principal — the config is
//! user-facing (announcement/maintenance banner, flags) — while writes stay behind
//! the shared RBAC gate, and a claims-less request never reaches the repository.
//! Past the gate, the write path validates its input before it reaches the adapter.

use std::sync::Arc;

use concierge::{
	infrastructure::{db, platform::PgPlatform, users::PgUsers},
	platform::Platform,
	ports::{PlatformConfigRepository, UserDirectoryRepository},
};
use domain::users::{AuthSubject, Email};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{GetPlatformConfigRequest, SetAnnouncementRequest, SetFeatureFlagRequest, SetMaintenanceModeRequest, platform_service_server::PlatformService};
use tonic::{Code, Request};
use uuid::Uuid;

async fn setup() -> Option<(Arc<dyn UserDirectoryRepository>, Arc<dyn PlatformConfigRepository>)> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some((Arc::new(PgUsers::new(pool.clone())), Arc::new(PgPlatform::new(pool))))
}

fn access_claims(sub: &str) -> Claims {
	Claims {
		sub: sub.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
	}
}

fn request_with<T>(claims: Claims, inner: T) -> Request<T> {
	let mut req = Request::new(inner);
	req.extensions_mut().insert(claims);
	req
}

#[tokio::test]
async fn any_authenticated_principal_reads_config_but_cannot_write() {
	let Some((users, config)) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	// A freshly provisioned user is an Investor — no console permission at all.
	let subject = AuthSubject::parse(&format!("platform-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("platform@example.com").unwrap(), true).await.unwrap();
	let sub = user.id().to_string();
	let no_admins: Arc<[String]> = Vec::new().into();
	let platform = Platform::new(users, no_admins, config);

	platform
		.get_platform_config(request_with(access_claims(&sub), GetPlatformConfigRequest {}))
		.await
		.expect("any authenticated principal may read the platform config");

	// Defense in depth: with no verified claims injected the read is still rejected.
	let denied = platform.get_platform_config(Request::new(GetPlatformConfigRequest {})).await.unwrap_err();
	assert_eq!(denied.code(), Code::Unauthenticated, "a claims-less request must not read the config");

	// Writes keep the admin gate: the same investor is refused.
	let write = platform
		.set_maintenance_mode(request_with(access_claims(&sub), SetMaintenanceModeRequest { enabled: true }))
		.await
		.unwrap_err();
	assert_eq!(write.code(), Code::PermissionDenied, "config writes stay operator-gated");
}

/// Past the RBAC gate (covered above and by the shared authz-gate suite), an operator's
/// config writes must still validate their input and round-trip through the snapshot.
/// One test so the two writes to the SINGLETON `platform_config` row stay sequential.
#[tokio::test]
async fn operator_config_writes_validate_and_round_trip() {
	let Some((users, config)) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let subject = AuthSubject::parse(&format!("platform-op-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("platform-op@example.com").unwrap(), true).await.unwrap();
	let sub = user.id().to_string();
	// Break-glass allowlist: the caller holds Owner, so these assertions are about the
	// validation past the gate, not the gate itself.
	let admins: Arc<[String]> = vec![sub.clone()].into();
	let platform = Platform::new(users, admins, config);

	let flag = |key: &str, rollout: u32| SetFeatureFlagRequest {
		key: key.to_string(),
		description: "coverage".into(),
		enabled: true,
		rollout,
	};

	for key in ["", "   "] {
		let rejected = platform.set_feature_flag(request_with(access_claims(&sub), flag(key, 50))).await.unwrap_err();
		assert_eq!(rejected.code(), Code::InvalidArgument, "a blank flag key must never be inserted");
	}

	// `rollout` is a u32 on the wire: the `> 100` guard has to reject everything above it,
	// including values that would wrap negative through the `as i32` narrowing and clamp
	// silently to 0 in the adapter. Unique keys — the table is shared dev/CI state, so a
	// rejected write must be proven absent by a key only this run could have written.
	let guard_key = format!("rollout-guard-{}", Uuid::new_v4());
	for rollout in [101, i32::MAX as u32 + 1, u32::MAX] {
		let rejected = platform.set_feature_flag(request_with(access_claims(&sub), flag(&guard_key, rollout))).await.unwrap_err();
		assert_eq!(rejected.code(), Code::InvalidArgument, "rollout {rollout} is out of the 0..=100 range");
	}

	let key = format!("coverage-{}", Uuid::new_v4());
	let written = platform
		.set_feature_flag(request_with(access_claims(&sub), flag(&key, 42)))
		.await
		.expect("an operator may write a valid flag")
		.into_inner();
	let stored = written.flags.iter().find(|f| f.key == key).expect("the new flag is in the returned snapshot");
	assert!(stored.enabled);
	assert_eq!(stored.rollout, 42);
	assert!(!written.flags.iter().any(|f| f.key.trim().is_empty()), "no rejected blank-keyed flag reached the table");
	assert!(!written.flags.iter().any(|f| f.key == guard_key), "no rejected out-of-range rollout reached the table");

	// The upsert re-writes an existing key rather than duplicating it.
	let updated = platform
		.set_feature_flag(request_with(
			access_claims(&sub),
			SetFeatureFlagRequest {
				key: key.clone(),
				description: "coverage".into(),
				enabled: false,
				rollout: 0,
			},
		))
		.await
		.expect("re-writing a flag key upserts")
		.into_inner();
	let matching: Vec<_> = updated.flags.iter().filter(|f| f.key == key).collect();
	assert_eq!(matching.len(), 1, "the flag key is upserted, not duplicated");
	assert!(!matching[0].enabled);
	assert_eq!(matching[0].rollout, 0);

	let title = format!("Scheduled window {}", Uuid::new_v4());
	let announced = platform
		.set_announcement(request_with(
			access_claims(&sub),
			SetAnnouncementRequest {
				title: title.clone(),
				body: "Trading pauses at 02:00 UTC.".into(),
				active: true,
			},
		))
		.await
		.expect("an operator may write the announcement")
		.into_inner();
	assert_eq!(announced.announcement_title, title);
	assert_eq!(announced.announcement_body, "Trading pauses at 02:00 UTC.");
	assert!(announced.announcement_active);
}
