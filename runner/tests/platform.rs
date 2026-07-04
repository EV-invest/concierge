//! Integration tests for the platform-config surface's authorization split.
//!
//! Real Postgres (no mocks, per the project rules), `DATABASE_URL`-gated like the
//! other suites. The read is open to ANY authenticated principal — the config is
//! user-facing (announcement/maintenance banner, flags) — while writes stay behind
//! the shared RBAC gate, and a claims-less request never reaches the repository.

use std::sync::Arc;

use concierge::{
	infrastructure::{db, platform::PgPlatform, users::PgUsers},
	platform::Platform,
	ports::{PlatformConfigRepository, UserDirectoryRepository},
};
use domain::users::{AuthSubject, Email};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{GetPlatformConfigRequest, SetMaintenanceModeRequest, platform_service_server::PlatformService};
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
