//! Integration tests for the shared RBAC gate (`authz::require_permission`).
//!
//! These hit a **real** Postgres (no mocks, per the project rules); they run when
//! `DATABASE_URL` is set and skip otherwise. They prove the gate resolves the caller's
//! authority from the PERSISTED record and fails closed for a non-privileged, suspended,
//! or token-revoked caller — the enforcement the choke-point test cannot cover (it only
//! exercises the unconfigured fail-closed verifier, never the wired denial path).

use concierge::{
	authz::require_permission,
	infrastructure::{db, users::PgUsers},
};
use domain::{
	authz::{Permission, Role},
	users::{AuthSubject, Email},
};
use evconcierge_auth::{Claims, TokenType};
use tonic::{Code, Request};
use uuid::Uuid;

async fn setup() -> Option<PgUsers> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some(PgUsers::new(pool))
}

fn unique_subject() -> AuthSubject {
	AuthSubject::parse(&format!("authz-{}", Uuid::new_v4())).unwrap()
}

fn access_claims(sub: &str, token_version: u64) -> Claims {
	Claims {
		sub: sub.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version,
	}
}

fn request_as(claims: Claims) -> Request<()> {
	let mut req = Request::new(());
	req.extensions_mut().insert(claims);
	req
}

#[tokio::test]
async fn gate_enforces_role_status_and_revocation() {
	let Some(users) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let no_admins: Vec<String> = Vec::new();

	// A freshly provisioned user is an Investor — holds nothing.
	let user = users.provision(unique_subject(), Email::parse("authz@example.com").unwrap(), true).await.unwrap();
	let sub = user.id().to_string();
	let denied = require_permission(&users, &no_admins, &request_as(access_claims(&sub, 0)), Permission::UserRead)
		.await
		.unwrap_err();
	assert_eq!(denied.code(), Code::PermissionDenied, "an investor must not read the operator console");

	// Grant Owner → RoleGrant is now allowed.
	users.set_role(user.id(), Role::Owner).await.unwrap();
	require_permission(&users, &no_admins, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.expect("owner may grant roles");

	// Suspend the owner → the gate denies at once, even with a still-valid (unexpired) token.
	users.disable_user(user.id()).await.unwrap();
	let suspended = require_permission(&users, &no_admins, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(suspended.code(), Code::PermissionDenied, "a suspended operator loses the console immediately");

	// Reinstate, then revoke tokens (bumps token_version) → a token minted under the OLD
	// version is rejected, while a token at the new floor is accepted.
	users.enable_user(user.id()).await.unwrap();
	let revoked = users.revoke_tokens(user.id()).await.unwrap();
	assert!(revoked.token_version() >= 1, "revoke_tokens bumps the floor");
	let stale = require_permission(&users, &no_admins, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(stale.code(), Code::Unauthenticated, "a token below the revocation floor is rejected");
	require_permission(&users, &no_admins, &request_as(access_claims(&sub, revoked.token_version())), Permission::RoleGrant)
		.await
		.expect("a token at the current version is accepted");

	// A service token is refused regardless of subject (self-service acts as a user only).
	let mut svc = access_claims(&sub, revoked.token_version());
	svc.typ = TokenType::Service;
	let svc_denied = require_permission(&users, &no_admins, &request_as(svc), Permission::UserRead).await.unwrap_err();
	assert_eq!(svc_denied.code(), Code::PermissionDenied, "a service token is not a user principal");
}

#[tokio::test]
async fn allowlisted_operator_is_still_gated_by_status_and_revocation() {
	let Some(users) = setup().await else {
		return;
	};
	// The allowlist grants a role, never an exemption: once a record exists, DisableUser
	// and RevokeTokens must bite the break-glass principals too.
	let user = users.provision(unique_subject(), Email::parse("breakglass@example.com").unwrap(), true).await.unwrap();
	let sub = user.id().to_string();
	let admins = vec![sub.clone()];

	require_permission(&users, &admins, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.expect("an active allowlisted operator holds Owner");

	users.disable_user(user.id()).await.unwrap();
	let suspended = require_permission(&users, &admins, &request_as(access_claims(&sub, 0)), Permission::RoleGrant).await.unwrap_err();
	assert_eq!(suspended.code(), Code::PermissionDenied, "a disabled allowlisted operator is denied");

	users.enable_user(user.id()).await.unwrap();
	let revoked = users.revoke_tokens(user.id()).await.unwrap();
	let stale = require_permission(&users, &admins, &request_as(access_claims(&sub, revoked.token_version() - 1)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(stale.code(), Code::Unauthenticated, "an allowlisted token below the revocation floor is rejected");

	require_permission(&users, &admins, &request_as(access_claims(&sub, revoked.token_version())), Permission::RoleGrant)
		.await
		.expect("an allowlisted token at the current floor is Owner again");
}

#[tokio::test]
async fn break_glass_allowlist_bootstraps_as_owner() {
	let Some(users) = setup().await else {
		return;
	};
	// An allowlisted subject holds Owner with no persisted role (the bootstrap path), so the
	// first operator can grant roles before any role exists.
	let boot_sub = Uuid::new_v4().to_string();
	let admins = vec![boot_sub.clone()];
	require_permission(&users, &admins, &request_as(access_claims(&boot_sub, 0)), Permission::RoleGrant)
		.await
		.expect("an allowlisted subject bootstraps as Owner");
}
