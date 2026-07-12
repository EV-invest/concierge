//! Integration tests for the shared RBAC gate (`authz::require_permission`).
//!
//! These hit a **real** Postgres (no mocks, per the project rules); they run when
//! `DATABASE_URL` is set and skip otherwise. They prove the gate resolves the caller's
//! authority from the PERSISTED record and fails closed for a non-privileged, suspended,
//! or token-revoked caller — the enforcement the choke-point test cannot cover (it only
//! exercises the unconfigured fail-closed verifier, never the wired denial path) — and
//! that the `ADMIN_SUBJECTS` break-glass elevation is SURFACED wherever the plane
//! reports a role (provisioner summaries → the issued session, `GetMe`/`GetUser`,
//! `ListUsers`) while the persisted `users.role` stays untouched.

use std::sync::Arc;

use concierge::{
	authz::{effective_role, require_permission},
	directory::{self, Directory},
	infrastructure::{db, users::PgUsers},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::{Permission, Role},
	users::{AuthSubject, Email},
};
use evconcierge_auth::{Claims, TokenType, provisioner_channel};
use evconcierge_contracts::concierge::v1::{DisableUserRequest, GetMeRequest, GetUserRequest, ListUsersRequest, user_directory_server::UserDirectory};
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
	request_with(claims, ())
}

fn request_with<T>(claims: Claims, inner: T) -> Request<T> {
	let mut req = Request::new(inner);
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

#[test]
fn effective_role_elevates_only_allowlisted_subjects() {
	let sub = Uuid::new_v4().to_string();
	let admins = vec![sub.clone()];
	for persisted in [Role::Investor, Role::Operator, Role::Admin, Role::Owner] {
		assert_eq!(
			effective_role(persisted, &sub, &admins),
			Role::Owner,
			"an allowlisted subject holds Owner regardless of the persisted role"
		);
		assert_eq!(
			effective_role(persisted, "someone-else", &admins),
			persisted,
			"a non-allowlisted subject keeps the persisted role"
		);
		assert_eq!(effective_role(persisted, &sub, &[]), persisted, "an empty allowlist elevates nobody");
	}
}

#[tokio::test]
async fn provisioner_summaries_surface_the_effective_role() {
	let Some(users) = setup().await else {
		return;
	};
	let users: Arc<dyn UserDirectoryRepository> = Arc::new(users);
	// Pre-provision so the concierge id is known, then allowlist it and drive the same
	// channel the auth task uses for Exchange (Provision) and Refresh (Lookup).
	let subject = unique_subject();
	let user = users.provision(subject.clone(), Email::parse("bootop@example.com").unwrap(), true).await.unwrap();
	let admins: Arc<[String]> = vec![user.id().to_string()].into();
	let (provisioner, rx) = provisioner_channel();
	tokio::spawn(directory::run_provisioner(rx, users.clone(), admins));

	let provisioned = provisioner.provision(subject.as_str().to_owned(), "bootop@example.com".into(), true).await.unwrap();
	assert_eq!(provisioned.role, "owner", "an Exchange summary carries the effective role");
	let looked_up = provisioner.lookup(user.id().to_string()).await.unwrap();
	assert_eq!(looked_up.role, "owner", "a Refresh summary carries the effective role");

	// Break-glass is surface-only: the persisted role is never written by elevation.
	let persisted = users.find_by_id(user.id()).await.unwrap().expect("user exists");
	assert_eq!(persisted.role(), Role::Investor, "users.role is untouched by elevation");

	// Non-allowlisted control: summaries keep the persisted role.
	let stranger = provisioner.provision(unique_subject().as_str().to_owned(), "stranger@example.com".into(), true).await.unwrap();
	assert_eq!(stranger.role, "investor", "a non-allowlisted summary keeps the persisted role");
}

#[tokio::test]
async fn malformed_admin_target_user_id_is_invalid_argument() {
	let Some(users) = setup().await else {
		return;
	};
	// The caller passes the gate (record-less break-glass Owner); a malformed TARGET field
	// is bad input (code 3), never UNAUTHENTICATED — a code 16 here reads as an expired
	// session to the console.
	let sub = Uuid::new_v4().to_string();
	let directory = Directory::new(Arc::new(users), vec![sub.clone()].into());

	let bad_read = directory
		.get_user(request_with(access_claims(&sub, 0), GetUserRequest { user_id: "123-not-a-uuid".into() }))
		.await
		.unwrap_err();
	assert_eq!(bad_read.code(), Code::InvalidArgument, "a malformed target user_id is bad input, not an auth failure");

	let bad_write = directory
		.disable_user(request_with(access_claims(&sub, 0), DisableUserRequest { user_id: "123-not-a-uuid".into() }))
		.await
		.unwrap_err();
	assert_eq!(bad_write.code(), Code::InvalidArgument, "mutations agree with reads on the target-field status code");
}

#[tokio::test]
async fn read_surfaces_report_the_effective_role() {
	let Some(users) = setup().await else {
		return;
	};
	let users: Arc<dyn UserDirectoryRepository> = Arc::new(users);
	let elevated = users.provision(unique_subject(), Email::parse("surfaced@example.com").unwrap(), true).await.unwrap();
	let plain = users.provision(unique_subject(), Email::parse("plain@example.com").unwrap(), true).await.unwrap();
	let sub = elevated.id().to_string();
	let directory = Directory::new(users, vec![sub.clone()].into());

	// GetMe: the caller's own profile shows the same authority the gate grants.
	let me = directory.get_me(request_with(access_claims(&sub, 0), GetMeRequest {})).await.unwrap().into_inner();
	assert_eq!(me.role, "owner", "GetMe reports the effective role");

	// GetUser: the admin detail view elevates the allowlisted target only.
	let detail = directory
		.get_user(request_with(access_claims(&sub, 0), GetUserRequest { user_id: sub.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(detail.role, "owner", "GetUser reports the effective role for an allowlisted target");
	let other = directory
		.get_user(request_with(access_claims(&sub, 0), GetUserRequest { user_id: plain.id().to_string() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(other.role, "investor", "GetUser keeps the persisted role for everyone else");

	// ListUsers: the operator console likewise (a full-UUID query isolates one row).
	let listed = directory
		.list_users(request_with(
			access_claims(&sub, 0),
			ListUsersRequest {
				query: sub.clone(),
				..Default::default()
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(listed.users.len(), 1, "the id query matches exactly the allowlisted row");
	assert_eq!(listed.users[0].role, "owner", "ListUsers reports the effective role");
	let listed = directory
		.list_users(request_with(
			access_claims(&sub, 0),
			ListUsersRequest {
				query: plain.id().to_string(),
				..Default::default()
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(listed.users[0].role, "investor", "ListUsers keeps the persisted role for everyone else");
}
