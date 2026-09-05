//! Integration tests for the shared RBAC gate (`authz::require_permission`) and for the
//! emergency access that retires itself.
//!
//! These hit a **real** Postgres (no mocks, per the project rules); they run when
//! `DATABASE_URL` is set and skip otherwise. They prove the gate resolves the caller's
//! authority from the PERSISTED record and fails closed for a non-privileged, suspended,
//! or token-revoked caller — the enforcement the choke-point test cannot cover (it only
//! exercises the unconfigured fail-closed verifier, never the wired denial path).
//!
//! They also pin the `OWNER_SUBJECTS` rule end to end: it elevates ONLY while the
//! persisted owner registry is empty, the first owner closes it for good, and every
//! surface that reports an elevated role reports `role_is_break_glass` beside it. The
//! persisted `users.role` is never written by any of it.
//!
//! ⚠️ LIKE THE CONSILIUM SUITE, THIS ONE OWNS THE OWNER ROSTER — emergency access is
//! decided against `users.role = 'owner'` globally, so it cannot be scoped to its own
//! fixtures. Each test takes the SAME session advisory lock `governance.rs` uses and
//! clears the roster first, so the two suites serialize instead of racing.

use std::sync::Arc;

mod common;

use concierge::{
	authz::{BreakGlass, require_permission},
	directory::{self, Directory},
	infrastructure::{db, users::PgUsers},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::{Permission, Role},
	users::{AuthSubject, Email, UserId},
};
use evconcierge_auth::{Claims, TokenType, provisioner_channel};
use evconcierge_contracts::concierge::v1::{DisableUserRequest, GetMeRequest, GetUserRequest, ListUsersRequest, user_directory_server::UserDirectory};
use sqlx::{Connection, PgConnection, PgPool};
use tonic::{Code, Request};
use uuid::Uuid;

/// The key `governance.rs` serializes on — deliberately the same one, because both
/// suites decide against the global owner roster.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"

struct Fixture {
	users: Arc<PgUsers>,
	pool: PgPool,
	/// Holding this connection open holds the advisory lock; dropping it releases.
	_roster_lock: PgConnection,
}

async fn setup() -> Option<Fixture> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	// This suite clears the owner registry — a state no API can restore. Never on a
	// database nobody has declared disposable.
	common::assert_disposable_database();
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let mut roster_lock = PgConnection::connect(&url).await.expect("a dedicated connection for the roster lock");
	sqlx::query("SELECT pg_advisory_lock($1)")
		.bind(ROSTER_LOCK)
		.execute(&mut roster_lock)
		.await
		.expect("take the roster lock");
	clear_roster(&pool).await;

	Some(Fixture {
		users: Arc::new(PgUsers::new(pool.clone())),
		pool,
		_roster_lock: roster_lock,
	})
}

/// An empty registry is the precondition for every emergency-access assertion, and no
/// API can produce one — the owner floor exists precisely to stop that.
async fn clear_roster(pool: &PgPool) {
	sqlx::query("UPDATE users SET role = 'investor' WHERE role = 'owner'")
		.execute(pool)
		.await
		.expect("clear the roster");
}

impl Fixture {
	fn port(&self) -> Arc<dyn UserDirectoryRepository> {
		self.users.clone()
	}

	/// Mint an owner straight through the repository: `SetRole` refuses to, and a fixture
	/// must not be able to do what the RPC cannot.
	async fn seat_owner(&self) {
		let id = self.provision("roster").await;
		self.users.set_role(id, Role::Owner).await.unwrap();
	}

	async fn provision(&self, tag: &str) -> UserId {
		let subject = AuthSubject::parse(&format!("authz-{tag}-{}", Uuid::new_v4())).unwrap();
		let email = Email::parse(&format!("{tag}-{}@example.com", Uuid::new_v4())).unwrap();
		self.users.provision(subject, email, true).await.unwrap().id()
	}
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
	let Some(fx) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let users = fx.users.as_ref();
	let closed = BreakGlass::new(Vec::new());

	// A freshly provisioned user is an Investor — holds nothing.
	let id = fx.provision("gate").await;
	let sub = id.to_string();
	let denied = require_permission(users, &closed, &request_as(access_claims(&sub, 0)), Permission::UserRead).await.unwrap_err();
	assert_eq!(denied.code(), Code::PermissionDenied, "an investor must not read the operator console");

	// Grant Owner → RoleGrant is now allowed.
	users.set_role(id, Role::Owner).await.unwrap();
	require_permission(users, &closed, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.expect("owner may grant roles");

	// Suspend the owner → the gate denies at once, even with a still-valid (unexpired) token.
	users.disable_user(id).await.unwrap();
	let suspended = require_permission(users, &closed, &request_as(access_claims(&sub, 0)), Permission::RoleGrant).await.unwrap_err();
	assert_eq!(suspended.code(), Code::PermissionDenied, "a suspended operator loses the console immediately");

	// Reinstate, then revoke tokens (bumps token_version) → a token minted under the OLD
	// version is rejected, while a token at the new floor is accepted.
	users.enable_user(id).await.unwrap();
	let revoked = users.revoke_tokens(id).await.unwrap();
	assert!(revoked.token_version() >= 1, "revoke_tokens bumps the floor");
	let stale = require_permission(users, &closed, &request_as(access_claims(&sub, 0)), Permission::RoleGrant).await.unwrap_err();
	assert_eq!(stale.code(), Code::Unauthenticated, "a token below the revocation floor is rejected");
	require_permission(users, &closed, &request_as(access_claims(&sub, revoked.token_version())), Permission::RoleGrant)
		.await
		.expect("a token at the current version is accepted");

	// A service token is refused regardless of subject (self-service acts as a user only).
	let mut svc = access_claims(&sub, revoked.token_version());
	svc.typ = TokenType::Service;
	let svc_denied = require_permission(users, &closed, &request_as(svc), Permission::UserRead).await.unwrap_err();
	assert_eq!(svc_denied.code(), Code::PermissionDenied, "a service token is not a user principal");
}

/// The whole `OWNER_SUBJECTS` rule in one test: the list is authority while the registry
/// is empty and dead weight the instant it is not. That is what makes keeping the
/// allowlist safe at all — it cannot outrank a fund that exists.
#[tokio::test]
async fn the_allowlist_elevates_only_while_the_owner_registry_is_empty() {
	let Some(fx) = setup().await else {
		return;
	};
	let users = fx.users.as_ref();
	let listed = fx.provision("listed").await;
	let stranger = fx.provision("stranger").await;
	let allowlist = BreakGlass::new(vec![listed.to_string()]);

	// Empty registry: the listed subject holds Owner, nobody else does.
	require_permission(users, &allowlist, &request_as(access_claims(&listed.to_string(), 0)), Permission::RoleGrant)
		.await
		.expect("an allowlisted subject holds Owner while the fund has none");
	let denied = require_permission(users, &allowlist, &request_as(access_claims(&stranger.to_string(), 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(denied.code(), Code::PermissionDenied, "an unlisted subject is elevated by nothing");

	// The elevation is surface-only: it never wrote a role.
	assert_eq!(users.find_by_id(listed).await.unwrap().unwrap().role(), Role::Investor, "users.role is untouched by elevation");

	// One persisted owner, and the same list means nothing — on the very instance that had
	// already seen the empty registry.
	fx.seat_owner().await;
	let closed = require_permission(users, &allowlist, &request_as(access_claims(&listed.to_string(), 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(closed.code(), Code::PermissionDenied, "the first owner closes emergency access: {closed}");

	// A brand-new instance, which has to read the registry rather than remember it, agrees
	// — so this is a property of the data, not of one process's memory.
	let fresh = BreakGlass::new(vec![listed.to_string()]);
	let closed = require_permission(users, &fresh, &request_as(access_claims(&listed.to_string(), 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(closed.code(), Code::PermissionDenied, "{closed}");
}

/// The latch is one-way, and this says so out loud. Emptying the roster is not reachable
/// through any API — the owner floor refuses it — so this reaches for raw SQL to build a
/// state production cannot, and asserts emergency access stays shut even then.
#[tokio::test]
async fn the_latch_does_not_reopen_when_the_roster_is_emptied_behind_it() {
	let Some(fx) = setup().await else {
		return;
	};
	let users = fx.users.as_ref();
	let listed = fx.provision("latch").await;
	let allowlist = BreakGlass::new(vec![listed.to_string()]);
	let sub = listed.to_string();

	require_permission(users, &allowlist, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.expect("open while the registry is empty");

	fx.seat_owner().await;
	assert!(
		require_permission(users, &allowlist, &request_as(access_claims(&sub, 0)), Permission::RoleGrant).await.is_err(),
		"latched shut by the first owner"
	);

	// Only Postgres can do this; the plane cannot.
	clear_roster(&fx.pool).await;
	let still_shut = require_permission(users, &allowlist, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(still_shut.code(), Code::PermissionDenied, "the latch never falls back to open: {still_shut}");
}

#[tokio::test]
async fn allowlisted_operator_is_still_gated_by_status_and_revocation() {
	let Some(fx) = setup().await else {
		return;
	};
	let users = fx.users.as_ref();
	// The allowlist grants a role, never an exemption: once a record exists, DisableUser
	// and RevokeTokens must bite the emergency principals too.
	let id = fx.provision("breakglass").await;
	let sub = id.to_string();
	let allowlist = BreakGlass::new(vec![sub.clone()]);

	require_permission(users, &allowlist, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.expect("an active allowlisted operator holds Owner");

	users.disable_user(id).await.unwrap();
	let suspended = require_permission(users, &allowlist, &request_as(access_claims(&sub, 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(suspended.code(), Code::PermissionDenied, "a disabled allowlisted operator is denied");

	users.enable_user(id).await.unwrap();
	let revoked = users.revoke_tokens(id).await.unwrap();
	let stale = require_permission(users, &allowlist, &request_as(access_claims(&sub, revoked.token_version() - 1)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(stale.code(), Code::Unauthenticated, "an allowlisted token below the revocation floor is rejected");

	require_permission(users, &allowlist, &request_as(access_claims(&sub, revoked.token_version())), Permission::RoleGrant)
		.await
		.expect("an allowlisted token at the current floor is Owner again");
}

#[tokio::test]
async fn break_glass_allowlist_bootstraps_as_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	// An allowlisted subject holds Owner with NO persisted record at all — the state a
	// fund is in before anyone's first sign-in has minted a row, and the reason the
	// bootstrap has to work off a raw `sub` rather than a record.
	let boot_sub = Uuid::new_v4().to_string();
	let allowlist = BreakGlass::new(vec![boot_sub.clone()]);
	require_permission(fx.users.as_ref(), &allowlist, &request_as(access_claims(&boot_sub, 0)), Permission::RoleGrant)
		.await
		.expect("an allowlisted subject bootstraps as Owner");

	// And once the fund exists, even that record-less bootstrap is over.
	fx.seat_owner().await;
	let closed = require_permission(fx.users.as_ref(), &allowlist, &request_as(access_claims(&boot_sub, 0)), Permission::RoleGrant)
		.await
		.unwrap_err();
	assert_eq!(closed.code(), Code::PermissionDenied, "{closed}");
}

#[tokio::test]
async fn provisioner_summaries_carry_the_role_and_name_its_source() {
	let Some(fx) = setup().await else {
		return;
	};
	let users = fx.port();
	// Pre-provision so the concierge id is known, then allowlist it and drive the same
	// channel the auth task uses for Exchange (Provision) and Refresh (Lookup).
	let subject = AuthSubject::parse(&format!("authz-prov-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject.clone(), Email::parse("bootop@example.com").unwrap(), true).await.unwrap();
	let allowlist = Arc::new(BreakGlass::new(vec![user.id().to_string()]));
	let (provisioner, rx) = provisioner_channel();
	tokio::spawn(directory::run_provisioner(rx, users.clone(), allowlist));

	let provisioned = provisioner.provision(subject.as_str().to_owned(), "bootop@example.com".into(), true).await.unwrap();
	assert_eq!(provisioned.role, "owner", "an Exchange summary carries the elevated role");
	assert!(provisioned.role_is_break_glass, "and says the authority is the environment's, not the register's");
	let looked_up = provisioner.lookup(user.id().to_string()).await.unwrap();
	assert_eq!(looked_up.role, "owner", "a Refresh summary agrees");
	assert!(looked_up.role_is_break_glass);

	// Elevation is surface-only: the persisted role is never written by it.
	let persisted = users.find_by_id(user.id()).await.unwrap().expect("user exists");
	assert_eq!(persisted.role(), Role::Investor, "users.role is untouched by elevation");

	// Non-allowlisted control: a summary keeps the persisted role and claims nothing.
	let stranger_subject = AuthSubject::parse(&format!("authz-str-{}", Uuid::new_v4())).unwrap();
	let stranger = provisioner.provision(stranger_subject.as_str().to_owned(), "stranger@example.com".into(), true).await.unwrap();
	assert_eq!(stranger.role, "investor");
	assert!(!stranger.role_is_break_glass);

	// Seat an owner and the elevated summary reverts on the next Refresh — a session
	// minted under emergency access does not keep its authority once the fund exists.
	fx.seat_owner().await;
	let after = provisioner.lookup(user.id().to_string()).await.unwrap();
	assert_eq!(after.role, "investor", "emergency access is over");
	assert!(!after.role_is_break_glass);
}

#[tokio::test]
async fn malformed_admin_target_user_id_is_invalid_argument() {
	let Some(fx) = setup().await else {
		return;
	};
	// The caller passes the gate (record-less emergency Owner on an empty registry); a
	// malformed TARGET field is bad input (code 3), never UNAUTHENTICATED — a code 16 here
	// reads as an expired session to the console.
	let sub = Uuid::new_v4().to_string();
	let directory = Directory::new(fx.port(), Arc::new(BreakGlass::new(vec![sub.clone()])));

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

/// The bug this whole change exists to close: the console drew "Owner" for people the
/// consilium had never heard of, and nothing on the wire said which was which. Every read
/// surface now returns the flag beside the role.
#[tokio::test]
async fn read_surfaces_report_the_role_and_whether_it_is_break_glass() {
	let Some(fx) = setup().await else {
		return;
	};
	let elevated = fx.provision("surfaced").await;
	let plain = fx.provision("plain").await;
	let sub = elevated.to_string();
	let directory = Directory::new(fx.port(), Arc::new(BreakGlass::new(vec![sub.clone()])));

	// GetMe: the caller's own profile shows the same authority the gate grants, labelled.
	let me = directory.get_me(request_with(access_claims(&sub, 0), GetMeRequest {})).await.unwrap().into_inner();
	assert_eq!(me.role, "owner", "GetMe reports the elevated role");
	assert!(me.role_is_break_glass, "and names where it came from");

	// GetUser: the admin detail view elevates the allowlisted target only.
	let detail = directory
		.get_user(request_with(access_claims(&sub, 0), GetUserRequest { user_id: sub.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(detail.role, "owner");
	assert!(detail.role_is_break_glass);
	let other = directory
		.get_user(request_with(access_claims(&sub, 0), GetUserRequest { user_id: plain.to_string() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(other.role, "investor", "GetUser keeps the persisted role for everyone else");
	assert!(!other.role_is_break_glass);

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
	assert_eq!(listed.users[0].role, "owner");
	assert!(listed.users[0].role_is_break_glass, "a console must be able to warn on this row");
	let listed = directory
		.list_users(request_with(
			access_claims(&sub, 0),
			ListUsersRequest {
				query: plain.to_string(),
				..Default::default()
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(listed.users[0].role, "investor");
	assert!(!listed.users[0].role_is_break_glass);
}
