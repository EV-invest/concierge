//! Integration tests for the Postgres user directory + the cross-plane outbox.
//!
//! These hit a **real** Postgres (no mocks, per the project rules). They run when
//! `DATABASE_URL` is set (e.g. after the dev DB is up) and skip otherwise, so a
//! DB-less `cargo test` still passes. Each test uses a fresh random `auth_subject`,
//! so runs neither collide nor require a clean database.
//!
//! The directory's gRPC handlers (`GetMe`/`RevokeTokens`/`DisableUser`) are thin
//! authz wrappers over this repository (covered structurally by
//! `auth_choke_point.rs`); here we drive the repository — the load-bearing write path
//! — and assert both the user row and the `user_outbox` rows it emits in the same tx.

use concierge::infrastructure::{db, users::PgUsers};
use domain::users::{AuthSubject, Email, UserStatus};
use sqlx::PgPool;
use uuid::Uuid;

async fn setup() -> Option<(PgUsers, PgPool)> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some((PgUsers::new(pool.clone()), pool))
}

fn unique_subject() -> AuthSubject {
	AuthSubject::parse(&format!("itest-{}", Uuid::new_v4())).unwrap()
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
	kind: String,
	sequence: i64,
	token_version: i64,
	auth_subject: String,
	email: Option<String>,
	email_verified: bool,
	kyc_level: i32,
}

async fn outbox_for(pool: &PgPool, user_id: Uuid) -> Vec<OutboxRow> {
	sqlx::query_as::<_, OutboxRow>("SELECT kind, sequence, token_version, auth_subject, email, email_verified, kyc_level FROM user_outbox WHERE user_id = $1 ORDER BY position")
		.bind(user_id)
		.fetch_all(pool)
		.await
		.expect("read outbox")
}

#[tokio::test]
async fn provision_creates_user_and_emits_created() {
	let Some((repo, pool)) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let subject = unique_subject();
	let user = repo.provision(subject.clone(), Email::parse("itest@example.com").unwrap(), true).await.unwrap();

	// GetMe reads exactly this row back.
	let loaded = repo.find_by_id(user.id()).await.unwrap().expect("user exists");
	assert_eq!(loaded.id(), user.id());
	assert_eq!(loaded.email().as_str(), "itest@example.com");
	assert_eq!(loaded.token_version(), 0);
	assert!(loaded.is_active());

	let rows = outbox_for(&pool, user.id().raw()).await;
	assert_eq!(rows.len(), 1, "exactly one CREATED on first provision");
	let created = &rows[0];
	assert_eq!(created.kind, "CREATED");
	assert_eq!(created.sequence, 1, "sequence = row_version after provision");
	assert_eq!(created.auth_subject, subject.as_str());
	assert_eq!(created.email.as_deref(), Some("itest@example.com"));
	assert!(created.email_verified);
	assert_eq!(created.token_version, 0);
}

#[tokio::test]
async fn reprovision_is_idempotent_and_emits_no_new_event() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let subject = unique_subject();
	let first = repo.provision(subject.clone(), Email::parse("before@example.com").unwrap(), true).await.unwrap();
	let again = repo.provision(subject.clone(), Email::parse("After@Example.com").unwrap(), true).await.unwrap();

	assert_eq!(first.id(), again.id(), "one subject maps to one user");
	assert_eq!(again.email().as_str(), "after@example.com", "email is updated and normalized");
	let rows = outbox_for(&pool, first.id().raw()).await;
	assert_eq!(rows.len(), 1, "an email-only re-sign-in emits no new outbox row");
}

#[tokio::test]
async fn revoke_bumps_version_and_emits_sessions_revoked() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let user = repo.provision(unique_subject(), Email::parse("rev@example.com").unwrap(), true).await.unwrap();
	let revoked = repo.revoke_tokens(user.id()).await.unwrap();
	assert_eq!(revoked.token_version(), 1);

	let reloaded = repo.find_by_id(user.id()).await.unwrap().unwrap();
	assert_eq!(reloaded.token_version(), 1, "bump persisted");

	let rows = outbox_for(&pool, user.id().raw()).await;
	let revoked_row = rows.last().expect("an outbox row");
	assert_eq!(revoked_row.kind, "SESSIONS_REVOKED");
	assert_eq!(revoked_row.token_version, 1, "carries the new token_version floor");
	assert_eq!(revoked_row.sequence, 2, "row_version advanced past CREATED");
}

#[tokio::test]
async fn disable_then_enable_emits_suspended_then_reinstated() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let user = repo.provision(unique_subject(), Email::parse("dis@example.com").unwrap(), true).await.unwrap();

	let disabled = repo.disable_user(user.id()).await.unwrap();
	assert_eq!(disabled.status(), UserStatus::Disabled);
	let suspended = outbox_for(&pool, user.id().raw()).await.pop().expect("a row");
	assert_eq!(suspended.kind, "SUSPENDED");
	assert_eq!(suspended.sequence, 2);

	let reinstated = repo.enable_user(user.id()).await.unwrap();
	assert_eq!(reinstated.status(), UserStatus::Active);
	let row = outbox_for(&pool, user.id().raw()).await.pop().expect("a row");
	assert_eq!(row.kind, "REINSTATED");
	assert_eq!(row.sequence, 3, "the per-user sequence is strictly increasing");
}

#[tokio::test]
async fn kyc_change_emits_kyc_changed_with_level() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let user = repo.provision(unique_subject(), Email::parse("kyc@example.com").unwrap(), true).await.unwrap();
	repo.set_kyc_level(user.id(), 2).await.unwrap();

	let row = outbox_for(&pool, user.id().raw()).await.pop().expect("a row");
	assert_eq!(row.kind, "KYC_CHANGED");
	assert_eq!(row.kyc_level, 2);
}
