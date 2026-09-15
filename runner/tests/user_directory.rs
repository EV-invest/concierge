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

use concierge::{
	infrastructure::{
		db,
		users::{AdminAction, PgUsers},
	},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::Role,
	users::{AuthSubject, Email, UserStatus},
};
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
	role: Option<String>,
}

async fn outbox_for(pool: &PgPool, user_id: Uuid) -> Vec<OutboxRow> {
	sqlx::query_as::<_, OutboxRow>("SELECT kind, sequence, token_version, auth_subject, email, email_verified, kyc_level, role FROM user_outbox WHERE user_id = $1 ORDER BY position")
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
	let revoked = repo.revoke_tokens(user.id(), &AdminAction::system("tokens_revoked"), 0).await.unwrap();
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

	let reinstated = repo.enable_user(user.id(), 0).await.unwrap();
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
	repo.set_kyc_level(user.id(), 2, &AdminAction::system("kyc_level_set"), 0).await.unwrap();

	let row = outbox_for(&pool, user.id().raw()).await.pop().expect("a row");
	assert_eq!(row.kind, "KYC_CHANGED");
	assert_eq!(row.kyc_level, 2);
}

#[tokio::test]
async fn role_change_emits_role_changed_carrying_the_new_role() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let user = repo.provision(unique_subject(), Email::parse("role@example.com").unwrap(), true).await.unwrap();

	// A default-role user is Investor; the CREATED snapshot carries it.
	let created = &outbox_for(&pool, user.id().raw()).await[0];
	assert_eq!(created.role.as_deref(), Some("investor"), "CREATED snapshots the default role");

	let promoted = repo.set_role(user.id(), Role::Admin).await.unwrap();
	assert_eq!(promoted.role(), Role::Admin, "role persisted on the aggregate");
	let record = repo.authz_record(user.id()).await.unwrap().expect("authz record exists");
	assert_eq!(record.role, Role::Admin, "authz_record reads it back for the gate");

	let row = outbox_for(&pool, user.id().raw()).await.pop().expect("a row");
	assert_eq!(row.kind, "ROLE_CHANGED");
	assert_eq!(row.role.as_deref(), Some("admin"), "the outbox row carries the new role for banking to mirror");
	assert_eq!(row.sequence, 2, "the per-user sequence advanced past CREATED");
}

#[derive(sqlx::FromRow)]
struct ActionRow {
	action: String,
	actor_user_id: Option<Uuid>,
	detail: Option<serde_json::Value>,
}

async fn actions_for(pool: &PgPool, user_id: Uuid) -> Vec<ActionRow> {
	sqlx::query_as::<_, ActionRow>("SELECT action, actor_user_id, detail FROM admin_action WHERE subject_user_id = $1 ORDER BY position")
		.bind(user_id)
		.fetch_all(pool)
		.await
		.expect("read admin_action")
}

/// #48: a user's KYC history is ONE log, and it carries the delta.
///
/// Both entry points reach `users.set_kyc_level` in the aggregate, but only the manual
/// one used to leave a trace. An operator opening a user's history saw the admin
/// decisions and had to infer the rest from `kyc_cases` — a table keyed by the vendor's
/// session id, shaped around its verdicts, and holding no manual rows at all. "Who set
/// tier 3 by hand, and when" was recoverable; "and what was it before" was not, because
/// the row said only where the level ended up, which is also what the account says.
///
/// No new table and no manual rows in `kyc_cases`: its `requested_tier` CHECK and unique
/// `provider_ref` are shaped for vendor cases, and reusing them for a human decision is a
/// modelling choice, not a mechanical one.
#[tokio::test]
async fn both_kyc_writers_land_in_one_audit_log_with_the_delta() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let operator = repo.provision(unique_subject(), Email::parse("kyc-operator@example.com").unwrap(), true).await.unwrap();
	let user = repo.provision(unique_subject(), Email::parse("kyc-subject@example.com").unwrap(), true).await.unwrap();

	// The VENDOR half, which used to write nothing here.
	let vendor_case = Uuid::new_v4();
	let vendor_audit = AdminAction::system("kyc_level_set").with_detail(serde_json::json!({ "source": "didit", "case_id": vendor_case.to_string() }));
	repo.raise_kyc_level_to(user.id(), 1, &vendor_audit, 1_700_000_000).await.unwrap();

	// The MANUAL half, moving the level DOWN — the direction only a human may take, and
	// precisely the one a row saying "kyc_level: 0" cannot be told apart from a fresh
	// account that was never raised at all.
	let manual = AdminAction::by(operator.id(), "kyc_level_set", &Default::default()).with_reason("documents withdrawn");
	repo.set_kyc_level(user.id(), 0, &manual, 1_700_000_100).await.unwrap();

	let rows = actions_for(&pool, user.id().raw()).await;
	assert_eq!(rows.len(), 2, "one log, both halves");
	assert!(rows.iter().all(|r| r.action == "kyc_level_set"), "one verb, so a history view needs no union");

	let vendor = rows[0].detail.as_ref().expect("the vendor row carries a detail");
	assert_eq!(rows[0].actor_user_id, None, "no human decided this, and inventing one would be worse than none");
	assert_eq!(vendor["from"], 0);
	assert_eq!(vendor["to"], 1);
	assert_eq!(vendor["source"], "didit", "who decided instead of an actor id");
	assert_eq!(vendor["case_id"], vendor_case.to_string(), "and which case, so the verdict is findable");

	let human = rows[1].detail.as_ref().expect("the manual row carries a detail");
	assert_eq!(rows[1].actor_user_id, Some(operator.id().raw()), "a human decision names its human");
	assert_eq!(human["from"], 1, "the DOWNGRADE is legible — this is the direction no vendor may take");
	assert_eq!(human["to"], 0);
	assert_eq!(human["kyc_level"], 0, "kept beside `to` so rows written before this still read alike");
}

/// A vendor verdict that raises nothing writes nothing.
///
/// `raise_kyc_level_to` is monotonic and returns before any write when the account
/// already holds the level — which is also the REDELIVERY path, travelled every time
/// Didit retries. An audit row there would turn one decision into a log entry per retry,
/// and a history that grows when nothing happened is a history nobody trusts.
#[tokio::test]
async fn a_vendor_approval_that_changes_nothing_writes_no_audit_row() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let user = repo.provision(unique_subject(), Email::parse("kyc-noop@example.com").unwrap(), true).await.unwrap();
	let audit = AdminAction::system("kyc_level_set").with_detail(serde_json::json!({ "source": "didit", "case_id": Uuid::new_v4().to_string() }));

	repo.raise_kyc_level_to(user.id(), 1, &audit, 1_700_000_000).await.unwrap();
	repo.raise_kyc_level_to(user.id(), 1, &audit, 1_700_000_100).await.unwrap();
	repo.raise_kyc_level_to(user.id(), 1, &audit, 1_700_000_200).await.unwrap();

	assert_eq!(actions_for(&pool, user.id().raw()).await.len(), 1, "three deliveries, one decision, one row");
}
