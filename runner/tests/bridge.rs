//! Integration tests for the cross-plane bridge producer (`UserEvents`).
//!
//! These hit a **real** Postgres (no mocks, per the project rules). They run when
//! `DATABASE_URL` is set and skip otherwise, so a DB-less `cargo test` still passes.
//! Each test provisions fresh users (unique `auth_subject`s), so runs neither collide
//! nor need a clean database.
//!
//! We drive the bridge through the real [`PgUsers`] write path (which emits outbox
//! rows in the write tx) and then call [`Bridge::pull_user_lifecycle`] directly,
//! asserting ordered events, the advancing `next_position` cursor, and that a
//! wrong/absent bridge token is rejected.

mod common;

use std::sync::Arc;

use concierge::{
	bridge::Bridge,
	infrastructure::{
		db,
		users::{AdminAction, PgUsers},
	},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::{Role, SEAT_GENERATION},
	users::UserId,
};
use evconcierge_contracts::concierge::v1::{PullUserLifecycleRequest, user_events_server::UserEvents, user_lifecycle_event::Kind};
use sqlx::PgPool;
use tonic::{Request, metadata::MetadataValue};
use uuid::Uuid;

const TOKEN: &str = "test-bridge-token";

async fn setup() -> Option<(PgUsers, PgPool)> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some((PgUsers::new(pool.clone()), pool))
}

fn authed<T>(body: T) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {TOKEN}")).unwrap());
	request
}

#[tokio::test]
async fn pull_returns_ordered_events_and_advances_cursor() {
	let Some((repo, pool)) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));

	// Where the outbox already stands. Reading from 0 would fill the page with whatever
	// a shared development database happens to hold — and once another suite has written
	// more than `limit` rows, the ones seeded below fall off the end and this test fails
	// for a reason that has nothing to do with the bridge.
	let start = sqlx::query_scalar::<_, i64>("SELECT COALESCE(max(position), 0) FROM user_outbox")
		.fetch_one(&pool)
		.await
		.expect("read the outbox head");

	// Seed a known sequence of mutations across two users → multiple outbox rows.
	let a = repo.resolve(common::google("a", true), 0).await.unwrap();
	let b = repo.resolve(common::google("b", true), 0).await.unwrap();
	repo.set_kyc_level(a.id(), 2, &AdminAction::system("kyc_level_set"), 0).await.unwrap();
	repo.revoke_tokens(b.id(), &AdminAction::system("tokens_revoked"), 0).await.unwrap();

	// Pull the whole outbox from the beginning.
	let resp = bridge
		.pull_user_lifecycle(authed(PullUserLifecycleRequest { after_position: start, limit: 1000 }))
		.await
		.expect("pull succeeds")
		.into_inner();

	assert!(resp.events.len() >= 4, "at least the four rows we seeded");

	// The cursor advanced past where we started reading.
	assert!(resp.next_position > start, "cursor advanced past the start");

	// Our seeded events are present with the right kinds, in position order.
	let a_id = a.id().to_string();
	let b_id = b.id().to_string();
	let a_kinds: Vec<i32> = resp.events.iter().filter(|e| e.user_id == a_id).map(|e| e.kind).collect();
	let b_kinds: Vec<i32> = resp.events.iter().filter(|e| e.user_id == b_id).map(|e| e.kind).collect();
	assert_eq!(a_kinds, vec![Kind::Created as i32, Kind::KycChanged as i32], "user a: CREATED then KYC_CHANGED in order");
	assert_eq!(
		b_kinds,
		vec![Kind::Created as i32, Kind::SessionsRevoked as i32],
		"user b: CREATED then SESSIONS_REVOKED in order"
	);

	// The KYC_CHANGED event carries the new level; SESSIONS_REVOKED the new floor.
	let kyc = resp.events.iter().find(|e| e.user_id == a_id && e.kind == Kind::KycChanged as i32).unwrap();
	assert_eq!(kyc.kyc_level, 2);
	let revoked = resp.events.iter().find(|e| e.user_id == b_id && e.kind == Kind::SessionsRevoked as i32).unwrap();
	assert_eq!(revoked.token_version, 1);
}

#[tokio::test]
async fn cursor_pagination_does_not_re_serve() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));

	let user = repo.resolve(common::google("page", true), 0).await.unwrap();
	repo.set_kyc_level(user.id(), 1, &AdminAction::system("kyc_level_set"), 0).await.unwrap();

	// First page of 1 starting at the row just before this user's CREATED. Even with
	// other tests writing concurrently, this user's CREATED is the lowest-positioned
	// row above `first_pos`, so a limit-1 pull returns exactly it.
	let first_pos = first_position_for(&pool, user.id().raw()).await - 1;
	let page1 = bridge
		.pull_user_lifecycle(authed(PullUserLifecycleRequest {
			after_position: first_pos,
			limit: 1,
		}))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(page1.events.len(), 1);
	assert_eq!(page1.events[0].user_id, user.id().to_string());
	assert_eq!(page1.events[0].kind, Kind::Created as i32);

	// Walking from the returned cursor never re-serves the first row and eventually
	// reaches this user's KYC_CHANGED (interleaved with other tests' rows). The cursor
	// strictly advances each page.
	let mut cursor = page1.next_position;
	let mut saw_kyc = false;
	for _ in 0..50 {
		let page = bridge
			.pull_user_lifecycle(authed(PullUserLifecycleRequest { after_position: cursor, limit: 1 }))
			.await
			.unwrap()
			.into_inner();
		let Some(event) = page.events.first() else { break };
		assert!(page.next_position > cursor, "cursor strictly advances, never re-serving served rows");
		cursor = page.next_position;
		if event.user_id == user.id().to_string() && event.kind == Kind::KycChanged as i32 {
			saw_kyc = true;
			break;
		}
	}
	assert!(saw_kyc, "reached this user's KYC_CHANGED past the cursor");
}

#[tokio::test]
async fn empty_pull_returns_cursor_unchanged() {
	let Some((_repo, pool)) = setup().await else {
		return;
	};
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));

	// A position above any row bigserial can plausibly reach → no events even with
	// other tests writing concurrently; the cursor is returned unchanged.
	let high = 1_000_000_000_000_i64;
	let resp = bridge
		.pull_user_lifecycle(authed(PullUserLifecycleRequest { after_position: high, limit: 100 }))
		.await
		.unwrap()
		.into_inner();
	assert!(resp.events.is_empty());
	assert_eq!(resp.next_position, high, "no rows ⇒ next_position is the request's after_position");
}

#[tokio::test]
async fn wrong_token_is_rejected() {
	let Some((_repo, pool)) = setup().await else {
		return;
	};
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));

	let mut wrong = Request::new(PullUserLifecycleRequest { after_position: 0, limit: 10 });
	wrong.metadata_mut().insert("authorization", MetadataValue::from_static("Bearer nope"));
	let err = bridge.pull_user_lifecycle(wrong).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn equal_length_wrong_token_is_rejected() {
	let Some((_repo, pool)) = setup().await else {
		return;
	};
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));

	// Flip TOKEN's last byte: same length, shared prefix, so a regression to a
	// length-only, prefix, or truncated compare would accept it — only the full
	// per-byte compare rejects it.
	let mut forged = TOKEN.to_string().into_bytes();
	*forged.last_mut().unwrap() ^= 1;
	let forged = String::from_utf8(forged).unwrap();
	let mut wrong = Request::new(PullUserLifecycleRequest { after_position: 0, limit: 10 });
	wrong.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {forged}")).unwrap());
	let err = bridge.pull_user_lifecycle(wrong).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn absent_token_is_rejected() {
	let Some((_repo, pool)) = setup().await else {
		return;
	};
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));

	let err = bridge
		.pull_user_lifecycle(Request::new(PullUserLifecycleRequest { after_position: 0, limit: 10 }))
		.await
		.unwrap_err();
	assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn unconfigured_bridge_fails_closed() {
	let Some((_repo, pool)) = setup().await else {
		return;
	};
	let bridge = Bridge::new(pool.clone(), None);

	let err = bridge.pull_user_lifecycle(authed(PullUserLifecycleRequest { after_position: 0, limit: 10 })).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::Unavailable, "no configured token ⇒ never serve the outbox");
}

#[tokio::test]
async fn outbox_append_serializes_position_with_commit_order() {
	let Some((repo, pool)) = setup().await else {
		return;
	};
	let repo = Arc::new(repo);
	let user = repo.resolve(common::google("lock", true), 0).await.unwrap();

	// Hold the outbox advisory lock in an open transaction — mimicking another writer
	// mid-append. This is the mechanism that forces `position` (BIGSERIAL) assignment order
	// to match COMMIT order, so the banking high-water cursor can never skip a committed row.
	let mut holder = pool.begin().await.unwrap();
	sqlx::query("SELECT pg_advisory_xact_lock($1)")
		.bind(concierge::infrastructure::users::USER_OUTBOX_ADVISORY_LOCK)
		.execute(&mut *holder)
		.await
		.unwrap();

	// A real mutation that must append an outbox row cannot proceed while the lock is held.
	let writer = repo.clone();
	let id = user.id();
	let mutation = tokio::spawn(async move { writer.set_kyc_level(id, 1, &AdminAction::system("kyc_level_set"), 0).await });

	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	assert!(!mutation.is_finished(), "the outbox append must block while the lock is held elsewhere");

	// Releasing the holder lets the blocked writer acquire the lock and commit.
	holder.rollback().await.unwrap();
	tokio::time::timeout(std::time::Duration::from_secs(10), mutation)
		.await
		.expect("the blocked writer completes once the lock is free")
		.expect("join the mutation task")
		.expect("set_kyc_level succeeds");
}

async fn first_position_for(pool: &PgPool, user_id: Uuid) -> i64 {
	sqlx::query_scalar::<_, i64>("SELECT MIN(position) FROM user_outbox WHERE user_id = $1")
		.bind(user_id)
		.fetch_one(pool)
		.await
		.expect("user has at least one outbox row")
}

/// Every row of `user`, oldest first, as the money plane reads it.
async fn pulled(pool: &PgPool, user: UserId) -> Vec<(Kind, Option<Vec<String>>)> {
	let bridge = Bridge::new(pool.clone(), Some(TOKEN.to_string()));
	let events = bridge
		.pull_user_lifecycle(authed(PullUserLifecycleRequest { after_position: 0, limit: 1000 }))
		.await
		.unwrap()
		.into_inner()
		.events;
	events
		.into_iter()
		.filter(|e| e.user_id == user.to_string())
		.map(|e| (e.kind(), e.seat_permissions.map(|s| s.bank)))
		.collect()
}

async fn operator(pool: &PgPool) -> UserId {
	let repo = PgUsers::new(pool.clone());
	let user = repo.resolve(common::google("seat", true), 0).await.unwrap();
	repo.set_role(user.id(), Role::Operator).await.unwrap();
	user.id()
}

fn bank(role: Role) -> Option<Vec<String>> {
	Some(role.bank_permissions().into_iter().map(str::to_owned).collect())
}

async fn seat_meaning(pool: &PgPool, role: Role) -> (Vec<String>, i32) {
	sqlx::query_as("SELECT bank_permissions, generation FROM seat_meanings WHERE role = $1")
		.bind(role.as_str())
		.fetch_one(pool)
		.await
		.unwrap()
}

/// Replace a seat's meaning outright; an UPDATE would be skipped unless it raised the generation.
async fn define_seat(pool: &PgPool, role: Role, bank: &[&str], generation: i32) {
	sqlx::query("DELETE FROM seat_meanings WHERE role = $1").bind(role.as_str()).execute(pool).await.unwrap();
	sqlx::query("INSERT INTO seat_meanings (role, bank_permissions, announced_at, generation) VALUES ($1, $2, 0, $3)")
		.bind(role.as_str())
		.bind(bank)
		.bind(generation)
		.execute(pool)
		.await
		.unwrap();
}

#[tokio::test]
async fn the_database_stamps_every_row_whatever_the_writer_sent() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	let pool = &scratch.pool;
	let user = operator(pool).await;
	// What a pre-0027 binary writes (no `permissions`), then what a binary with a stale set writes.
	for permissions in [None, Some(vec!["bank:stale".to_owned()])] {
		let column = if permissions.is_some() { ", permissions" } else { "" };
		let value = if permissions.is_some() { ", $3" } else { "" };
		sqlx::query(sqlx::AssertSqlSafe(format!(
			"INSERT INTO user_outbox (user_id, kind, kyc_level, occurred_at, sequence, auth_subject, email, email_verified, token_version, role{column}) \
			 SELECT id, 'KYC_CHANGED', 0, 0, $2, auth_subject, email, email_verified, token_version, role{value} FROM users WHERE id = $1"
		)))
		.bind(user.raw())
		.bind(100_i64)
		.bind(permissions)
		.execute(pool)
		.await
		.unwrap();
	}
	assert_eq!(
		pulled(pool, user).await,
		[
			(Kind::Created, bank(Role::Investor)),
			(Kind::RoleChanged, bank(Role::Operator)),
			(Kind::KycChanged, bank(Role::Operator)),
			(Kind::KycChanged, bank(Role::Operator)),
		]
	);
	scratch.drop_database().await;
}

#[tokio::test]
async fn a_row_written_before_the_set_was_stated_reads_as_unstated_not_empty() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	let pool = &scratch.pool;
	let user = operator(pool).await;
	sqlx::query("UPDATE user_outbox SET permissions = NULL WHERE user_id = $1 AND kind = 'CREATED'")
		.bind(user.raw())
		.execute(pool)
		.await
		.unwrap();
	assert_eq!(pulled(pool, user).await, [(Kind::Created, None), (Kind::RoleChanged, bank(Role::Operator))]);
	scratch.drop_database().await;
}

#[tokio::test]
async fn an_older_binary_never_overwrites_a_newer_seat_meaning() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	let pool = &scratch.pool;
	let user = operator(pool).await;
	let newer = SEAT_GENERATION as i32 + 1;
	sqlx::query("UPDATE seat_meanings SET bank_permissions = '{bank:newer}', generation = $1 WHERE role = 'operator'")
		.bind(newer)
		.execute(pool)
		.await
		.unwrap();

	// v0.13.1's announce upsert, verbatim.
	sqlx::query(
		"INSERT INTO seat_meanings (role, bank_permissions, announced_at) VALUES ($1, $2, $3) \
		 ON CONFLICT (role) DO UPDATE SET bank_permissions = EXCLUDED.bank_permissions, announced_at = EXCLUDED.announced_at \
		 WHERE seat_meanings.bank_permissions IS DISTINCT FROM EXCLUDED.bank_permissions",
	)
	.bind("operator")
	.bind(Role::Operator.bank_permissions())
	.bind(0_i64)
	.execute(pool)
	.await
	.unwrap();
	db::migrate(pool).await.expect("an older binary boots beside a newer meaning");

	assert_eq!(seat_meaning(pool, Role::Operator).await, (vec!["bank:newer".to_owned()], newer));
	assert_eq!(
		pulled(pool, user).await.last(),
		Some(&(Kind::PermissionsChanged, Some(vec!["bank:newer".to_owned()]))),
		"the money plane converges on the newest meaning, whichever binary boots"
	);
	scratch.drop_database().await;
}

#[tokio::test]
async fn a_seat_redefined_without_a_new_generation_refuses_the_boot() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	define_seat(&scratch.pool, Role::Operator, &["bank:other"], SEAT_GENERATION as i32).await;
	let err = db::migrate(&scratch.pool).await.expect_err("same generation, different set");
	assert!(err.to_string().contains("bump SEAT_GENERATION"), "{err}");
	scratch.drop_database().await;
}

#[tokio::test]
async fn a_set_stated_in_another_order_is_the_same_set() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	let pool = &scratch.pool;
	let mut reversed = Role::Operator.bank_permissions();
	reversed.reverse();
	define_seat(pool, Role::Operator, &reversed, 0).await;
	let user = operator(pool).await;
	db::migrate(pool).await.unwrap();
	assert_eq!(seat_meaning(pool, Role::Operator).await.1, SEAT_GENERATION as i32);
	assert_eq!(pulled(pool, user).await.iter().filter(|(kind, _)| *kind == Kind::PermissionsChanged).count(), 0);
	scratch.drop_database().await;
}

#[tokio::test]
async fn a_user_whose_last_row_is_unstated_is_told_once() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	let pool = &scratch.pool;
	let user = operator(pool).await;
	sqlx::query("UPDATE user_outbox SET permissions = NULL WHERE user_id = $1 AND kind = 'ROLE_CHANGED'")
		.bind(user.raw())
		.execute(pool)
		.await
		.unwrap();
	db::migrate(pool).await.unwrap();
	db::migrate(pool).await.unwrap();
	assert_eq!(
		pulled(pool, user).await,
		[(Kind::Created, bank(Role::Investor)), (Kind::RoleChanged, None), (Kind::PermissionsChanged, bank(Role::Operator))]
	);
	scratch.drop_database().await;
}
