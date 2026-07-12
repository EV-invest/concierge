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

use std::sync::Arc;

use concierge::{
	bridge::Bridge,
	infrastructure::{db, users::PgUsers},
	ports::UserDirectoryRepository,
};
use domain::users::{AuthSubject, Email};
use evconcierge_contracts::concierge::v1::{PullUserLifecycleRequest, user_events_server::UserEvents, user_lifecycle_event::Kind};
use sqlx::PgPool;
use tonic::{Request, metadata::MetadataValue};
use uuid::Uuid;

const TOKEN: &str = "test-bridge-token";

async fn setup() -> Option<(PgUsers, PgPool)> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some((PgUsers::new(pool.clone()), pool))
}

fn unique_subject() -> AuthSubject {
	AuthSubject::parse(&format!("itest-{}", Uuid::new_v4())).unwrap()
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

	// Seed a known sequence of mutations across two users → multiple outbox rows.
	let a = repo.provision(unique_subject(), Email::parse("a@example.com").unwrap(), true).await.unwrap();
	let b = repo.provision(unique_subject(), Email::parse("b@example.com").unwrap(), true).await.unwrap();
	repo.set_kyc_level(a.id(), 2).await.unwrap();
	repo.revoke_tokens(b.id()).await.unwrap();

	// Pull the whole outbox from the beginning.
	let resp = bridge
		.pull_user_lifecycle(authed(PullUserLifecycleRequest { after_position: 0, limit: 1000 }))
		.await
		.expect("pull succeeds")
		.into_inner();

	assert!(resp.events.len() >= 4, "at least the four rows we seeded");

	// The cursor advanced past the start of the outbox.
	assert!(resp.next_position > 0, "cursor advanced past the start");

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

	let user = repo.provision(unique_subject(), Email::parse("page@example.com").unwrap(), true).await.unwrap();
	repo.set_kyc_level(user.id(), 1).await.unwrap();

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
	let user = repo.provision(unique_subject(), Email::parse("lock@example.com").unwrap(), true).await.unwrap();

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
	let mutation = tokio::spawn(async move { writer.set_kyc_level(id, 1).await });

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
