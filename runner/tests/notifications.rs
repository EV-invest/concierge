//! Real-Postgres coverage for the notification adapter.
//!
//! Proves the SQL actually EXECUTES, which unit tests cannot: the queries lean on
//! several constructs that either work or fail only against a live server —
//! `ON CONFLICT` inference against a *partial* unique index, `make_interval(secs =>)`
//! with a float bind, a `FOR UPDATE SKIP LOCKED` CTE feeding an `UPDATE … RETURNING`,
//! and the `(created_at, id) < (SELECT …)` keyset cursor.
//!
//! Every test generates its own subscriber, so the suites can run concurrently against
//! the shared dev database without a clean-slate requirement — matching the convention
//! in `platform.rs` and `user_directory.rs`.

use std::sync::Arc;

use concierge::{
	infrastructure::{db, notifications::PgNotifications},
	ports::{NotificationDispatchRepository, NotificationRepository},
};
use uuid::Uuid;

async fn setup() -> Option<Arc<PgNotifications>> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some(Arc::new(PgNotifications::new(pool)))
}

const TOPIC: &str = "fund:quy-nhon";

#[tokio::test]
async fn subscriber_is_idempotent_and_tracks_the_address() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = Uuid::new_v4();

	// The upsert infers a PARTIAL unique index (`WHERE user_id IS NOT NULL`), which is
	// the construct most likely to fail only at runtime.
	let first = repo.subscriber_for_user(user, "a@example.com", true).await.expect("create subscriber");
	let second = repo.subscriber_for_user(user, "b@example.com", false).await.expect("upsert subscriber");

	assert_eq!(first.id, second.id, "a second touch upserts rather than creating a rival subscriber");
	assert_eq!(second.email, "b@example.com", "the address is kept in step with the directory's copy");
	assert!(!second.email_verified, "verification follows the directory too, including downgrades");
	assert!(second.confirmed, "a signed-in subscriber is confirmed on sight — Google already verified the address");
	assert!(!first.unsubscribe_token.is_empty(), "every subscriber gets an unsubscribe token at creation");
	assert!(second.in_app_enabled && second.email_enabled, "both channels start on");
}

#[tokio::test]
async fn emit_requires_a_subscription_and_dedupes() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = Uuid::new_v4();
	let sub = repo.subscriber_for_user(user, "emit@example.com", true).await.expect("subscriber");

	// Not following yet ⇒ nothing is delivered, and it is not an error.
	let none = repo.emit(user, TOPIC, "nav", "t", "b", "", "k1", 100).await.expect("emit without subscription");
	assert!(none.notification_id.is_none(), "an unfollowed topic stores nothing");
	assert!(!none.in_app && !none.email, "and delivers on no channel");

	repo.set_topic_subscription(sub.id, TOPIC, true, true).await.expect("follow");

	let first = repo.emit(user, TOPIC, "nav", "NAV updated", "body", "/funds/x", "k1", 100).await.expect("emit");
	assert!(first.notification_id.is_some(), "a followed topic stores the notification");
	assert!(first.in_app, "in-app is on, so it is delivered there");
	assert!(first.email, "email is on and the address is verified, so a copy is queued");
	assert!(!first.deduped);

	// The whole point of the unique dedupe index: an at-least-once retry is a no-op.
	let retry = repo.emit(user, TOPIC, "nav", "NAV updated", "body", "/funds/x", "k1", 100).await.expect("retry emit");
	assert!(retry.deduped, "the same dedupe key must not produce a second notification or a second email");
	assert!(retry.notification_id.is_none());

	assert_eq!(repo.unread_count(sub.id).await.expect("count"), 1, "the retry did not inflate the inbox");
}

#[tokio::test]
async fn channels_gate_delivery_independently_and_may_both_be_off() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = Uuid::new_v4();
	let sub = repo.subscriber_for_user(user, "gate@example.com", true).await.expect("subscriber");
	repo.set_topic_subscription(sub.id, TOPIC, true, true).await.expect("follow");

	// Email off, in-app on.
	repo.set_channel_enabled(sub.id, None, Some(false)).await.expect("email off");
	let a = repo.emit(user, TOPIC, "k", "t", "", "", "c1", 1).await.expect("emit");
	assert!(a.in_app && !a.email, "the master email switch alone suppresses the copy");

	// Both off — a supported state, not a broken record.
	repo.set_channel_enabled(sub.id, Some(false), None).await.expect("in-app off");
	let b = repo.emit(user, TOPIC, "k", "t", "", "", "c2", 1).await.expect("emit");
	assert!(!b.in_app && !b.email, "with both channels off nothing is delivered");
	assert!(b.notification_id.is_some(), "the durable record is still written — it anchors the dedupe key");

	// Suppression is a read-path concern, so the inbox reads empty while in-app is off,
	// and the history comes back when it is switched on again.
	repo.set_channel_enabled(sub.id, Some(true), None).await.expect("in-app back on");
	assert_eq!(repo.unread_count(sub.id).await.expect("count"), 2, "re-enabling restores history rather than showing a gap");
}

#[tokio::test]
async fn inbox_paginates_by_keyset_and_marks_read() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = Uuid::new_v4();
	let sub = repo.subscriber_for_user(user, "page@example.com", true).await.expect("subscriber");
	repo.set_topic_subscription(sub.id, TOPIC, true, false).await.expect("follow");

	// Emitted back-to-back on purpose: they land in the same second, which is what makes
	// the select list's `… AS created_at` alias shadow the ORDER BY and break the cursor.
	for i in 0..5 {
		repo.emit(user, TOPIC, "k", &format!("n{i}"), "", "", &format!("p{i}"), 100 + i).await.expect("emit");
	}

	let page1 = repo.list(sub.id, None, 2, false, None).await.expect("page 1");
	assert_eq!(page1.len(), 2, "the limit is honoured");

	// The cursor is the previous page's last id, resolved server-side into its
	// (created_at, id) key — the construct being proven here.
	let page2 = repo.list(sub.id, Some(page1[1].id), 2, false, None).await.expect("page 2");
	assert_eq!(page2.len(), 2);
	assert!(
		page1.iter().all(|a| page2.iter().all(|b| a.id != b.id)),
		"pages must not overlap, or the reader sees duplicates while scrolling"
	);

	assert_eq!(repo.unread_count(sub.id).await.expect("count"), 5);
	let marked = repo.mark_read(sub.id, &[page1[0].id], false).await.expect("mark one");
	assert_eq!(marked, 1);
	assert_eq!(repo.unread_count(sub.id).await.expect("count"), 4);

	let unread_only = repo.list(sub.id, None, 10, true, None).await.expect("unread page");
	assert_eq!(unread_only.len(), 4, "the read one drops out of the unread filter");

	assert_eq!(repo.mark_read(sub.id, &[], true).await.expect("mark all"), 4, "mark-all only touches what is still unread");
	assert_eq!(repo.unread_count(sub.id).await.expect("count"), 0);

	// A foreign id must not be markable even though ids are unguessable.
	let other = Uuid::new_v4();
	let other_sub = repo.subscriber_for_user(other, "other@example.com", true).await.expect("other subscriber");
	assert_eq!(
		repo.mark_read(other_sub.id, &[page1[0].id], false).await.expect("cross-subscriber mark"),
		0,
		"mark_read is scoped by subscriber, so one user cannot touch another's inbox"
	);
}

#[tokio::test]
async fn anonymous_subscribe_is_throttled_and_confirmable() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let email = format!("anon-{}@example.com", Uuid::new_v4());

	let first = repo.subscribe_anonymous(&email, TOPIC, 3600).await.expect("first subscribe");
	let (_, token) = first.expect("a confirmation mail is queued for a brand-new address");

	// The durable per-address throttle: this is what bounds mail volume per victim,
	// however many requests arrive.
	let second = repo.subscribe_anonymous(&email, TOPIC, 3600).await.expect("second subscribe");
	assert!(second.is_none(), "a repeat inside the window queues no second confirmation");

	assert!(repo.confirm(&token).await.expect("confirm"), "the token confirms the subscriber");
	assert!(!repo.confirm(&token).await.expect("replay"), "the token is spent, so a leaked link cannot be replayed");

	// Already confirmed ⇒ still no mail, and the caller cannot tell that apart from
	// the throttled case.
	let third = repo.subscribe_anonymous(&email, TOPIC, 0).await.expect("third subscribe");
	assert!(third.is_none(), "a confirmed address is never re-mailed a confirmation");
}

#[tokio::test]
async fn unsubscribe_stops_email_without_touching_the_inbox() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = Uuid::new_v4();
	let sub = repo.subscriber_for_user(user, "unsub@example.com", true).await.expect("subscriber");
	repo.set_topic_subscription(sub.id, TOPIC, true, true).await.expect("follow");
	repo.emit(user, TOPIC, "k", "t", "", "", "u1", 1).await.expect("emit");

	assert!(repo.unsubscribe(&sub.unsubscribe_token, None).await.expect("unsubscribe"), "a known token unsubscribes");
	assert!(
		!repo.unsubscribe("not-a-real-token", None).await.expect("unknown token"),
		"an unknown token is a clean false, not an error"
	);

	let after = repo.subscriber_for_user(user, "unsub@example.com", true).await.expect("reload");
	assert!(!after.email_enabled, "List-Unsubscribe switches the email channel off");
	assert!(after.in_app_enabled, "…and deliberately leaves the in-app channel alone");
	assert_eq!(repo.unread_count(sub.id).await.expect("count"), 1, "unsubscribing is not account deletion — the inbox survives");
}

#[tokio::test]
async fn delivery_queue_claims_leases_and_backs_off() {
	let Some(repo) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let user = Uuid::new_v4();
	let sub = repo.subscriber_for_user(user, "queue@example.com", true).await.expect("subscriber");
	repo.set_topic_subscription(sub.id, TOPIC, true, true).await.expect("follow");
	// Quiet whatever a shared development database already has queued. `claim_due` takes
	// the OLDEST due rows first, so a backlog left by another suite would fill the batch
	// and hide the row seeded below — a failure with nothing to do with the queue. The
	// long lease keeps the drained rows out of the way for the rest of this test.
	while !repo.claim_due(500, 3600).await.expect("drain the queue").is_empty() {}

	repo.emit(user, TOPIC, "nav", "Queued", "body", "/x", "q1", 100).await.expect("emit");

	// The claim is a `FOR UPDATE SKIP LOCKED` CTE feeding an UPDATE … RETURNING, and
	// the lease is `make_interval(secs => $2)` with a float bind — both runtime-only.
	let claimed = repo.claim_due(50, 300).await.expect("claim");
	let job = claimed.iter().find(|j| j.recipient == "queue@example.com").expect("our job is claimed");
	assert_eq!(job.kind, "notification");
	assert_eq!(job.title.as_deref(), Some("Queued"), "the join carries the notification body through for rendering");
	assert!(!job.unsubscribe_token.is_empty(), "…and the subscriber's unsubscribe token, for the List-Unsubscribe header");
	assert_eq!(job.attempts, 1, "claiming counts an attempt, so a crash mid-send cannot retry forever");

	// The lease hides it from a second dispatcher.
	let again = repo.claim_due(50, 300).await.expect("second claim");
	assert!(again.iter().all(|j| j.id != job.id), "a leased row is invisible until the lease lapses");

	repo.mark_failed(job.id, "smtp exploded", 60, 6).await.expect("mark failed");
	repo.mark_sent(job.id).await.expect("mark sent");
	assert!(repo.sent_last_24h().await.expect("budget read") >= 1, "the daily send budget can see what was sent");
}
