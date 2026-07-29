//! Postgres adapter for the notification plane.
//!
//! Subscribers, their per-topic subscriptions, the in-app inbox, and the outbound
//! email queue. Runtime queries (not the compile-time macros) keep `cargo build`
//! independent of a live database, mirroring the users and platform adapters.
//!
//! TWO INVARIANTS WORTH KNOWING BEFORE READING THE SQL:
//!
//! 1. `emit` is internally atomic — the inbox row and the email queue row are written
//!    in ONE transaction, so a queued email always has a durable notification behind
//!    it. `notifications_dedupe_idx` is what makes a retried at-least-once emit a
//!    no-op rather than a duplicate mail.
//!
//! 2. The inbox row is written even when in-app delivery is switched off. It is the
//!    durable record of what the platform decided to tell someone, it anchors the
//!    dedupe key, and it means re-enabling the channel restores history instead of
//!    showing a gap. Suppression is therefore a READ-path concern: [`list`] and
//!    [`unread_count`] return nothing while `in_app_enabled` is false.
//!
//! Timestamps cross the boundary as `EXTRACT(EPOCH FROM …)::BIGINT` unix seconds
//! rather than `TIMESTAMPTZ`, matching `AdminUserRow::created_at` — it keeps the
//! sqlx feature set narrow (no `time`/`chrono` decode path).

use async_trait::async_trait;
use domain::error::DomainError;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ports::{NotificationDispatchRepository, NotificationRepository};

pub struct PgNotifications {
	pool: PgPool,
}

impl PgNotifications {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

/// A subscriber — signed-in (`user_id` set) or account-less (`user_id` NULL).
#[derive(Clone, sqlx::FromRow)]
pub struct SubscriberRow {
	pub id: Uuid,
	pub user_id: Option<Uuid>,
	pub email: String,
	pub email_verified: bool,
	pub in_app_enabled: bool,
	pub email_enabled: bool,
	pub confirmed: bool,
	pub unsubscribe_token: String,
}

/// One followed topic.
#[derive(Clone, sqlx::FromRow)]
pub struct SubscriptionRow {
	pub topic: String,
	pub email_enabled: bool,
}

/// One inbox entry.
#[derive(Clone, sqlx::FromRow)]
pub struct NotificationRow {
	pub id: Uuid,
	pub topic: String,
	pub kind: String,
	pub title: String,
	pub body: String,
	pub link: String,
	pub occurred_at: i64,
	pub created_at: i64,
	/// 0 when unread.
	pub read_at: i64,
}

/// What an `emit` actually did. `delivered` is the OR of the channel flags.
#[derive(Clone, Copy, Default)]
pub struct EmitOutcome {
	pub notification_id: Option<Uuid>,
	pub in_app: bool,
	pub email: bool,
	/// The dedupe key had already been used — nothing was written.
	pub deduped: bool,
}

/// One claimed email job, joined with everything the renderer needs.
#[derive(Clone, sqlx::FromRow)]
pub struct DeliveryJob {
	pub id: i64,
	pub kind: String,
	pub recipient: String,
	pub attempts: i32,
	pub unsubscribe_token: String,
	pub confirm_token: Option<String>,
	pub topic: Option<String>,
	pub title: Option<String>,
	pub body: Option<String>,
	pub link: Option<String>,
	pub occurred_at: Option<i64>,
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

/// 24 bytes of OS randomness, hex-encoded — the shape of every opaque token here.
///
/// Generated in Rust rather than with `gen_random_bytes()`: that lives in the
/// `pgcrypto` extension, which is not installed on our cluster, so the SQL version
/// failed at runtime even though the migration itself applied cleanly
/// (`gen_random_uuid()` is core Postgres; `gen_random_bytes()` is not). Minting tokens
/// here also spares the plane any need for rights to create extensions.
fn opaque_token() -> String {
	let mut bytes = [0u8; 24];
	getrandom::fill(&mut bytes).expect("CSPRNG unavailable");
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// NOTE: sqlx 0.9 refuses non-`'static` query strings (its SQL-injection guard), so
// the shared column lists below are repeated verbatim at each call site rather than
// composed with `format!`. Keep `(confirmed_at IS NOT NULL) AS confirmed` in step
// across the two subscriber reads.

#[async_trait]
impl NotificationRepository for PgNotifications {
	async fn subscriber_for_user(&self, user_id: Uuid, email: &str, email_verified: bool) -> Result<SubscriberRow, DomainError> {
		// Lazily created on first touch, then kept in step with the directory's copy of
		// the address. A signed-in subscriber is confirmed on sight: the identity plane
		// only ever holds an address Google already verified, so a second opt-in round
		// trip would be friction with no security value.
		sqlx::query_as::<_, SubscriberRow>(
			"INSERT INTO notification_subscribers (user_id, email, email_verified, confirmed_at, unsubscribe_token) \
			 VALUES ($1, $2, $3, now(), $4) \
			 ON CONFLICT (user_id) WHERE user_id IS NOT NULL \
			 DO UPDATE SET email = EXCLUDED.email, email_verified = EXCLUDED.email_verified, updated_at = now() \
			 RETURNING id, user_id, email, email_verified, in_app_enabled, email_enabled, \
			           (confirmed_at IS NOT NULL) AS confirmed, unsubscribe_token",
		)
		.bind(user_id)
		.bind(email)
		.bind(email_verified)
		.bind(opaque_token())
		.fetch_one(&self.pool)
		.await
		.map_err(repo_err)
	}

	async fn subscriptions(&self, subscriber_id: Uuid) -> Result<Vec<SubscriptionRow>, DomainError> {
		sqlx::query_as::<_, SubscriptionRow>("SELECT topic, email_enabled FROM notification_subscriptions WHERE subscriber_id = $1 ORDER BY topic ASC")
			.bind(subscriber_id)
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)
	}

	async fn set_channel_enabled(&self, subscriber_id: Uuid, in_app: Option<bool>, email: Option<bool>) -> Result<(), DomainError> {
		// COALESCE keeps this one statement for either switch: a NULL bind leaves the
		// column alone, so there is no read-modify-write race between the two channels.
		sqlx::query(
			"UPDATE notification_subscribers \
			 SET in_app_enabled = COALESCE($2, in_app_enabled), email_enabled = COALESCE($3, email_enabled), updated_at = now() \
			 WHERE id = $1",
		)
		.bind(subscriber_id)
		.bind(in_app)
		.bind(email)
		.execute(&self.pool)
		.await
		.map_err(repo_err)?;
		Ok(())
	}

	async fn set_topic_subscription(&self, subscriber_id: Uuid, topic: &str, subscribed: bool, email_enabled: bool) -> Result<(), DomainError> {
		if subscribed {
			sqlx::query(
				"INSERT INTO notification_subscriptions (subscriber_id, topic, email_enabled) VALUES ($1, $2, $3) \
				 ON CONFLICT (subscriber_id, topic) DO UPDATE SET email_enabled = EXCLUDED.email_enabled, updated_at = now()",
			)
			.bind(subscriber_id)
			.bind(topic)
			.bind(email_enabled)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		} else {
			sqlx::query("DELETE FROM notification_subscriptions WHERE subscriber_id = $1 AND topic = $2")
				.bind(subscriber_id)
				.bind(topic)
				.execute(&self.pool)
				.await
				.map_err(repo_err)?;
		}
		Ok(())
	}

	async fn emit(&self, user_id: Uuid, topic: &str, kind: &str, title: &str, body: &str, link: &str, dedupe_key: &str, occurred_at: i64) -> Result<EmitOutcome, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;

		let Some(sub) = sqlx::query_as::<_, SubscriberRow>(
			"SELECT id, user_id, email, email_verified, in_app_enabled, email_enabled, \
			        (confirmed_at IS NOT NULL) AS confirmed, unsubscribe_token \
			 FROM notification_subscribers WHERE user_id = $1",
		)
		.bind(user_id)
		.fetch_optional(&mut *tx)
		.await
		.map_err(repo_err)?
		else {
			// Never touched their notification settings ⇒ no subscriber row ⇒ nothing
			// to deliver. Not an error: emitters fire for every user, not just followers.
			return Ok(EmitOutcome::default());
		};

		let Some(topic_sub) = sqlx::query_as::<_, SubscriptionRow>("SELECT topic, email_enabled FROM notification_subscriptions WHERE subscriber_id = $1 AND topic = $2")
			.bind(sub.id)
			.bind(topic)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?
		else {
			return Ok(EmitOutcome::default());
		};

		// The durable record is written regardless of channel state — see the module
		// header. `DO NOTHING` is what makes a retried emit idempotent.
		let inserted = sqlx::query(
			"INSERT INTO notifications (subscriber_id, topic, kind, title, body, link, dedupe_key, occurred_at) \
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (subscriber_id, dedupe_key) DO NOTHING RETURNING id",
		)
		.bind(sub.id)
		.bind(topic)
		.bind(kind)
		.bind(title)
		.bind(body)
		.bind(link)
		.bind(dedupe_key)
		.bind(occurred_at)
		.fetch_optional(&mut *tx)
		.await
		.map_err(repo_err)?;

		let Some(row) = inserted else {
			tx.commit().await.map_err(repo_err)?;
			return Ok(EmitOutcome {
				deduped: true,
				..Default::default()
			});
		};
		let notification_id: Uuid = row.try_get("id").map_err(repo_err)?;

		let in_app = sub.in_app_enabled;
		// Every one of these has to hold: the master switch, the per-topic copy, a
		// confirmed opt-in, and an address we are actually allowed to mail.
		let email = sub.email_enabled && topic_sub.email_enabled && sub.confirmed && sub.email_verified && !sub.email.is_empty();

		if email {
			sqlx::query(
				"INSERT INTO notification_deliveries (notification_id, subscriber_id, kind, recipient) \
				 VALUES ($1, $2, 'notification', $3)",
			)
			.bind(notification_id)
			.bind(sub.id)
			.bind(&sub.email)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		}

		tx.commit().await.map_err(repo_err)?;
		Ok(EmitOutcome {
			notification_id: Some(notification_id),
			in_app,
			email,
			deduped: false,
		})
	}

	async fn list(&self, subscriber_id: Uuid, cursor: Option<Uuid>, limit: i64, unread_only: bool, topic: Option<&str>) -> Result<Vec<NotificationRow>, DomainError> {
		// Keyset pagination on (created_at, id): the cursor row's own key is resolved in a
		// subquery, so the caller never has to encode or trust a composite cursor.
		//
		// The ORDER BY is table-QUALIFIED for correctness, not neatness. The select list
		// aliases `EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at`, and an unqualified
		// `ORDER BY created_at` binds to that OUTPUT alias — whole seconds — while the WHERE
		// clause can only see the table's microsecond TIMESTAMPTZ. Sorting and paging then
		// disagree, and rows repeat across pages whenever several notifications land in the
		// same second, which a fan-out makes routine.
		// `inbox_paginates_by_keyset_and_marks_read` reproduces it and pins the fix.
		sqlx::query_as::<_, NotificationRow>(
			"SELECT id, topic, kind, title, body, link, occurred_at, \
			        EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, \
			        COALESCE(EXTRACT(EPOCH FROM read_at)::BIGINT, 0) AS read_at \
			 FROM notifications \
			 WHERE subscriber_id = $1 \
			   AND ($2::UUID IS NULL OR (created_at, id) < ROW((SELECT created_at FROM notifications WHERE id = $2), $2)) \
			   AND (NOT $3 OR read_at IS NULL) \
			   AND ($4::TEXT IS NULL OR topic = $4) \
			 ORDER BY notifications.created_at DESC, notifications.id DESC LIMIT $5",
		)
		.bind(subscriber_id)
		.bind(cursor)
		.bind(unread_only)
		.bind(topic)
		.bind(limit)
		.fetch_all(&self.pool)
		.await
		.map_err(repo_err)
	}

	async fn unread_count(&self, subscriber_id: Uuid) -> Result<i64, DomainError> {
		let row = sqlx::query("SELECT count(*) AS n FROM notifications WHERE subscriber_id = $1 AND read_at IS NULL")
			.bind(subscriber_id)
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		row.try_get::<i64, _>("n").map_err(repo_err)
	}

	async fn mark_read(&self, subscriber_id: Uuid, ids: &[Uuid], all: bool) -> Result<u64, DomainError> {
		let result = if all {
			sqlx::query("UPDATE notifications SET read_at = now() WHERE subscriber_id = $1 AND read_at IS NULL")
				.bind(subscriber_id)
				.execute(&self.pool)
				.await
		} else {
			// Scoped by subscriber_id as well as id: an id from another subscriber's
			// inbox must not be markable, even though ids are unguessable UUIDs.
			sqlx::query("UPDATE notifications SET read_at = now() WHERE subscriber_id = $1 AND id = ANY($2) AND read_at IS NULL")
				.bind(subscriber_id)
				.bind(ids)
				.execute(&self.pool)
				.await
		};
		Ok(result.map_err(repo_err)?.rows_affected())
	}

	async fn subscribe_anonymous(&self, email: &str, topic: &str, throttle_secs: i64) -> Result<Option<(Uuid, String)>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;

		// An account-less subscriber starts unconfirmed and email-only. `in_app_enabled`
		// is false because there is no cabinet to show anything in.
		let row = sqlx::query(
			"INSERT INTO notification_subscribers (user_id, email, email_verified, in_app_enabled, email_enabled, confirm_token, unsubscribe_token) \
			 VALUES (NULL, $1, FALSE, FALSE, TRUE, $2, $3) \
			 ON CONFLICT (lower(email)) WHERE user_id IS NULL \
			 DO UPDATE SET updated_at = now() \
			 RETURNING id, confirm_token, confirmed_at IS NOT NULL AS confirmed, \
			           COALESCE(EXTRACT(EPOCH FROM now() - confirm_sent_at)::BIGINT, $4 + 1) AS since_sent",
		)
		.bind(email)
		.bind(opaque_token())
		.bind(opaque_token())
		.bind(throttle_secs)
		.fetch_one(&mut *tx)
		.await
		.map_err(repo_err)?;

		let subscriber_id: Uuid = row.try_get("id").map_err(repo_err)?;
		let confirmed: bool = row.try_get("confirmed").map_err(repo_err)?;
		let since_sent: i64 = row.try_get("since_sent").map_err(repo_err)?;
		let confirm_token: Option<String> = row.try_get("confirm_token").map_err(repo_err)?;

		sqlx::query(
			"INSERT INTO notification_subscriptions (subscriber_id, topic, email_enabled) VALUES ($1, $2, TRUE) \
			 ON CONFLICT (subscriber_id, topic) DO UPDATE SET email_enabled = TRUE, updated_at = now()",
		)
		.bind(subscriber_id)
		.bind(topic)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;

		// Already confirmed ⇒ the subscription is simply added, silently, with no mail.
		// Still inside the throttle window ⇒ no second confirmation mail either. Both
		// paths look identical to the caller, which is what keeps this non-enumerable.
		let should_mail = !confirmed && since_sent > throttle_secs;
		if should_mail {
			sqlx::query("UPDATE notification_subscribers SET confirm_sent_at = now() WHERE id = $1")
				.bind(subscriber_id)
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;
			sqlx::query(
				"INSERT INTO notification_deliveries (notification_id, subscriber_id, kind, recipient) \
				 VALUES (NULL, $1, 'confirm', $2)",
			)
			.bind(subscriber_id)
			.bind(email)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		}

		tx.commit().await.map_err(repo_err)?;
		Ok(if should_mail { confirm_token.map(|t| (subscriber_id, t)) } else { None })
	}

	async fn confirm(&self, token: &str) -> Result<bool, DomainError> {
		// One-shot: the token is cleared as it is spent, so a leaked confirmation link
		// cannot be replayed to re-confirm after an unsubscribe.
		let n = sqlx::query("UPDATE notification_subscribers SET confirmed_at = now(), confirm_token = NULL, email_verified = TRUE, updated_at = now() WHERE confirm_token = $1")
			.bind(token)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?
			.rows_affected();
		Ok(n > 0)
	}

	async fn unsubscribe(&self, token: &str, topic: Option<&str>) -> Result<bool, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let Some(row) = sqlx::query("SELECT id FROM notification_subscribers WHERE unsubscribe_token = $1")
			.bind(token)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?
		else {
			return Ok(false);
		};
		let subscriber_id: Uuid = row.try_get("id").map_err(repo_err)?;

		match topic {
			Some(t) => {
				sqlx::query("DELETE FROM notification_subscriptions WHERE subscriber_id = $1 AND topic = $2")
					.bind(subscriber_id)
					.bind(t)
					.execute(&mut *tx)
					.await
					.map_err(repo_err)?;
			}
			// The List-Unsubscribe contract is "stop mailing me", not "delete my
			// account": the master email switch goes off and every topic copy with it,
			// but the in-app channel and the inbox history are left untouched.
			None => {
				sqlx::query("UPDATE notification_subscribers SET email_enabled = FALSE, updated_at = now() WHERE id = $1")
					.bind(subscriber_id)
					.execute(&mut *tx)
					.await
					.map_err(repo_err)?;
			}
		}

		tx.commit().await.map_err(repo_err)?;
		Ok(true)
	}
}

#[async_trait]
impl NotificationDispatchRepository for PgNotifications {
	async fn claim_due(&self, limit: i64, lease_secs: i64) -> Result<Vec<DeliveryJob>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;

		// SKIP LOCKED lets N dispatchers drain the same queue without coordinating.
		// Pushing `next_attempt_at` forward is the visibility lease: the row stays
		// 'pending', so a dispatcher that dies mid-send simply lets it come due again.
		let claimed = sqlx::query(
			"WITH due AS ( \
			   SELECT id FROM notification_deliveries \
			   WHERE status = 'pending' AND next_attempt_at <= now() \
			   ORDER BY next_attempt_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED \
			 ) \
			 UPDATE notification_deliveries d \
			 SET attempts = d.attempts + 1, next_attempt_at = now() + make_interval(secs => $2) \
			 FROM due WHERE d.id = due.id RETURNING d.id",
		)
		.bind(limit)
		.bind(lease_secs as f64)
		.fetch_all(&mut *tx)
		.await
		.map_err(repo_err)?;

		let ids: Vec<i64> = claimed.iter().map(|r| r.try_get::<i64, _>("id").unwrap_or_default()).collect();
		if ids.is_empty() {
			tx.commit().await.map_err(repo_err)?;
			return Ok(Vec::new());
		}

		let jobs = sqlx::query_as::<_, DeliveryJob>(
			"SELECT d.id, d.kind, d.recipient, d.attempts, s.unsubscribe_token, s.confirm_token, \
			        n.topic, n.title, n.body, n.link, n.occurred_at \
			 FROM notification_deliveries d \
			 JOIN notification_subscribers s ON s.id = d.subscriber_id \
			 LEFT JOIN notifications n ON n.id = d.notification_id \
			 WHERE d.id = ANY($1) ORDER BY d.id ASC",
		)
		.bind(&ids)
		.fetch_all(&mut *tx)
		.await
		.map_err(repo_err)?;

		tx.commit().await.map_err(repo_err)?;
		Ok(jobs)
	}

	async fn mark_sent(&self, delivery_id: i64) -> Result<(), DomainError> {
		sqlx::query("UPDATE notification_deliveries SET status = 'sent', sent_at = now(), last_error = '' WHERE id = $1")
			.bind(delivery_id)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	async fn mark_failed(&self, delivery_id: i64, error: &str, backoff_secs: i64, max_attempts: i32) -> Result<(), DomainError> {
		// The attempt counter was already bumped at claim time, so this only decides
		// whether the row gets another turn or is parked as 'failed'.
		sqlx::query(
			"UPDATE notification_deliveries \
			 SET status = CASE WHEN attempts >= $4 THEN 'failed' ELSE 'pending' END, \
			     next_attempt_at = now() + make_interval(secs => $3), \
			     last_error = left($2, 500) \
			 WHERE id = $1",
		)
		.bind(delivery_id)
		.bind(error)
		.bind(backoff_secs as f64)
		.bind(max_attempts)
		.execute(&self.pool)
		.await
		.map_err(repo_err)?;
		Ok(())
	}

	async fn sent_last_24h(&self) -> Result<i64, DomainError> {
		let row = sqlx::query("SELECT count(*) AS n FROM notification_deliveries WHERE status = 'sent' AND sent_at > now() - interval '24 hours'")
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		row.try_get::<i64, _>("n").map_err(repo_err)
	}
}
