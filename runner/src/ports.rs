//! Driven ports — the outbound interfaces the runner's services depend on,
//! implemented by `infrastructure`. The hexagonal "domain/port" layer over the
//! generic DDD building blocks in [`domain::architecture`], mirroring banking.
//!
//! [`UserDirectoryRepository`] ties the [`User`] aggregate to its Postgres
//! persistence and the narrow read side ([`Reader`]). Methods are use-case-shaped
//! and each is internally atomic — the aggregate's drained lifecycle events are
//! written to the cross-plane `user_outbox` in the same transaction as the state
//! change (the ACID point), so callers never juggle a transaction across the port
//! boundary. [`PlatformConfigRepository`] is the plain-config port for the
//! platform/cabinet control surface (no aggregate, so no kernel markers).

use async_trait::async_trait;
use domain::{
	architecture::{Reader, Repository},
	authz::Role,
	error::DomainError,
	users::{AuthSubject, Email, ProfileFields, User, UserId},
};
use uuid::Uuid;

use crate::infrastructure::{
	notifications::{DeliveryJob, EmitOutcome, NotificationRow, SubscriberRow, SubscriptionRow},
	platform::{FeatureFlagRow, PlatformConfigRow},
	users::{AdminUserRow, AuthzRecord},
};

/// Persistence + read port for the [`User`] aggregate (the identity control plane).
#[async_trait]
pub trait UserDirectoryRepository: Repository<Aggregate = User> + Reader<Aggregate = User> {
	/// Find a user by canonical id.
	async fn find_by_id(&self, id: UserId) -> Result<Option<User>, DomainError>;

	/// Upsert by the immutable [`AuthSubject`] at sign-in: create (emitting `CREATED`)
	/// or refresh the email. Idempotent for concurrent first-logins.
	async fn provision(&self, subject: AuthSubject, email: Email, email_verified: bool) -> Result<User, DomainError>;

	/// Full-replace the caller's editable profile fields.
	async fn update_profile(&self, id: UserId, fields: ProfileFields) -> Result<User, DomainError>;

	/// Bump the user's authoritative `token_version` ("revoke all"); emits SESSIONS_REVOKED.
	async fn revoke_tokens(&self, id: UserId) -> Result<User, DomainError>;

	/// Disable a user (freeze sign-in/refresh); emits SUSPENDED.
	async fn disable_user(&self, id: UserId) -> Result<User, DomainError>;

	/// Re-enable a disabled user; emits REINSTATED.
	async fn enable_user(&self, id: UserId) -> Result<User, DomainError>;

	/// Set a user's KYC level; emits KYC_CHANGED.
	async fn set_kyc_level(&self, id: UserId, level: u32) -> Result<User, DomainError>;

	/// Set a user's platform access role; emits ROLE_CHANGED across the bridge.
	async fn set_role(&self, id: UserId, role: Role) -> Result<User, DomainError>;

	/// The role + status + authoritative `token_version` the authz gates decide on.
	/// `None` when the user does not exist.
	async fn authz_record(&self, id: UserId) -> Result<Option<AuthzRecord>, DomainError>;

	/// The operator console's user list: filtered + paginated summaries plus the total
	/// matching the filters.
	async fn list(&self, query: &str, role: &str, status: &str, limit: i64, offset: i64) -> Result<(Vec<AdminUserRow>, i64), DomainError>;
}

/// Port for the platform/cabinet control config (maintenance mode, announcement
/// banner, feature flags) — plain config state, not a domain aggregate.
#[async_trait]
pub trait PlatformConfigRepository: Send + Sync {
	async fn config(&self) -> Result<PlatformConfigRow, DomainError>;

	async fn flags(&self) -> Result<Vec<FeatureFlagRow>, DomainError>;

	async fn set_maintenance(&self, enabled: bool) -> Result<(), DomainError>;

	async fn set_announcement(&self, title: &str, body: &str, active: bool) -> Result<(), DomainError>;

	async fn upsert_flag(&self, key: &str, description: &str, enabled: bool, rollout: i32) -> Result<(), DomainError>;
}

/// Port for the notification plane's read/write surface: subscribers, their
/// per-topic subscriptions, and the in-app inbox. Plain control-plane state rather
/// than a domain aggregate, so — like [`PlatformConfigRepository`] — no kernel markers.
///
/// [`Self::emit`] is the one use case that spans two tables; it is internally atomic
/// (inbox row + queued email in one transaction), so callers never hold a transaction
/// across the port boundary.
#[async_trait]
pub trait NotificationRepository: Send + Sync {
	/// The signed-in subscriber for a user, created on first touch and kept in step
	/// with the directory's copy of the address.
	async fn subscriber_for_user(&self, user_id: Uuid, email: &str, email_verified: bool) -> Result<SubscriberRow, DomainError>;

	async fn subscriptions(&self, subscriber_id: Uuid) -> Result<Vec<SubscriptionRow>, DomainError>;

	/// Flip one or both master channel switches. `None` leaves a channel untouched.
	/// Both may end up false — that is the supported "stop contacting me" state.
	async fn set_channel_enabled(&self, subscriber_id: Uuid, in_app: Option<bool>, email: Option<bool>) -> Result<(), DomainError>;

	async fn set_topic_subscription(&self, subscriber_id: Uuid, topic: &str, subscribed: bool, email_enabled: bool) -> Result<(), DomainError>;

	/// Record a notification and queue its email copy if every gate allows it.
	/// Idempotent on `(subscriber, dedupe_key)`.
	#[allow(clippy::too_many_arguments)]
	async fn emit(&self, user_id: Uuid, topic: &str, kind: &str, title: &str, body: &str, link: &str, dedupe_key: &str, occurred_at: i64) -> Result<EmitOutcome, DomainError>;

	/// One page of the inbox, newest first. `cursor` is the last id of the previous page.
	async fn list(&self, subscriber_id: Uuid, cursor: Option<Uuid>, limit: i64, unread_only: bool, topic: Option<&str>) -> Result<Vec<NotificationRow>, DomainError>;

	async fn unread_count(&self, subscriber_id: Uuid) -> Result<i64, DomainError>;

	/// Mark specific ids, or every unread one. Returns the number actually flipped.
	async fn mark_read(&self, subscriber_id: Uuid, ids: &[Uuid], all: bool) -> Result<u64, DomainError>;

	/// Account-less subscribe (double opt-in). Returns the confirmation token ONLY
	/// when a confirmation mail was actually queued — already-confirmed addresses and
	/// throttled repeats both return `None`, and the caller must not tell them apart.
	async fn subscribe_anonymous(&self, email: &str, topic: &str, throttle_secs: i64) -> Result<Option<(Uuid, String)>, DomainError>;

	/// Spend a confirmation token. False when it is unknown or already spent.
	async fn confirm(&self, token: &str) -> Result<bool, DomainError>;

	/// One-click unsubscribe. `None` topic switches the email channel off entirely.
	async fn unsubscribe(&self, token: &str, topic: Option<&str>) -> Result<bool, DomainError>;
}

/// Port for draining the outbound email queue. Split from [`NotificationRepository`]
/// so the background dispatcher depends only on the four calls it actually makes.
#[async_trait]
pub trait NotificationDispatchRepository: Send + Sync {
	/// Claim up to `limit` due jobs, leasing them for `lease_secs` so concurrent
	/// dispatchers never send the same mail twice.
	async fn claim_due(&self, limit: i64, lease_secs: i64) -> Result<Vec<DeliveryJob>, DomainError>;

	async fn mark_sent(&self, delivery_id: i64) -> Result<(), DomainError>;

	/// Reschedule with backoff, or park as `failed` once `max_attempts` is reached.
	async fn mark_failed(&self, delivery_id: i64, error: &str, backoff_secs: i64, max_attempts: i32) -> Result<(), DomainError>;

	/// Sends in the trailing 24h — the input to the daily send-budget breaker.
	async fn sent_last_24h(&self) -> Result<i64, DomainError>;
}
