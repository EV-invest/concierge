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
//!
//! [`GovernanceRepository`] is the same contract for the ownership consilium: each
//! method is one use case and is internally atomic, so the verdict, the seat change,
//! the cross-plane `ROLE_CHANGED` and the audit row can never land apart.
//!
//! [`KycProvider`] is the DRIVING side of the same idea for identity verification: the
//! vendor is behind a port so that swapping Didit for Sumsub costs one adapter and
//! nothing else, and so that no vendor type is reachable from a handler.
//! [`KycCaseRepository`] persists the attempts the provider answers about.

use async_trait::async_trait;
use domain::{
	architecture::{Reader, Repository},
	authz::Role,
	error::DomainError,
	governance::{AdmissionId, AdmissionVote, RemovalId, Vote},
	users::{AuthSubject, Email, ProfileFields, User, UserId},
};
use uuid::Uuid;

use crate::{
	genesis::{GenesisOutcome, GenesisSubject},
	infrastructure::{
		governance::{AdmissionRecord, Audit, InvitationRecord, OwnerRow, RemovalRecord, SelfDecision},
		notifications::{DeliveryJob, EmitOutcome, NotificationRow, SubscriberRow, SubscriptionRow},
		platform::{FeatureFlagRow, PlatformConfigRow},
		users::{AdminUserRow, AuthzRecord},
	},
};

/// The verdict of [`UserDirectoryRepository::set_role_outside_ownership`]. A refusal is
/// an ordinary answer rather than an error, so the caller keeps the wording of the two
/// refusals — each names the RPC that DOES do the job — next to the RPC that issues them,
/// instead of threading gRPC vocabulary through the adapter.
pub enum RoleChange {
	/// Boxed only to keep the enum small: the aggregate dwarfs the two refusals, which
	/// carry nothing.
	Applied(Box<User>),
	/// The target holds no seat and `Owner` was asked for.
	WouldGrantOwnership,
	/// The target holds a seat and something other than `Owner` was asked for.
	WouldTakeOwnership,
}

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
	///
	/// The ONE writer of the level, whoever decided it: the operator RPC under
	/// `Permission::KycManage` and the identity provider's webhook ([`KycProvider`])
	/// both land here, so the event, the `user_outbox` row and the money plane's mirror
	/// come out identical — and banking never learns that a KYC vendor exists.
	async fn set_kyc_level(&self, id: UserId, level: u32) -> Result<User, DomainError>;

	/// Set a user's platform access role UNCONDITIONALLY; emits ROLE_CHANGED across the
	/// bridge.
	///
	/// ⚠️ THIS WRITES `owner` IF ASKED TO. It is the raw writer the genesis seed and the
	/// consilium are built on, not a handler's tool — a request-driven path must call
	/// [`Self::set_role_outside_ownership`] instead, or the "exactly two writers of
	/// `owner`" invariant this plane rests on is simply untrue.
	async fn set_role(&self, id: UserId, role: Role) -> Result<User, DomainError>;

	/// Set a role, refusing BOTH directions of ownership, with the decision taken inside
	/// the write transaction from the target row held `FOR UPDATE`.
	///
	/// The atomicity is the point, not a detail. Read on a separate connection, the check
	/// is a TOCTOU window: an admission committing in between is invisible to it, so a
	/// concurrent `SetRole(candidate, "investor")` sees `holds_seat = false`, sails past
	/// both refusals, and then blocks on the row until the consilium commits — stripping
	/// the seat it had just granted, with no consilium, no floor check and no audit row.
	/// Holding the row across the decision makes the two paths serialize instead.
	///
	/// Taking only the target's row cannot deadlock against the consilium: that path
	/// acquires the governance revision row, then the owner rows, then the target's, then
	/// the outbox advisory lock — this one acquires a suffix of the same order.
	async fn set_role_outside_ownership(&self, id: UserId, role: Role) -> Result<RoleChange, DomainError>;

	/// The role + status + authoritative `token_version` the authz gates decide on.
	/// `None` when the user does not exist.
	async fn authz_record(&self, id: UserId) -> Result<Option<AuthzRecord>, DomainError>;

	/// How many people HOLD a seat, counted straight from `users.role`. This is the
	/// number emergency access latches on ([`crate::authz::BreakGlass`]) — never a
	/// count that could include someone merely authorizing as an owner.
	async fn owner_count(&self) -> Result<i64, DomainError>;

	/// The operator console's user list: filtered + paginated summaries plus the total
	/// matching the filters.
	async fn list(&self, query: &str, role: &str, status: &str, limit: i64, offset: i64) -> Result<(Vec<AdminUserRow>, i64), DomainError>;
}

/// The highest level an identity-verification VENDOR may ever cause.
///
/// Tier 3 is the ceiling of a human decision (`UserDirectory.SetKycLevel` under
/// `Permission::KycManage`), and so is every downgrade. Clamping here, in the CHECK on
/// `kyc_cases.requested_tier`, and again where the webhook applies its verdict means a
/// compromised vendor account, a forged case row and a bug would each have to line up
/// before a provider could hand anyone the top tier.
pub const PROVIDER_MAX_TIER: u32 = 2;

/// How long a signed webhook stays acceptable. Past this, a captured-and-replayed
/// delivery is refused on age alone rather than on idempotency.
pub const KYC_CALLBACK_WINDOW_SECS: i64 = 300;

/// A verification session the provider opened: the vendor's handle for it, and the URL
/// the browser is sent to.
pub struct KycSession {
	/// The vendor's own session identifier — stored as `kyc_cases.provider_ref` and the
	/// ONLY thing a callback may resolve a case by.
	pub provider_ref: String,
	/// Where to send the browser to actually perform the verification.
	pub redirect_url: String,
}

/// The vendor-neutral state of one verification attempt.
///
/// Deliberately a closed enum rather than the provider's string: a new vendor status
/// must break the compile at the one place a status is turned into a decision
/// ([`KycStatus::grants_tier`] and its caller), not become a silent no-op in production.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KycStatus {
	/// The session exists but the user has not begun.
	Pending,
	InProgress,
	/// A human at the vendor is looking at it. The level is untouched until they answer.
	InReview,
	Approved,
	Declined,
	/// The user walked away mid-flow.
	Abandoned,
	Expired,
	NotFinished,
	/// A previously-approved verification aged out at the vendor.
	KycExpired,
}

impl KycStatus {
	/// The persisted `kyc_cases.status` vocabulary — kept in step with that column's
	/// CHECK constraint by [`Self::is_decided`]'s test.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::InProgress => "in_progress",
			Self::InReview => "in_review",
			Self::Approved => "approved",
			Self::Declined => "declined",
			Self::Abandoned => "abandoned",
			Self::Expired => "expired",
			Self::NotFinished => "not_finished",
			Self::KycExpired => "kyc_expired",
		}
	}

	/// Whether the attempt has stopped moving. Mirrors the `kyc_cases_decision_at`
	/// CHECK: exactly these statuses carry a `decision_at`.
	pub fn is_decided(self) -> bool {
		match self {
			Self::Pending | Self::InProgress | Self::InReview => false,
			Self::Approved | Self::Declined | Self::Abandoned | Self::Expired | Self::NotFinished | Self::KycExpired => true,
		}
	}

	/// The level this verdict may RAISE a user to, if any.
	///
	/// Only an approval moves the level, and only upwards. Every failure mode —
	/// declined, abandoned, expired, unfinished, aged-out — leaves it exactly where it
	/// was: someone who holds tier 2 and fails an attempt at a higher one must not be
	/// dropped to zero by a vendor. Downgrades are a human act under
	/// `Permission::KycManage`, and there is no other path to one.
	pub fn grants_tier(self, requested: u32) -> Option<u32> {
		match self {
			Self::Approved => Some(requested.min(PROVIDER_MAX_TIER)),
			Self::Pending | Self::InProgress | Self::InReview | Self::Declined | Self::Abandoned | Self::Expired | Self::NotFinished | Self::KycExpired => None,
		}
	}
}

/// The headers a provider's webhook authenticates itself with, lifted out of the
/// transport so [`KycProvider::parse_callback`] never sees an `http` type.
pub struct CallbackHeaders {
	/// HMAC-SHA256 of the RAW request body, hex-encoded (Didit: `X-Signature`).
	pub signature: Option<String>,
	/// Unix seconds the provider claims to have sent at (Didit: `X-Timestamp`).
	pub timestamp: Option<i64>,
}

/// One provider verdict, already stripped of everything we refuse to hold.
pub struct KycDecision {
	/// The vendor's session id. The case is looked up by THIS and nothing else.
	pub provider_ref: String,
	pub status: KycStatus,
	/// The opaque correlation value we handed the vendor at session start (the case
	/// id). Usable ONLY as a cross-check against the row found by `provider_ref` — it
	/// arrives in the request body and is therefore attacker-controlled input, never an
	/// identity.
	pub vendor_data: String,
	/// Allowlisted decision METADATA for `kyc_cases.payload` — document country, document
	/// type, per-check outcomes. Never documents, images, or document numbers.
	pub metadata: serde_json::Value,
}

/// Why a callback was refused. Every variant is a REJECTION: nothing was written and no
/// level moved.
#[derive(Debug)]
pub enum KycCallbackError {
	/// Missing signature header, or one that does not match the body under the shared
	/// secret.
	BadSignature,
	/// The delivery is outside [`KYC_CALLBACK_WINDOW_SECS`], or carries no usable
	/// timestamp at all.
	StaleTimestamp,
	/// Not the documented body shape, or a status string the closed [`KycStatus`] does
	/// not know.
	Malformed(String),
}

/// Driving port for an identity-verification vendor.
///
/// The vendor is young and the platform may well outlive our choice of it, so the whole
/// integration is two methods: open a session, and turn a signed callback into a
/// verdict. No vendor type crosses this boundary, and no user identifier crosses it
/// outbound either — the vendor is handed the CASE id, never a user id, so a breach at
/// the vendor yields correlation handles rather than our identity space.
#[async_trait]
pub trait KycProvider: Send + Sync {
	/// The `kyc_cases.provider` key this adapter writes and looks cases up by.
	fn name(&self) -> &'static str;

	/// Open a verification session for an already-opened case.
	async fn start_session(&self, case_id: Uuid, requested_tier: u32) -> Result<KycSession, DomainError>;

	/// Authenticate and parse one webhook delivery.
	///
	/// I/O-FREE by contract — signature check, replay window and parsing only, with the
	/// clock passed in. It touches no network and no database, so the security-critical
	/// half of this integration is a pure function a test can hammer without standing
	/// anything up.
	fn parse_callback(&self, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError>;
}

/// One verification attempt, as much of it as a decision needs.
pub struct KycCase {
	pub id: Uuid,
	/// Read from the STORED row — the reason this table exists. The callback is
	/// unauthenticated and its body carries no identity we would believe.
	pub user_id: UserId,
	pub requested_tier: u32,
	pub status: KycStatus,
}

/// What [`KycCaseRepository::record_decision`] did.
pub enum CaseDecision {
	/// The case moved to a new status. Only this arm may lead to a level change.
	Recorded(KycCase),
	/// The case was already in this status — an at-least-once redelivery. Nothing was
	/// written and nothing must follow, or a replayed `Approved` would re-emit
	/// `KYC_CHANGED` onto the cross-plane outbox.
	Redelivered(KycCase),
	/// No case for this `(provider, provider_ref)`. Also the shape of the legitimate
	/// race where a webhook overtakes the transaction that opens the case.
	Unknown,
}

/// Persistence port for verification attempts.
///
/// [`Self::record_decision`] is internally atomic and single-shot: it takes the case row
/// `FOR UPDATE`, decides from THAT read whether the status actually transitions, and
/// writes at most once — so concurrent redeliveries of the same event serialize into one
/// [`CaseDecision::Recorded`] and any number of [`CaseDecision::Redelivered`].
#[async_trait]
pub trait KycCaseRepository: Send + Sync {
	/// Record a started attempt. `id` is minted by the caller because it is also the
	/// correlation value handed to the vendor.
	async fn open_case(&self, id: Uuid, user_id: UserId, provider: &str, provider_ref: &str, requested_tier: u32) -> Result<(), DomainError>;

	/// Apply a verdict to the case it names, if it moves anything.
	async fn record_decision(&self, provider: &str, decision: &KycDecision) -> Result<CaseDecision, DomainError>;
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

/// Persistence + read port for the ownership consilium (the `OwnerRemoval` aggregate
/// and the roster it is decided against).
///
/// `now` is passed in rather than read here so the domain layer stays clock-free and
/// every decision is reproducible from its inputs.
#[async_trait]
pub trait GovernanceRepository: Send + Sync {
	/// The current owner roster, oldest seat first.
	async fn owners(&self) -> Result<Vec<OwnerRow>, DomainError>;

	/// Snapshot the peer set, mint the target's token, and queue their invitation —
	/// one transaction, so `target_notified` can never claim a message nobody queued.
	async fn open_removal(&self, target: UserId, initiator: UserId, reason: &str, now: i64) -> Result<RemovalRecord, DomainError>;

	async fn find_removal(&self, id: RemovalId, now: i64) -> Result<Option<RemovalRecord>, DomainError>;

	/// Every proposal, newest first. Nothing is filtered out: a rejected, expired or
	/// void one stays readable.
	async fn list_removals(&self, limit: i64, now: i64) -> Result<Vec<RemovalRecord>, DomainError>;

	/// Record one peer's answer and carry the verdict if it passed.
	async fn peer_vote(&self, id: RemovalId, voter: UserId, vote: Vote, now: i64, audit: &Audit) -> Result<RemovalRecord, DomainError>;

	async fn cancel_removal(&self, id: RemovalId, by: UserId, now: i64) -> Result<RemovalRecord, DomainError>;

	/// Snapshot the voter set and open a proposal to GRANT a seat. No token and no mail:
	/// every voter is a signed-in owner, and the candidate has no say.
	async fn open_admission(&self, candidate: UserId, initiator: UserId, reason: &str, now: i64) -> Result<AdmissionRecord, DomainError>;

	async fn find_admission(&self, id: AdmissionId, now: i64) -> Result<Option<AdmissionRecord>, DomainError>;

	/// Every admission, newest first. Nothing is filtered out.
	async fn list_admissions(&self, limit: i64, now: i64) -> Result<Vec<AdmissionRecord>, DomainError>;

	/// Record one owner's answer and grant the seat if the vote was unanimous.
	async fn admission_vote(&self, id: AdmissionId, voter: UserId, vote: AdmissionVote, now: i64, audit: &Audit) -> Result<AdmissionRecord, DomainError>;

	async fn cancel_admission(&self, id: AdmissionId, by: UserId, now: i64) -> Result<AdmissionRecord, DomainError>;

	/// The redacted invitation behind an emailed token. STRICTLY read-only.
	async fn invitation(&self, token: &str, now: i64) -> Result<Option<InvitationRecord>, DomainError>;

	/// The target answering from their mailbox: attempt-counted, constant-time and
	/// one-shot.
	async fn self_decision(&self, token: &str, code: &str, vote: Vote, now: i64, audit: &Audit) -> Result<SelfDecision, DomainError>;

	/// Give up a seat voluntarily. Subject to the same floor as a removal.
	async fn resign(&self, who: UserId, now: i64) -> Result<(), DomainError>;

	/// The live feed's clock, read straight from Postgres.
	async fn revision(&self) -> Result<u64, DomainError>;

	/// Queue one governance mail to a resolved recipient, bypassing notification
	/// preferences. False when `dedupe_key` had already been accepted.
	async fn enqueue_mail(&self, user_id: Uuid, recipient: &str, kind: &str, dedupe_key: &str, payload: &serde_json::Value) -> Result<bool, DomainError>;
}

/// Port for the one-shot genesis seeding of the owner registry.
///
/// Split from [`GovernanceRepository`] because it is not a consilium use case and has
/// exactly one caller — the composition root, once per boot. Like every method there,
/// it is internally atomic: the roster check, the resolution and every seat it grants
/// are ONE transaction under the governance lock, so two replicas booting together
/// cannot seat the fund twice.
#[async_trait]
pub trait OwnerGenesisRepository: Send + Sync {
	/// Seat `subjects` iff the registry is still empty and at least
	/// [`domain::governance::MIN_OWNERS`] of them resolve to an existing user. Returns
	/// what happened; the caller does the logging, so the branches stay assertable in a
	/// test rather than only readable in a log.
	async fn seed_owners(&self, subjects: &[GenesisSubject]) -> Result<GenesisOutcome, DomainError>;
}
