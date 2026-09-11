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
	governance::{AdmissionId, AdmissionVote, ProposalVote, RemovalId, UserProposalId, UserProposalKind, Vote},
	users::{AuthSubject, Email, ProfileFields, User, UserId},
};
use uuid::Uuid;

use crate::{
	genesis::{GenesisOutcome, GenesisSubject},
	infrastructure::{
		governance::{AdmissionRecord, Audit, InvitationRecord, OwnerRow, RemovalRecord, SelfDecision, UserProposalRecord},
		notifications::{DeliveryJob, EmitOutcome, NotificationRow, SubscriberRow, SubscriptionRow},
		platform::{FeatureFlagRow, PlatformConfigRow},
		users::{AdminAction, AdminUserRow, AuthzRecord, Reinstatement},
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
	/// `Admin` was asked for and the target does not hold it. Granting it goes through
	/// the owners; taking it away deliberately does not.
	WouldGrantAdmin,
}

/// What [`UserDirectoryRepository::raise_kyc_level_to`] did.
///
/// "Already holds it" is an ORDINARY answer and not an error: at-least-once webhook
/// delivery makes a verdict for a level the user already reached a routine event, and an
/// `Err` there would put a genuine, correctly-handled delivery into the vendor's retry
/// loop.
pub enum KycLevelChange {
	/// The level moved up, and exactly one `KYC_CHANGED` went to the outbox with it.
	/// `from` is carried for the log line — the decision itself was taken under the row
	/// lock, so nothing downstream may re-derive it with a second read.
	Raised { from: u32, to: u32 },
	/// The user already stood at or above the target, so nothing was written. NOT a
	/// failure: an approval for tier 1 reaching someone who already holds tier 2 is a
	/// correct delivery whose only correct effect is nothing.
	AlreadyHolds(u32),
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

	/// Bump the user's authoritative `token_version` ("revoke all"); emits
	/// SESSIONS_REVOKED and one `admin_action` row in the same transaction.
	async fn revoke_tokens(&self, id: UserId, action: &AdminAction, now: i64) -> Result<User, DomainError>;

	/// Disable a user UNQUALIFIED (freeze sign-in/refresh); emits SUSPENDED.
	///
	/// ⚠️ Records no [`domain::users::Suspension`] and no audit row, so the account reads
	/// as one an admin may lift and one that never lapses. It is the raw brake the
	/// fixtures and the provisioner sit on — a request-driven path calls [`Self::hold_user`]
	/// or opens a suspension proposal, exactly as a role write must go through
	/// [`Self::set_role_outside_ownership`] rather than [`Self::set_role`].
	async fn disable_user(&self, id: UserId) -> Result<User, DomainError>;

	/// One operator's emergency brake: freeze now, lapse in
	/// [`domain::users::HOLD_TTL_SECS`] unless the owners ratify it. Emits SUSPENDED and
	/// one audit row.
	///
	/// This is the reason suspension could not simply become a quorum. The frozen flag is
	/// re-read by the money plane when it dispatches, so a hold stops a withdrawal that is
	/// already queued within a sweep; a quorum by mail takes hours, and a broadcast made
	/// in those hours cannot be undone. Refused over a suspension the owners imposed —
	/// the weaker measure must not be able to restate the stronger one and inherit its
	/// own expiry clock.
	async fn hold_user(&self, id: UserId, action: &AdminAction, now: i64) -> Result<User, DomainError>;

	/// Re-enable a disabled user UNQUALIFIED; emits REINSTATED. The raw writer beneath
	/// [`Self::reinstate_outside_governance`].
	async fn enable_user(&self, id: UserId) -> Result<User, DomainError>;

	/// Re-enable a user, refusing to lift what the OWNERS imposed, with the decision taken
	/// inside the write transaction from the target row held `FOR UPDATE`.
	///
	/// Without the refusal the whole suspension consilium is advisory: the owners vote to
	/// freeze an account and any one admin presses "reinstate". The atomicity is the same
	/// point [`Self::set_role_outside_ownership`] makes — a proposal executing between a
	/// separate read and this write would be invisible to the check.
	async fn reinstate_outside_governance(&self, id: UserId, action: &AdminAction, now: i64) -> Result<Reinstatement, DomainError>;

	/// Release every hold whose deadline has passed, emitting REINSTATED for each so the
	/// money plane unfreezes too. Returns whom it released; `limit` bounds one pass.
	///
	/// The one place this plane sweeps rather than expiring lazily — see the
	/// implementation for why the bridge leaves no choice.
	async fn lapse_due_holds(&self, now: i64, limit: i64) -> Result<Vec<UserId>, DomainError>;

	/// Set a user's KYC level; emits KYC_CHANGED.
	///
	/// Unconditional in DIRECTION only. The aggregate refuses anything above
	/// [`domain::users::MAX_KYC_LEVEL`] and the `users_kyc_level_range` CHECK refuses it
	/// again at the column, so an out-of-range level is not something a caller here can
	/// choose — it comes back as [`DomainError::Validation`].
	///
	/// The ONE writer of the level, whoever decided it: the operator RPC under
	/// `Permission::KycManage` and the identity provider's webhook ([`KycProvider`])
	/// both land here, so the event, the `user_outbox` row and the money plane's mirror
	/// come out identical — and banking never learns that a KYC vendor exists.
	async fn set_kyc_level(&self, id: UserId, level: u32, action: &AdminAction, now: i64) -> Result<User, DomainError>;

	/// RAISE a user's KYC level to `target`, with the "is this actually a raise?"
	/// comparison taken inside the write transaction from the row held `FOR UPDATE`.
	///
	/// The atomicity is the whole point, exactly as in
	/// [`Self::set_role_outside_ownership`]. Read on a separate connection, "is the
	/// target above the current level?" is a TOCTOU window, and the vendor webhook is the
	/// one caller that cannot avoid racing: an operator revoking a level under
	/// `Permission::KycManage` commits in between, the webhook's stale read still says
	/// `0 -> 2`, and it then blocks on the row only to write the level a human had just
	/// taken away — a DOWNGRADE reversed by a vendor, which is the one thing the whole
	/// KYC surface promises cannot happen. Holding the row across the comparison makes the
	/// two paths serialize instead.
	///
	/// This does NOT replace [`Self::set_kyc_level`]; it wraps the same aggregate call in
	/// a monotonic guard. The direction-unconditional writer stays the human path's tool,
	/// because a human under `KycManage` is precisely who is allowed to move a level DOWN.
	///
	/// Taking only the target's row cannot deadlock against the consilium path: that one
	/// acquires the governance revision row, then the owner rows, then the target's, then
	/// the outbox advisory lock — this acquires a suffix of the same order.
	async fn raise_kyc_level_to(&self, id: UserId, target: u32) -> Result<KycLevelChange, DomainError>;

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
	/// `Admin` is refused in the GRANTING direction too, and named to the caller. An
	/// operator who can appoint operators can appoint accomplices, and the seat carries
	/// every identity mutation except role granting — suspending accounts, moving KYC
	/// levels, revoking anyone's sessions. Taking the role AWAY stays one act by design:
	/// containing a rogue operator must never be the slower path.
	///
	/// Taking only the target's row cannot deadlock against the consilium: that path
	/// acquires the governance revision row, then the owner rows, then the target's, then
	/// the outbox advisory lock — this one acquires a suffix of the same order.
	async fn set_role_outside_ownership(&self, id: UserId, role: Role, action: &AdminAction, now: i64) -> Result<RoleChange, DomainError>;

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
/// ONE, because one is what the vendor actually checks. There is a single Didit
/// workflow (`DIDIT_WORKFLOW_ID`) and it verifies a document and a selfie — the tier-1
/// evidence. Tier 2 means "everything in tier 1 plus proof of address and source of
/// funds" (`banking`'s `users.proto`), and no workflow we run asks for either, so a
/// vendor approval is evidence for tier 1 and nothing more. Raising this again is not a
/// constant edit: it is a second workflow id, selected by tier inside
/// `KycProvider::start_session`, and this ceiling is what stops the constant and the
/// vendor drifting apart in the meantime.
///
/// Tier 3 is the ceiling of a human decision (`UserDirectory.SetKycLevel` under
/// `Permission::KycManage`), and so is every downgrade.
///
/// This is also the clamp that retires the cases opened while `/kyc/start` still took
/// the tier from the request body: rows asking for 2 are already in the table, some of
/// them still running, and refusing the tier at the entry point does nothing for a case
/// that was opened yesterday. Clamping where the verdict is APPLIED is what makes those
/// grant a 1 when they land.
///
/// NOT the `kyc_cases_requested_tier` CHECK, which still reads `BETWEEN 1 AND 2` and is
/// meant to: that one bounds the tier a provider may be ASKED for and follows the
/// platform's tier model, this one bounds what an approval may GRANT and follows the
/// configured workflow. `0014_kyc_requested_tier_intent.sql` is the argument.
pub const PROVIDER_MAX_TIER: u32 = 1;

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
	/// A reviewer sent specific steps back to the user. The attempt is RUNNING again,
	/// not finished: no level moves and the case stays open.
	Resubmitted,
	/// The user walked away mid-flow.
	Abandoned,
	Expired,
	/// A previously-approved verification aged out at the vendor.
	KycExpired,
}

impl KycStatus {
	/// Every variant. Two places enumerate this vocabulary against the database — the
	/// adapter rehydrating `kyc_cases.status`, and the "is this user still mid-flow?"
	/// lookup that names the running statuses in SQL — and a hand-written list in either
	/// would fail SILENTLY when a variant is added: an unlisted running status simply
	/// stops counting as running, and the user buys another vendor session.
	pub const ALL: [Self; 9] = [
		Self::Pending,
		Self::InProgress,
		Self::InReview,
		Self::Approved,
		Self::Declined,
		Self::Resubmitted,
		Self::Abandoned,
		Self::Expired,
		Self::KycExpired,
	];

	/// The persisted `kyc_cases.status` vocabulary — kept in step with that column's
	/// CHECK constraint by [`Self::is_decided`]'s test.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::InProgress => "in_progress",
			Self::InReview => "in_review",
			Self::Approved => "approved",
			Self::Declined => "declined",
			Self::Resubmitted => "resubmitted",
			Self::Abandoned => "abandoned",
			Self::Expired => "expired",
			Self::KycExpired => "kyc_expired",
		}
	}

	/// Whether the attempt has stopped moving. Mirrors the `kyc_cases_decision_at`
	/// CHECK: exactly these statuses carry a `decision_at`.
	pub fn is_decided(self) -> bool {
		match self {
			// `Resubmitted` belongs HERE, with the open states: a reviewer asking for
			// specific steps again puts the attempt back in the user's hands, so a
			// `decision_at` on it would claim an outcome that has not happened.
			Self::Pending | Self::InProgress | Self::InReview | Self::Resubmitted => false,
			Self::Approved | Self::Declined | Self::Abandoned | Self::Expired | Self::KycExpired => true,
		}
	}

	/// The level this verdict may RAISE a user to, if any.
	///
	/// Only an approval moves the level, and only upwards. Every failure mode —
	/// declined, abandoned, expired, aged-out — and every mid-flight state leaves it
	/// exactly where it was: someone who holds tier 2 and fails an attempt at a higher
	/// one must not be dropped to zero by a vendor. Downgrades are a human act under
	/// `Permission::KycManage`, and there is no other path to one.
	pub fn grants_tier(self, requested: u32) -> Option<u32> {
		match self {
			Self::Approved => Some(requested.min(PROVIDER_MAX_TIER)),
			Self::Pending | Self::InProgress | Self::InReview | Self::Resubmitted | Self::Declined | Self::Abandoned | Self::Expired | Self::KycExpired => None,
		}
	}
}

/// The headers a provider's webhook authenticates itself with, lifted out of the
/// transport so [`KycProvider::parse_callback`] never sees an `http` type.
pub struct CallbackHeaders {
	/// HMAC-SHA256 of the RAW request body, hex-encoded (Didit: `X-Signature`).
	pub signature: Option<String>,
	/// HMAC-SHA256 of the CANONICALISED body, hex-encoded (Didit: `X-Signature-V2`).
	/// Either signature alone authenticates a delivery — see the adapter's
	/// `verify_signature` for why we accept both rather than picking one.
	pub signature_v2: Option<String>,
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
	/// Unix seconds the vendor stamped INSIDE the signed body — the instant this verdict
	/// was made, as opposed to the instant this delivery happened to arrive.
	///
	/// This is the ordering key [`KycCaseRepository::record_decision`] judges a verdict
	/// by, which is why it is the signed copy and not the `X-Timestamp` header: the
	/// header is unauthenticated, so ordering taken from it could be rewritten by anyone
	/// holding one captured delivery. Non-optional by construction — a body without it is
	/// refused as [`KycCallbackError::Malformed`] before a decision is ever built.
	pub signed_at: i64,
}

/// Why a callback was refused. Every variant is a REJECTION: nothing was written and no
/// level moved.
#[derive(Debug)]
pub enum KycCallbackError {
	/// Missing signature header, or one that does not match the body under the shared
	/// secret.
	BadSignature,
	/// The delivery is outside [`KYC_CALLBACK_WINDOW_SECS`], on the transport header or
	/// on the SIGNED body timestamp, or carries no `X-Timestamp` at all.
	StaleTimestamp,
	/// Not the documented body shape — including a body that carries no `timestamp`.
	/// That one is a REJECTION and not a skipped check: the header copy is unsigned, so
	/// a delivery whose signed body cannot be dated is replayable at any later time.
	Malformed(String),
	/// A signed, in-window, well-formed delivery carrying a status word this adapter
	/// does not know.
	///
	/// Split out from [`Self::Malformed`] because it is not the caller's fault and not
	/// a forgery: the vendor's vocabulary grows, and the day it does, an endpoint that
	/// answers 400 to every delivery is an outage. The route accepts these and changes
	/// nothing — see the handler, which also explains why the log line is `error!`.
	UnknownStatus(String),
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
	/// The delivery is genuine but SUPERSEDED: it describes an older verdict than the one
	/// the case already holds, or it would reopen a case that has finished. Nothing was
	/// written and nothing must follow.
	///
	/// Distinct from [`Self::Redelivered`] on purpose, and the difference decides whether
	/// the caller may still act. A redelivery asserts the state the case IS in, so
	/// re-applying it is idempotent and repairs a first delivery that recorded the status
	/// and then failed to move the level. An ignored delivery asserts a state the case has
	/// LEFT — acting on it would apply a verdict the vendor has already replaced.
	///
	/// Carries the case as it actually stands, never the superseded verdict.
	Ignored(KycCase),
	/// The delivery's [`KycDecision::vendor_data`] names a different case than the one
	/// `provider_ref` resolved to. Nothing was written and nothing must follow.
	///
	/// The check lives inside the write transaction rather than in the handler because it
	/// is a REFUSAL, and a refusal decided after the commit is not one: the cross-check
	/// used to run on the returned case, so a delivery the handler then answered `400` had
	/// already moved the row's `status`, `decision_at` and `payload` (#54).
	///
	/// It outranks [`Self::Redelivered`] and [`Self::Ignored`] deliberately. Those two
	/// classify a delivery we believe; this one says the two ends disagree about what they
	/// are talking about, which makes the delivery untrustworthy about this case in every
	/// reading.
	///
	/// Carries the case as it actually stands, which is also what it stood at before.
	Mismatch(KycCase),
	/// No case for this `(provider, provider_ref)`. Also the shape of the legitimate
	/// race where a webhook overtakes the transaction that opens the case.
	Unknown,
}

/// The caller's still-running attempt, as much of it as `/kyc/start` needs to hand the
/// browser back where it left off.
pub struct LiveCase {
	pub id: Uuid,
	/// Where the vendor sent the browser when this case was opened.
	///
	/// `None` for a row written before `kyc_cases.redirect_url` existed. That case can be
	/// COUNTED but not resumed: the vendor's session URL is not derivable from anything
	/// else we keep, and there is no second call that would fetch it back.
	pub redirect_url: Option<String>,
}

/// What `/kyc/start` must know BEFORE it is allowed to spend a paid vendor session.
pub struct StartGate {
	pub live: Option<LiveCase>,
	/// Attempts this user opened inside the trailing window.
	pub recent: i64,
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
	async fn open_case(&self, id: Uuid, user_id: UserId, provider: &str, provider_ref: &str, requested_tier: u32, redirect_url: &str) -> Result<(), DomainError>;

	/// Read what decides whether this caller may open ANOTHER case: their still-running
	/// attempt, and how many they have opened in the last `window_secs`.
	///
	/// A read, and a deliberately cheap one, because it sits in front of a BILLABLE call.
	/// `/kyc/start` had nothing between the session check and `POST /v3/session/`, so a
	/// signed-in account looping the route drained the platform's Didit quota — and the
	/// degradation past that point is fail-closed, which turns one abusive user into a
	/// verification outage for everyone. This is the read that has to happen first.
	///
	/// NOT a lock and not a reservation: two simultaneous requests can both read "no live
	/// case" and both open one. Serialising them would mean holding a row across a vendor
	/// round trip, and the window cap already bounds what that race can cost.
	async fn start_gate(&self, user_id: UserId, window_secs: i64) -> Result<StartGate, DomainError>;

	/// Apply a verdict to the case it names, if it moves anything.
	///
	/// Ordering is decided here and nowhere else, from [`KycDecision::signed_at`] against
	/// the instant stored with the current status — because arrival order is not send
	/// order. Didit retries a delivery at roughly one and four minutes, so a retried
	/// `in_review` landing after the `approved` that replaced it is routine. A verdict
	/// strictly older than the stored one, and any delivery that would move a finished
	/// case back to a running state, answer [`CaseDecision::Ignored`].
	///
	/// The [`KycDecision::vendor_data`] cross-check is decided here too, and for the same
	/// reason ordering is: it is a REFUSAL, and a refusal has to be reached before the
	/// write it refuses. Answering [`CaseDecision::Mismatch`] is the contract — the
	/// implementation must compare inside the transaction that holds the row, so that a
	/// disagreeing delivery leaves the case exactly where it stood.
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

	/// Write an inbox entry REGARDLESS of what the user follows, and queue no email copy.
	///
	/// [`Self::emit`] is opt-in per topic, which is right for fund news and wrong for a
	/// notice that somebody is asking to move this person's own money: nobody subscribes
	/// to that, and there is no topic every user follows by default. The mail itself has
	/// already gone down the governance queue, which bypasses preferences for the same
	/// reason — this is its in-app trace. The subscriber row is created on first touch, as
	/// [`Self::subscriber_for_user`] does. False when `dedupe_key` had already been used
	/// for this user. Reading is still gated: `in_app_enabled = false` hides it like every
	/// other entry — suppression stays a read-path concern.
	// Positional like `emit` above: the two are the same write with one gate removed, and
	// reading them side by side is the point.
	#[allow(clippy::too_many_arguments)]
	async fn record(
		&self,
		user_id: Uuid,
		email: &str,
		email_verified: bool,
		topic: &str,
		kind: &str,
		title: &str,
		body: &str,
		dedupe_key: &str,
		occurred_at: i64,
	) -> Result<bool, DomainError>;

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

	/// Snapshot the voter set and open a proposal over one PERSON's standing — a permanent
	/// suspension, a reinstatement from one, or the `admin` seat. No token and no mail:
	/// every voter is a signed-in owner, and the subject has no say.
	async fn open_user_proposal(&self, kind: UserProposalKind, subject: UserId, initiator: UserId, reason: &str, now: i64) -> Result<UserProposalRecord, DomainError>;

	async fn find_user_proposal(&self, id: UserProposalId, now: i64) -> Result<Option<UserProposalRecord>, DomainError>;

	/// Every proposal, newest first, optionally narrowed to one kind. Nothing is filtered
	/// out: a rejected, expired or void one stays readable.
	async fn list_user_proposals(&self, kind: Option<UserProposalKind>, limit: i64, now: i64) -> Result<Vec<UserProposalRecord>, DomainError>;

	/// Record one owner's answer and, if the threshold is met, APPLY the verdict — the
	/// status or role write, its cross-plane event and the audit row, all in this
	/// transaction.
	async fn user_proposal_vote(&self, id: UserProposalId, voter: UserId, vote: ProposalVote, now: i64, audit: &Audit) -> Result<UserProposalRecord, DomainError>;

	async fn cancel_user_proposal(&self, id: UserProposalId, by: UserId, now: i64) -> Result<UserProposalRecord, DomainError>;

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
