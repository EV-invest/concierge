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
//! [`GrantRepository`] holds grants over tenant namespaces (`domain::iam`). Each write
//! decides the actor's authority inside its own transaction, for the same TOCTOU reason
//! `set_role_outside_ownership` does, and returns a refusal as an ordinary answer.
//!
//! [`KycProvider`] is the DRIVING side of the same idea for identity verification: the
//! vendor is behind a port so that swapping Didit for Sumsub costs one adapter and
//! nothing else, and so that no vendor type is reachable from a handler.
//! [`KycCaseRepository`] persists the attempts the provider answers about.

use async_trait::async_trait;
use domain::{
	architecture::{Reader, Repository},
	auth::ProvenIdentity,
	authz::Role,
	error::DomainError,
	governance::{AdmissionId, AdmissionVote, ProposalVote, RemovalId, UserProposalId, UserProposalKind, Vote},
	iam::{Catalog, Target},
	users::{Email, ProfileFields, User, UserId, Username},
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

/// Who is granting.
pub struct GrantActor {
	/// The grant's `granted_by`.
	pub id: UserId,
	/// The seat the RBAC gate resolved. Only the lock-free precheck and the rate limit
	/// trust it; the write re-reads the persisted seat under the actor's row lock.
	pub role: Role,
	/// Whether emergency access elevates this caller (`authz::Elevation::elevates`). It is
	/// the one part of the effective role no row records, so it travels explicitly.
	pub elevated: bool,
}

/// Whose grant: by id, or by a handle a delegate already knows — an email or a username,
/// resolved by `infrastructure::users::account_named`. A delegate may not grant by id.
pub enum GrantSubject {
	Id(UserId),
	Account(String),
}

impl GrantSubject {
	/// For a NOT_FOUND message — the caller's own input, echoed back.
	pub fn describe(&self) -> String {
		match self {
			Self::Id(id) => id.to_string(),
			Self::Account(handle) => handle.clone(),
		}
	}
}

/// The actor's say over one namespace's grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantAuthority {
	/// A seat holding `iam:tenants:grant`: any target, told why an address fails.
	Seat,
	/// The holder of an alias the catalog lets delegate: only what it delegates, by email,
	/// told nothing about an address.
	Delegate,
	None,
}

/// What [`GrantRepository::grant`] did.
pub enum GrantOutcome {
	/// The grant now in effect — new, or already held.
	Granted(GrantRecord),
	/// The actor may not grant this target, or addressed the subject by id as a delegate.
	Denied,
	/// The subject is the actor.
	ToSelf,
	/// No tenant owns the target's namespace. Said only to a seat.
	UnknownTenant,
	/// The tenant's current catalog defines nothing the target names.
	UndefinedTarget,
	/// The account is disabled; a grant to it would wake up on reinstatement without
	/// anyone having decided that. Said only to a seat.
	TargetDisabled,
	/// The handle names several accounts. Said only to a seat.
	AmbiguousAccount,
	/// A delegate's address cannot be granted, for a reason they are not told: telling
	/// "nobody holds it" from "several accounts do" from "that account is disabled" would
	/// let anyone with a delegating alias ask the plane about any address (banking#447).
	/// The cause travels for the log line only.
	Ungrantable(UngrantableAddress),
}

/// Why a delegate's address could not be granted — for the operator's log, never for the
/// caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UngrantableAddress {
	NoAccount,
	SharedByAccounts,
	AccountNotActive,
}

impl UngrantableAddress {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::NoAccount => "no_account",
			Self::SharedByAccounts => "shared_by_accounts",
			Self::AccountNotActive => "account_not_active",
		}
	}
}

/// What [`GrantRepository::revoke`] did.
pub enum RevokeOutcome {
	Revoked,
	/// The subject holds no active grant of the target — including an id or email that
	/// names no account, so a revoke is never an existence oracle.
	NotHeld,
	Denied,
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

/// One grant of a target inside a tenant namespace (`grants`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRecord {
	pub id: i64,
	pub user_id: UserId,
	pub target: String,
	pub granted_by: UserId,
	pub granted_at: i64,
	pub reason: Option<String>,
}

/// An active grant with the holder's identity beside it.
pub struct GrantHolderRecord {
	pub grant: GrantRecord,
	pub email: Option<String>,
	pub username: Option<String>,
	pub legal_name: Option<String>,
	pub preferred_name: Option<String>,
}

/// A tenant's current catalog and how it treats seats.
pub struct TenantCatalog {
	pub namespace: String,
	/// `tenants.granting_seats_hold_all`.
	pub granting_seats_hold_all: bool,
	pub catalog: Catalog,
}

/// What [`GrantRepository::publish`] did.
pub enum PublishOutcome {
	Published,
	/// The stored catalog is this one.
	Unchanged,
	/// Older than the stored one, or the same version with different content.
	Stale {
		stored: u64,
	},
}

/// Grants over tenant namespaces, and the catalogs that give them meaning.
#[async_trait]
pub trait GrantRepository: Send + Sync {
	/// The actor's say over `namespace` right now, from their persisted record — for reads,
	/// which need no lock.
	async fn authority(&self, actor: &GrantActor, namespace: &str) -> Result<GrantAuthority, DomainError>;

	/// The actor's seat and status, their own grants, and the subject's row are all read
	/// inside the write transaction, and authority is settled before the subject is looked
	/// at. `NotFound` for an unknown subject, said only to a seat.
	async fn grant(&self, subject: &GrantSubject, target: &Target, actor: &GrantActor, action: &AdminAction, now: i64) -> Result<GrantOutcome, DomainError>;

	async fn revoke(&self, subject: &GrantSubject, target: &Target, actor: &GrantActor, action: &AdminAction, now: i64) -> Result<RevokeOutcome, DomainError>;

	/// Every active grant inside `namespace`, oldest first. `None`: no such tenant.
	async fn holders(&self, namespace: &str) -> Result<Option<Vec<GrantHolderRecord>>, DomainError>;

	/// The active targets `user` holds, in every namespace.
	async fn targets_of(&self, user: UserId) -> Result<Vec<Target>, DomainError>;

	/// The current catalog of every tenant that has one.
	async fn catalogs(&self) -> Result<Vec<TenantCatalog>, DomainError>;

	/// The current catalog of `namespace`. `None`: no tenant, or it never published.
	async fn catalog(&self, namespace: &str) -> Result<Option<TenantCatalog>, DomainError>;

	/// The namespace of the tenant whose client's tokens carry `audience`.
	async fn audience_namespace(&self, audience: &str) -> Result<Option<String>, DomainError>;

	/// Keep `catalog` as `namespace`'s current one, published by `client_id`, unless it is
	/// not newer than the stored one.
	async fn publish(&self, namespace: &str, client_id: &str, catalog: &Catalog, now: i64) -> Result<PublishOutcome, DomainError>;
}

/// A registered relying party (`rp_clients`).
#[derive(Clone, Debug)]
pub struct ClientRecord {
	pub client_id: String,
	/// The `aud` its access tokens carry.
	pub audience: String,
	/// Exact redirect URIs. Compared byte for byte, never by prefix.
	pub redirect_uris: Vec<String>,
	/// SHA-256 of the client secret; `None` until the operator sets one, and a client
	/// without one can obtain no token.
	pub secret_hash: Option<Vec<u8>>,
	pub disabled: bool,
	/// The tenant namespace whose catalog it publishes and whose permissions its tokens read.
	pub namespace: String,
}

/// A one-time authorization code to store (`rp_codes`). Only its digest is persisted.
pub struct NewCode<'a> {
	pub code_hash: &'a [u8],
	pub client_id: &'a str,
	pub redirect_uri: &'a str,
	pub code_challenge: &'a str,
	pub user: UserId,
	pub token_version: u64,
	/// The `evinvest.ltd` refresh family the browser was signed in with; the session
	/// the code opens inherits it, so signing out there ends it.
	pub upstream_family: &'a str,
	pub issued_at: i64,
	pub expires_at: i64,
	pub client_ip: &'a str,
	pub user_agent: &'a str,
}

/// A presented code, as the client presented it (the verifier already hashed to the
/// challenge it must match).
pub struct CodeClaim<'a> {
	pub code_hash: &'a [u8],
	pub client_id: &'a str,
	pub redirect_uri: &'a str,
	pub challenge_of_verifier: &'a str,
	pub now: i64,
}

/// What [`RelyingPartyRepository::claim_code`] found. Every arm but `Unknown` has burned
/// the code.
pub enum CodeOutcome {
	Redeemed {
		user: UserId,
		token_version: u64,
	},
	Unknown,
	Expired,
	/// Bound to another client, redirect_uri or PKCE challenge.
	Mismatch,
	/// Presented after it was already redeemed; the sessions it opened are now revoked.
	Replayed {
		client_id: String,
		user: UserId,
		revoked_sessions: u64,
	},
}

/// A refresh family to open for a redeemed code (`rp_sessions`).
pub struct NewSession<'a> {
	pub id: Uuid,
	pub client_id: &'a str,
	pub user: UserId,
	pub code_hash: &'a [u8],
	pub secret_hash: &'a [u8],
	pub token_version: u64,
	pub now: i64,
	pub expires_at: i64,
	pub absolute_expires_at: i64,
}

/// A refresh family as stored.
pub struct SessionRow {
	pub client_id: String,
	pub user: UserId,
	pub current_hash: Vec<u8>,
	pub prev_hash: Option<Vec<u8>>,
	pub token_version: u64,
	pub expires_at: i64,
	pub absolute_expires_at: i64,
	pub revoked: bool,
}

/// Why a family was revoked — the `rp_sessions_revoked_reason` vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRevocation {
	/// A rotated-out refresh secret was presented: theft.
	RefreshReuse,
	/// The user no longer passes the client's policy, or the account is suspended.
	AccessDenied,
	/// The user's `token_version` moved past the family's ("revoke all").
	TokensRevoked,
	/// The `evinvest.ltd` session it was authorized by ended — single logout.
	UpstreamRevoked,
}

impl SessionRevocation {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::RefreshReuse => "refresh_reuse",
			Self::AccessDenied => "access_denied",
			Self::TokensRevoked => "tokens_revoked",
			Self::UpstreamRevoked => "upstream_revoked",
		}
	}
}

/// Relying parties: the client registry, one-time codes and refresh families. Each
/// method is internally atomic.
#[async_trait]
pub trait RelyingPartyRepository: Send + Sync {
	async fn client(&self, client_id: &str) -> Result<Option<ClientRecord>, DomainError>;

	/// Every registered client, for the boot's secret sync and verifier audiences.
	async fn clients(&self) -> Result<Vec<ClientRecord>, DomainError>;

	/// Store (or clear) a client's secret digest. Returns whether it changed.
	async fn set_secret_hash(&self, client_id: &str, secret_hash: Option<&[u8]>, now: i64) -> Result<bool, DomainError>;

	/// Store a code, reaping ones long past their expiry.
	async fn issue_code(&self, code: NewCode<'_>) -> Result<(), DomainError>;

	/// Burn a presented code and say what it was — or, if it was already burned, mark it
	/// replayed and revoke the families it opened.
	async fn claim_code(&self, claim: CodeClaim<'_>) -> Result<CodeOutcome, DomainError>;

	/// Open a family for a redeemed code. `false` when the code was replayed since it was
	/// claimed — nothing is opened then.
	async fn open_session(&self, session: NewSession<'_>) -> Result<bool, DomainError>;

	async fn session(&self, id: Uuid) -> Result<Option<SessionRow>, DomainError>;

	/// Rotate a family from `presented_hash` to `next_hash`. `false` when the family moved
	/// on or was revoked since it was read.
	async fn rotate_session(&self, id: Uuid, presented_hash: &[u8], next_hash: &[u8], expires_at: i64, now: i64) -> Result<bool, DomainError>;

	async fn revoke_session(&self, id: Uuid, reason: SessionRevocation, now: i64) -> Result<(), DomainError>;

	/// Single logout: expire `user`'s outstanding codes and revoke their live sessions —
	/// those authorized by `upstream_family`, or all of them when it is `None`. Returns
	/// how many sessions ended.
	async fn revoke_upstream(&self, user: UserId, upstream_family: Option<&str>, now: i64) -> Result<u64, DomainError>;

	/// Whether an access token issued under family `id` for `audience` may still be
	/// honoured: the family is live and belongs to a client with that audience.
	async fn session_live(&self, id: Uuid, audience: &str, now: i64) -> Result<bool, DomainError>;
}

/// Persistence + read port for the [`User`] aggregate (the identity control plane).
#[async_trait]
pub trait UserDirectoryRepository: Repository<Aggregate = User> + Reader<Aggregate = User> {
	/// Find a user by canonical id.
	async fn find_by_id(&self, id: UserId) -> Result<Option<User>, DomainError>;

	/// The account a sign-in opens — the ONE linking rule every non-password method lands
	/// in, decided under advisory locks on the subject and the mailbox:
	///
	/// 1. a linked provider subject opens its account (the email follows the provider's,
	///    never downgrading a verified one, never onto an address another account proved);
	/// 2. a proven mailbox opens the account it is verified on;
	/// 3. a proven mailbox takes over the account that registered it UNVERIFIED with a
	///    password: sessions revoked, password dropped, address verified;
	/// 4. otherwise a new account (`CREATED`), verified iff the mailbox was proven.
	///
	/// A provider subject is linked to whichever account 2-4 picked.
	async fn resolve(&self, identity: ProvenIdentity, now: i64) -> Result<User, DomainError>;

	/// The caller's chosen handle. [`DomainError::Conflict`] when somebody holds it.
	async fn set_username(&self, id: UserId, username: Username) -> Result<User, DomainError>;

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
	/// own expiry clock. Refused, too, while a hold is live or within
	/// [`domain::users::HOLD_COOLDOWN_SECS`] of one ending, unless a suspension proposal
	/// about the account is open — decided under the row lock, like the rest. `by` is
	/// the actor, whose PERSISTED role and status are read inside that same transaction:
	/// an admin or owner seat is held only by an owner, a role resolved on another
	/// connection before the lock could be one the owners had just revoked, and an actor
	/// held in that same window holds nobody.
	async fn hold_user(&self, id: UserId, action: &AdminAction, by: UserId, now: i64) -> Result<User, DomainError>;

	/// Re-enable a disabled user UNQUALIFIED; emits REINSTATED. The raw writer beneath
	/// [`Self::reinstate_outside_governance`]. `now` is when a lifted hold is recorded as
	/// having ended — capped at its deadline, if that came first.
	async fn enable_user(&self, id: UserId, now: i64) -> Result<User, DomainError>;

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
	/// `Kyc::Manage` and the identity provider's webhook ([`KycProvider`])
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
	/// `Kyc::Manage` commits in between, the webhook's stale read still says
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
	/// `action` carries no actor: no human decided this. Its `detail` is where the
	/// decision's provenance goes — which provider, which case — so the vendor half of a
	/// user's KYC history lands in the same log the manual half does, answering the same
	/// question in the same shape (#48). `from` and `to` are filled in by the adapter,
	/// which is the only place that knows what the level was under the row lock.
	async fn raise_kyc_level_to(&self, id: UserId, target: u32, action: &AdminAction, now: i64) -> Result<KycLevelChange, DomainError>;

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
/// `Kyc::Manage`), and so is every downgrade.
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
	/// NOT one of the vendor's words, and the only status this plane writes on its own:
	/// an approval reached on a document that has ALREADY granted a level to a different
	/// account (#51). DECIDED on purpose — it carries a `decision_at` and stops the case
	/// running — because the vendor has spoken its last word on this session and nothing
	/// will ever move the row again. Leaving it in a running state instead would have
	/// cleared `decision_at` on a case the vendor had already finished, and would have
	/// pinned `/kyc/start` to a session the user cannot use, with no operator handle to
	/// release it. It grants no level; an operator raises one with `SetKycLevel` if the
	/// duplicate turns out to have an honest explanation.
	HeldDuplicate,
}

impl KycStatus {
	/// Every variant. Two places enumerate this vocabulary against the database — the
	/// adapter rehydrating `kyc_cases.status`, and the "is this user still mid-flow?"
	/// lookup that names the running statuses in SQL — and a hand-written list in either
	/// would fail SILENTLY when a variant is added: an unlisted running status simply
	/// stops counting as running, and the user buys another vendor session.
	pub const ALL: [Self; 10] = [
		Self::Pending,
		Self::InProgress,
		Self::InReview,
		Self::Approved,
		Self::Declined,
		Self::Resubmitted,
		Self::Abandoned,
		Self::Expired,
		Self::KycExpired,
		Self::HeldDuplicate,
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
			Self::HeldDuplicate => "held_duplicate",
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
			Self::Approved | Self::Declined | Self::Abandoned | Self::Expired | Self::KycExpired | Self::HeldDuplicate => true,
		}
	}

	/// Whether a case sitting in this status may be retired by `KYC_CASE_TTL_SECS` —
	/// i.e. whether waiting on it is waiting on the USER.
	///
	/// The clock the TTL runs on is the case's LAST MOVEMENT, not its creation: two of
	/// these three statuses are written by the vendor, so a row holding one is proof of
	/// an exchange that happened. Measured from creation, a `resubmitted` a reviewer
	/// returns on day two would be stale the second it was written.
	///
	/// `pending` in particular is the status a case is opened in and the one it never
	/// leaves when the user closes the tab at the vendor: Didit sends no event for a
	/// session nobody began, so nothing else in this plane would ever move that row
	/// (#91). Without an age bound it stays RUNNING for ever, `start_gate` keeps handing
	/// it back, and a tier-0 user whose row also carries no usable `redirect_url` can
	/// neither continue nor start again — the cabinet's Start button is disabled by a
	/// case no event will ever close.
	///
	/// `InReview` is deliberately NOT here. A human at the vendor is holding that case,
	/// their queue is not the user's fault, and retiring one behind their back would open
	/// a second billed session for an attempt that is about to be answered.
	///
	/// A DECIDED status is not abandonable either: it has stopped running, so there is
	/// nothing left to retire.
	pub fn is_abandonable(self) -> bool {
		match self {
			Self::Pending | Self::InProgress | Self::Resubmitted => true,
			Self::InReview => false,
			Self::Approved | Self::Declined | Self::Abandoned | Self::Expired | Self::KycExpired | Self::HeldDuplicate => false,
		}
	}

	/// The level this verdict may RAISE a user to, if any.
	///
	/// Only an approval moves the level, and only upwards. Every failure mode —
	/// declined, abandoned, expired, aged-out — and every mid-flight state leaves it
	/// exactly where it was: someone who holds tier 2 and fails an attempt at a higher
	/// one must not be dropped to zero by a vendor. Downgrades are a human act under
	/// `Kyc::Manage`, and there is no other path to one.
	pub fn grants_tier(self, requested: u32) -> Option<u32> {
		match self {
			Self::Approved => Some(requested.min(PROVIDER_MAX_TIER)),
			Self::Pending | Self::InProgress | Self::InReview | Self::Resubmitted | Self::Declined | Self::Abandoned | Self::Expired | Self::KycExpired | Self::HeldDuplicate => None,
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
	/// A keyed one-way fingerprint of the DOCUMENT this verdict was reached on, and the
	/// only cross-account handle this plane holds (#51).
	///
	/// A field of its own rather than a key in [`Self::metadata`], because `metadata`'s
	/// discipline is "copy nothing the allowlist does not name" and its home is a JSON
	/// blob. This has a column, an index and a question it answers.
	///
	/// `None` whenever it could not be computed — no pepper configured, or a verdict
	/// carrying no document number. Absence disables DETECTION and never a decision: the
	/// level still moves exactly as it did.
	pub identity_digest: Option<String>,
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

	/// The origins — `scheme://host[:port]`, as WHATWG serialises them — that this
	/// adapter's [`KycSession::redirect_url`] may point at. `/kyc/start` refuses any
	/// answer outside this set rather than sending a signed-in browser to it.
	///
	/// Asked of the PROVIDER and not read from configuration beside it, because the two
	/// are the same fact and a second copy is a copy that drifts. The adapter knows both
	/// what it dialled and what that vendor answers with — which are not always the same
	/// host, and were not for Didit — so nothing outside it has to guess.
	///
	/// An EMPTY set means "this adapter cannot say", and the check then refuses
	/// everything. That is deliberate: the alternative, degrading to "any `https:` URL",
	/// is the state this check exists to leave, and it would arrive silently. The boot
	/// refuses to mount a provider that declares nothing.
	fn session_origins(&self) -> Vec<String>;

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
	/// A verdict landing on a case this plane retired as `abandoned` comes out here too,
	/// and for the same reading rather than by analogy: the user walked away and opened
	/// another attempt, so the state this delivery describes is one the case has LEFT.
	/// It is not [`Self::Unknown`] — the case exists, the vendor is right to have sent
	/// this, and a 404 would put it in a retry loop that can only ever end in a delivery
	/// nobody accepted.
	///
	/// A case the VENDOR called `abandoned` is NOT this, and the implementation must be
	/// able to tell the two apart by something other than the column: Didit writes that
	/// word for an applicant who left a session it still considers open, and one who
	/// returns by the same link and finishes is approved on that very case. Treating the
	/// status as proof of our own retirement would answer that approval here and leave a
	/// verified applicant at the level they had.
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

/// An attempt that has just been opened at the vendor, as [`KycCaseRepository::open_case`]
/// must write it.
///
/// A struct rather than seven positional arguments, because two of them are the same
/// `&str` type and sit next to each other: `provider` and `provider_ref` swapped at a
/// call site compile cleanly and produce a row the webhook can never look up.
pub struct NewCase<'a> {
	/// Minted by the CALLER, because it is also the correlation value handed to the
	/// vendor and echoed back in `vendor_data`.
	pub id: Uuid,
	pub user_id: UserId,
	pub provider: &'a str,
	pub provider_ref: &'a str,
	pub requested_tier: u32,
	pub redirect_url: &'a str,
	/// `KYC_CASE_TTL_SECS`: how old an abandonable running case of this user must be for
	/// opening this one to retire it. See [`KycCaseRepository::open_case`].
	pub ttl_secs: i64,
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
	pub status: KycStatus,
	pub requested_tier: u32,
	/// Unix seconds. Carried as a scalar rather than a timestamp type because the only
	/// consumer is a JSON body, and a plane that answers in epoch seconds everywhere
	/// (`*_expires_at`, `occurred_at`, `event_at`) must not grow a second time format
	/// for one route.
	pub created_at: i64,
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
	/// Record a started attempt.
	///
	/// This is also the ONE place a case is written to `abandoned`, and it must happen in
	/// the SAME transaction as the insert: every attempt of this user that
	/// [`KycStatus::is_abandonable`] and has not MOVED for `ttl_secs` is decided as
	/// `abandoned` here, because opening a new case is the moment the user says the old
	/// one is over. The read paths only IGNORE such a row (see [`Self::live_case`]) — a
	/// read that rewrote a status would put a decision on a `GET`, and a polled `GET` at
	/// that.
	///
	/// The row must also be MARKED as retired by this plane, in a way
	/// [`Self::record_decision`] can read back: `abandoned` on its own is a word the
	/// vendor writes too, and only our own mark may send a later verdict to
	/// [`CaseDecision::Ignored`].
	///
	/// Both halves under one transaction so the table never shows the state where the old
	/// case has been retired and the new one does not exist: a `/kyc/status` landing in
	/// that window would tell a user mid-start that they have no attempt at all.
	async fn open_case(&self, case: NewCase<'_>) -> Result<(), DomainError>;

	/// Read what decides whether this caller may open ANOTHER case: their still-running
	/// attempt, and how many they have opened in the last `window_secs`.
	///
	/// A read, and a deliberately cheap one, because it sits in front of a BILLABLE call.
	/// `/kyc/start` had nothing between the session check and `POST /v3/session/`, so a
	/// signed-in account looping the route drained the platform's Didit quota — and the
	/// degradation past that point is fail-closed, which turns one abusive user into a
	/// verification outage for everyone. This is the read that has to happen first.
	///
	/// NOT a lock and not a reservation: it reports what the table says at the instant it
	/// is read, and two simultaneous readers get the same answer. Serialising them is the
	/// CALLER's job — `/kyc/start` single-flights per user, in process — because doing it
	/// here would mean holding a row across the vendor round trip. Where that
	/// single-flight does not reach (a second replica), the window cap is what bounds the
	/// race.
	async fn start_gate(&self, user_id: UserId, window_secs: i64, ttl_secs: i64) -> Result<StartGate, DomainError>;

	/// This caller's still-running attempt, if they are in one.
	///
	/// The read half of [`Self::start_gate`], on its own, because `GET /kyc/status` must
	/// not pay for the window count: it is polled by every cabinet that has a signed-in
	/// user on a verification screen, while the count exists only to decide whether a
	/// BILLED vendor call may happen. Sharing the SQL with `start_gate` rather than
	/// copying it is what keeps "which statuses are still running" a single answer —
	/// two lists here would let `/kyc/status` report a live case the start route no
	/// longer considers live, which is precisely the disagreement #190 is about.
	///
	/// `ttl_secs` bounds how long an attempt whose next move is the USER's counts as
	/// running, measured from the last time the case MOVED: past it the case is ABANDONED
	/// in fact, and this read says so by ignoring it (#91). The same clock and the same
	/// predicate as [`Self::open_case`] retires by — a row one of them calls dead and the
	/// other leaves running is a user told to continue an attempt that has been closed. The row is left exactly as it stands — a read decides nothing, and the
	/// status is rewritten only when the user actually opens the next case
	/// ([`Self::open_case`]). Statuses that are not [`KycStatus::is_abandonable`] —
	/// `in_review`, where a human at the vendor is holding the case — never age out, at
	/// any `ttl_secs`.
	async fn live_case(&self, user_id: UserId, ttl_secs: i64) -> Result<Option<LiveCase>, DomainError>;

	/// The highest tier any OTHER case of this user was approved for and still holds
	/// `approved` status, if there is one.
	///
	/// Asked when a terminal NEGATIVE verdict looks like it contradicts the level an
	/// account holds. Without it the predicate is "this user is above this case's tier",
	/// which fires on the most ordinary sequence there is: verified once, verified again,
	/// and then the vendor reports the FIRST session as lapsed. That is routine, the
	/// second approval is entirely valid, and paging the owners about it teaches them to
	/// ignore the one mail that exists to be read.
	///
	/// The raw tier comes back rather than a level: what a status grants is
	/// [`KycStatus::grants_tier`]'s answer and nobody else's, so the SQL that finds the
	/// row does not get to have an opinion about it. `None` when no other approved case
	/// exists.
	async fn approved_cover(&self, user_id: UserId, excluding: Uuid) -> Result<Option<u32>, DomainError>;

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
	///
	/// A case this plane retired as `abandoned` still EXISTS as far as the vendor is
	/// concerned, so a late delivery about it is answered, never 404-ed — see
	/// [`CaseDecision::Ignored`]. That arm is for cases THIS plane retired and no other:
	/// a case the vendor itself called `abandoned` takes the ordinary path, so an
	/// applicant who returns by the same session link and finishes is still approved.
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
	/// preferences. What happened to `dedupe_key` is the answer — see
	/// [`GovernanceMailQueued`].
	///
	/// `recipient` and `email_verified` are the identity record's, read together: the
	/// subscriber row this refreshes is what `emit` later consults before mailing, so
	/// the flag written here decides whether ordinary notifications may go to the
	/// address — it must be the record's, never assumed from the fact that a governance
	/// mail was addressed to it.
	async fn enqueue_mail(
		&self,
		user_id: Uuid,
		recipient: &str,
		email_verified: bool,
		kind: &str,
		dedupe_key: &str,
		payload: &serde_json::Value,
	) -> Result<GovernanceMailQueued, DomainError>;
}

/// What queueing a governance mail did with its `dedupe_key`.
///
/// Three answers, not "inserted or not": the key is unique across the WHOLE queue, so a
/// key already present may be this very mail being retried — or somebody else's mail. The
/// two used to be one `false`, and the relay wrote an inbox trace for whoever the new call
/// named, so a spent key reused for another recipient put an entry in their inbox without
/// queueing anything or spending their budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernanceMailQueued {
	/// A new row: the mail will be sent.
	Inserted,
	/// The key already names this kind of mail to this recipient: an at-least-once retry.
	SameMail,
	/// The key already names a mail of another kind, or to another recipient.
	Foreign,
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

/// How long an emailed code works.
pub const CODE_TTL_SECS: i64 = 600;
/// Wrong guesses a code survives before it burns (`email_codes_attempts`).
pub const CODE_MAX_ATTEMPTS: i32 = 5;
/// Codes one address may be sent per [`CODE_SEND_WINDOW_SECS`], counted in the table so
/// the cap holds across replicas.
pub const CODE_SENDS_PER_WINDOW: i64 = 5;
pub const CODE_SEND_WINDOW_SECS: i64 = 900;

/// What a code is for. A sign-in code proves a mailbox to whoever asks; a verification
/// code proves the signed-in account's own address and is bound to that account.
#[derive(Clone, Debug)]
pub enum CodePurpose {
	Login(Email),
	Verify(UserId),
}

#[derive(Debug, Eq, PartialEq)]
pub enum CodeIssue {
	/// Stored and queued for the mailer.
	Sent,
	/// The address was sent [`CODE_SENDS_PER_WINDOW`] codes in the window already.
	Throttled,
}

/// Why a presented code did not prove the mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeRefusal {
	/// No live code was sent there, or it was already used.
	Missing,
	Expired,
	/// Wrong, with guesses left.
	Wrong,
	/// Wrong, and that was the last guess: the code is burned.
	Exhausted,
}

/// Failed password guesses before the password locks for [`PASSWORD_LOCK_SECS`]. The
/// lock is on the password only: a code still signs the account in, so nobody can lock
/// an owner out of their own account by guessing at it.
pub const PASSWORD_MAX_FAILURES: i32 = 10;
pub const PASSWORD_LOCK_SECS: i64 = 900;

/// The password an account handle names, for checking.
pub struct StoredPassword {
	pub user: UserId,
	/// PHC string, `$argon2id$…`.
	pub phc: String,
	pub locked_until: Option<i64>,
}

pub struct SignInMethods {
	pub password: bool,
	/// Linked providers, by `user_identities.provider`.
	pub providers: Vec<String>,
}

pub enum SignUp {
	Created(User),
	/// The address backs a password already, or is verified on an account: that person
	/// signs in, with a code if need be.
	Taken,
}

#[derive(Debug)]
pub enum VerifyRefusal {
	Code(CodeRefusal),
	/// The address is verified on another account already.
	Taken,
}

/// Emailed codes (and, beside them, passwords): the credentials this plane checks itself
/// rather than trusting a provider for. Every method is one transaction, and a wrong guess
/// is counted in it BEFORE the comparison, so an attempt that errors still counts.
#[async_trait]
pub trait CredentialRepository: Send + Sync {
	/// Mint a code and queue the mail carrying it. The address a verification code goes
	/// to is the account's current one, read here.
	async fn issue_code(&self, purpose: CodePurpose, now: i64) -> Result<CodeIssue, DomainError>;

	/// Spend a sign-in code. `Ok(Ok(()))` proves the mailbox; the account it opens is
	/// [`UserDirectoryRepository::resolve`]'s to decide.
	async fn redeem_login_code(&self, email: &Email, code: &str, now: i64) -> Result<Result<(), CodeRefusal>, DomainError>;

	/// Spend a verification code and mark the account's address verified, in one
	/// transaction.
	async fn verify_email(&self, user: UserId, code: &str, now: i64) -> Result<Result<User, VerifyRefusal>, DomainError>;

	/// A new account behind an email and a password, its address unverified.
	async fn sign_up(&self, email: &Email, phc: String, now: i64) -> Result<SignUp, DomainError>;

	/// The password of the one account `handle` names (an email or a username), if it
	/// has one.
	async fn password_named(&self, handle: &str) -> Result<Option<StoredPassword>, DomainError>;

	/// Count a guess: a failure moves toward the lock, a success clears the count.
	async fn record_password_attempt(&self, user: UserId, succeeded: bool, now: i64) -> Result<(), DomainError>;

	/// How the account can sign in, for its settings.
	async fn methods(&self, user: UserId) -> Result<SignInMethods, DomainError>;

	/// Set (or replace) the password, on the strength of a verification code — so a stolen
	/// session alone cannot plant a password that outlives its revocation. Spending the
	/// code verifies the address, as [`Self::verify_email`] does.
	async fn set_password(&self, user: UserId, code: &str, phc: String, now: i64) -> Result<Result<(), VerifyRefusal>, DomainError>;
}
