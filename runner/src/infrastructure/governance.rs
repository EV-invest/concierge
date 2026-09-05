//! Postgres adapter for the ownership consilia — taking a seat away, and granting one.
//!
//! THE ONE THING TO KNOW BEFORE READING THE SQL. Every write path opens with
//! [`lock_governance`], which bumps the single-row `governance_revision` counter. That
//! does three jobs at once: it is the live feed's clock, it is the reason a reader that
//! sees a committed change also sees the number move, and — because it is one row — it
//! totally orders governance writes. Without that total order the paths here would take
//! `owner_removal` and `users` row locks in opposite orders and deadlock under
//! contention. At this volume serialization is free, so it is taken rather than fought.
//!
//! A verdict and its consequence commit together or not at all: the vote, the state
//! transition, the seat change on `users`, the `ROLE_CHANGED` outbox row the money plane
//! pulls, the audit event and the revision bump are one transaction. The seat is written
//! through the SAME helpers `PgUsers` uses ([`super::users::load_for_update`] and
//! friends), so there is one identity writer and one outbox convention, not two.
//!
//! Expiry is LAZY. Nothing sweeps: a write path expires a due proposal before acting on
//! it, and read paths project a due proposal as expired without writing
//! ([`effective_state`]). A stale approval can therefore never execute, and no
//! background task has to be running for that to hold.
//!
//! Runtime queries (`sqlx::query*`, never the compile-time macros) keep `cargo build`
//! independent of a live database, mirroring the other adapters.

use async_trait::async_trait;
use domain::{
	architecture::EmitsEvents,
	authz::Role,
	error::DomainError,
	governance::{
		AdmissionId, AdmissionPeer, AdmissionVote, GovernanceEvent, MAX_CODE_ATTEMPTS, MIN_OWNERS, Outcome, OwnerAdmission, OwnerRemoval, Peer, ProposalState, REMOVAL_TTL_SECS, RemovalId,
		RemovalState, Vote, check_floor,
	},
	users::UserId,
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
	genesis::{GenesisOutcome, GenesisSubject, Resolution},
	infrastructure::{notifications, users},
	ports::{GovernanceRepository, OwnerGenesisRepository},
};

/// Crockford base32 with `I`, `L`, `O` and `U` removed — the four a person mistypes or
/// mishears. Ten characters from it is ~46 bits, and 32 divides 256, so masking the low
/// five bits of a random byte is uniform with no rejection loop.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 10;
/// Dedupe key prefix for the target's invitation mail — one per proposal, ever.
const INVITE_DEDUPE_PREFIX: &str = "owner-removal-invite";
/// The delivery kind the dispatcher renders the invitation with.
pub const INVITE_MAIL_KIND: &str = "owner_removal_self_accept";

macro_rules! admission_columns {
	() => {
		"a.id, a.candidate_user_id, a.initiator_user_id, a.reason, a.state, a.owner_count, a.created_at, a.expires_at, \
		 COALESCE(a.decided_at, 0) AS decided_at, a.void_reason, a.version"
	};
}

macro_rules! removal_columns {
	() => {
		"r.id, r.target_user_id, r.initiator_user_id, r.reason, r.state, r.owner_count, r.created_at, r.expires_at, \
		 COALESCE(r.decided_at, 0) AS decided_at, r.void_reason, r.version, r.target_decision, \
		 COALESCE(r.target_decided_at, 0) AS target_decided_at, r.target_notified"
	};
}

pub struct PgGovernance {
	pool: PgPool,
	/// Origin the target's approval page is served from. The adapter that mints the
	/// token also builds the URL it travels in, so the two cannot drift.
	approval_url_base: String,
}

impl PgGovernance {
	pub fn new(pool: PgPool, approval_url_base: String) -> Self {
		Self {
			pool,
			approval_url_base: approval_url_base.trim_end_matches('/').to_owned(),
		}
	}
}

/// One current owner, as the roster surface renders them.
#[derive(Clone, sqlx::FromRow)]
pub struct OwnerRow {
	pub id: Uuid,
	pub email: Option<String>,
	pub display_name: Option<String>,
	pub owner_since: i64,
}

/// A proposal plus the addresses its surfaces show. The aggregate holds ids only —
/// `domain` knows nothing about how a person is displayed.
#[derive(Debug)]
pub struct RemovalRecord {
	pub removal: OwnerRemoval,
	/// The state a surface should show. Equal to `removal.state()` except for a proposal
	/// that is due but which no write path has touched yet — read paths must not write,
	/// so expiry is projected here rather than applied to the aggregate.
	pub state: RemovalState,
	pub target_email: String,
	pub initiator_email: String,
	/// Snapshotted peers, in the same order as `removal.peers()`.
	pub peer_emails: Vec<String>,
}

/// An admission plus the addresses its surfaces show.
#[derive(Debug)]
pub struct AdmissionRecord {
	pub admission: OwnerAdmission,
	/// The state a surface should show — a due proposal reads as expired without a read
	/// path having to write. Same projection as [`RemovalRecord::state`].
	pub state: ProposalState,
	pub candidate_email: String,
	pub initiator_email: String,
	/// Snapshotted voters, in the same order as `admission.peers()`.
	pub peer_emails: Vec<String>,
}

/// What the TARGET is shown behind their emailed token. No peer identities and no vote
/// breakdown: knowing exactly who voted to remove you, before you answer, is not
/// something this flow needs to hand over.
#[derive(Debug)]
pub struct InvitationRecord {
	pub removal_id: Uuid,
	pub state: RemovalState,
	pub initiator_email: String,
	pub target_email: String,
	pub reason: String,
	pub created_at: i64,
	pub expires_at: i64,
	pub decision: Vote,
	pub attempts_remaining: u32,
}

/// The outcome of an attempt to answer from a mailbox.
#[derive(Debug)]
pub enum SelfDecision {
	/// Unknown, expired, burned, already-spent-and-contradicted, or a proposal that is
	/// no longer open. The caller must render every one of these identically.
	Unusable,
	WrongCode {
		attempts_remaining: u32,
	},
	Decided(Box<InvitationRecord>),
}

/// Where an answer came from. Recorded against every transition, because a vote whose
/// provenance was never captured cannot be audited afterwards.
#[derive(Clone, Default)]
pub struct Audit {
	pub client_ip: String,
	pub user_agent: String,
}

impl Audit {
	fn truncated(&self) -> (String, String) {
		(self.client_ip.chars().take(64).collect(), self.user_agent.chars().take(256).collect())
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

fn digest(raw: &str) -> Vec<u8> {
	Sha256::digest(raw.as_bytes()).to_vec()
}

fn secret_code() -> String {
	let mut bytes = [0u8; CODE_LEN];
	getrandom::fill(&mut bytes).expect("CSPRNG unavailable");
	bytes.iter().map(|b| CODE_ALPHABET[(b & 0x1f) as usize] as char).collect()
}

/// A due proposal reads as expired without anything having written that yet, so a
/// surface never shows an unanswerable proposal as open.
pub fn effective_state(stored: RemovalState, expires_at: i64, now: i64) -> RemovalState {
	if stored.is_open() && now >= expires_at { RemovalState::Expired } else { stored }
}

/// Which proposal an audit row belongs to. `governance_event` is ONE log for both
/// consilia — "who has held a seat, and by whose decision" is a single question — with a
/// CHECK enforcing that exactly one of the two ids is set.
#[derive(Clone, Copy)]
enum Subject {
	Removal(Uuid),
	Admission(Uuid),
}

/// Drain an aggregate's events into the audit log. Shared by both consilia so the
/// version-stamping rule below is written down once.
async fn insert_events(conn: &mut PgConnection, subject: Subject, version: u64, events: Vec<GovernanceEvent>, actor: Option<UserId>, audit: &Audit, now: i64) -> Result<(), DomainError> {
	let (client_ip, user_agent) = audit.truncated();
	let (removal_id, admission_id) = match subject {
		Subject::Removal(id) => (Some(id), None),
		Subject::Admission(id) => (None, Some(id)),
	};
	// The i-th of n drained events was minted at `version - (n - 1 - i)`, exactly as the
	// user outbox stamps its sequence, so the log and the row's version agree.
	let count = events.len() as u64;
	for (i, event) in events.into_iter().enumerate() {
		sqlx::query(
			"INSERT INTO governance_event (removal_id, admission_id, kind, actor_user_id, version, occurred_at, client_ip, user_agent) \
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		)
		.bind(removal_id)
		.bind(admission_id)
		.bind(event.kind())
		.bind(actor.map(|a| a.raw()))
		.bind((version - (count - 1 - i as u64)) as i64)
		.bind(now)
		.bind(&client_ip)
		.bind(&user_agent)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	}
	Ok(())
}

/// Bump the revision counter and, by taking its row lock, serialize this transaction
/// against every other governance write. Must be the FIRST statement of any write path.
async fn lock_governance(conn: &mut PgConnection) -> Result<i64, DomainError> {
	sqlx::query_scalar::<_, i64>("UPDATE governance_revision SET revision = revision + 1 WHERE id RETURNING revision")
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)
}

/// The roster, locked for the duration of the transaction so a concurrent `SetRole`
/// cannot move it between the snapshot and the decision taken from it.
async fn owner_ids_for_update(conn: &mut PgConnection) -> Result<Vec<UserId>, DomainError> {
	// Suspended owners are DELIBERATELY included: ownership is the role, and excluding
	// them would let an admin lower the denominator (and the floor) by suspending people.
	let rows = sqlx::query("SELECT id FROM users WHERE role = 'owner' ORDER BY id FOR UPDATE")
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	rows.iter().map(|r| r.try_get::<Uuid, _>("id").map(UserId::from_raw).map_err(repo_err)).collect()
}

/// Take the seat: the role write and its cross-plane `ROLE_CHANGED` go through the user
/// adapter's own helpers, on THIS transaction.
///
/// The demotion is all the way to `Investor` rather than `Admin`. An expulsion is
/// adversarial, and someone the fund has just voted out should not keep every
/// identity mutation except granting roles.
async fn take_seat(conn: &mut PgConnection, target: UserId) -> Result<(), DomainError> {
	let mut user = users::load_for_update(conn, target).await?;
	user.set_role(Role::Investor);
	users::update_row(conn, &user).await?;
	users::drain_outbox(conn, &mut user).await
}

/// Grant the seat, through the SAME identity helpers `take_seat` uses, on THIS
/// transaction — so the role write, its cross-plane `ROLE_CHANGED` and the verdict that
/// authorized it commit together or not at all.
async fn grant_seat(conn: &mut PgConnection, candidate: UserId) -> Result<(), DomainError> {
	let mut user = users::load_for_update(conn, candidate).await?;
	user.set_role(Role::Owner);
	users::update_row(conn, &user).await?;
	users::drain_outbox(conn, &mut user).await
}

async fn load_peers(conn: &mut PgConnection, id: RemovalId) -> Result<Vec<Peer>, DomainError> {
	let rows = sqlx::query("SELECT user_id, vote, COALESCE(voted_at, 0) AS voted_at FROM owner_removal_peer WHERE removal_id = $1 ORDER BY user_id")
		.bind(id.raw())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	rows.iter()
		.map(|r| {
			Ok(Peer {
				user_id: UserId::from_raw(r.try_get("user_id").map_err(repo_err)?),
				vote: Vote::parse(r.try_get::<&str, _>("vote").map_err(repo_err)?)?,
				voted_at: r.try_get("voted_at").map_err(repo_err)?,
			})
		})
		.collect()
}

/// Read one proposal `FOR UPDATE`, with its snapshotted peers, as the aggregate.
async fn load_for_update(conn: &mut PgConnection, id: RemovalId) -> Result<OwnerRemoval, DomainError> {
	let row = sqlx::query(concat!("SELECT ", removal_columns!(), " FROM owner_removal r WHERE r.id = $1 FOR UPDATE"))
		.bind(id.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound {
			entity: "owner removal",
			id: id.to_string(),
		})?;
	let peers = load_peers(conn, id).await?;
	rehydrate(&row, peers)
}

fn rehydrate(row: &sqlx::postgres::PgRow, peers: Vec<Peer>) -> Result<OwnerRemoval, DomainError> {
	Ok(OwnerRemoval::rehydrate(
		RemovalId::from_raw(row.try_get("id").map_err(repo_err)?),
		UserId::from_raw(row.try_get("target_user_id").map_err(repo_err)?),
		UserId::from_raw(row.try_get("initiator_user_id").map_err(repo_err)?),
		row.try_get::<String, _>("reason").map_err(repo_err)?,
		RemovalState::parse(row.try_get::<&str, _>("state").map_err(repo_err)?)?,
		row.try_get::<i32, _>("owner_count").map_err(repo_err)? as u32,
		peers,
		Vote::parse(row.try_get::<&str, _>("target_decision").map_err(repo_err)?)?,
		row.try_get("target_decided_at").map_err(repo_err)?,
		row.try_get("target_notified").map_err(repo_err)?,
		row.try_get("created_at").map_err(repo_err)?,
		row.try_get("expires_at").map_err(repo_err)?,
		row.try_get("decided_at").map_err(repo_err)?,
		row.try_get::<String, _>("void_reason").map_err(repo_err)?,
		row.try_get::<i64, _>("version").map_err(repo_err)? as u64,
	))
}

fn optional_ts(value: i64) -> Option<i64> {
	(value != 0).then_some(value)
}

/// Write the proposal back and drain its events into the audit log.
async fn persist(conn: &mut PgConnection, removal: &mut OwnerRemoval, actor: Option<UserId>, audit: &Audit, now: i64) -> Result<(), DomainError> {
	sqlx::query(
		"UPDATE owner_removal SET state = $2, decided_at = $3, void_reason = $4, version = $5, \
		 target_decision = $6, target_decided_at = $7, target_notified = $8 WHERE id = $1",
	)
	.bind(removal.id().raw())
	.bind(removal.state().as_str())
	.bind(optional_ts(removal.decided_at()))
	.bind(removal.void_reason())
	.bind(removal.version() as i64)
	.bind(removal.decision().as_str())
	.bind(optional_ts(removal.decided_as_target_at()))
	.bind(removal.target_notified())
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;

	for peer in removal.peers() {
		sqlx::query("UPDATE owner_removal_peer SET vote = $3, voted_at = $4 WHERE removal_id = $1 AND user_id = $2")
			.bind(removal.id().raw())
			.bind(peer.user_id.raw())
			.bind(peer.vote.as_str())
			.bind(optional_ts(peer.voted_at))
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}

	let version = removal.version();
	let events = removal.drain_events();
	insert_events(conn, Subject::Removal(removal.id().raw()), version, events, actor, audit, now).await
}

/// Write an admission back and drain its events into the same audit log.
async fn persist_admission(conn: &mut PgConnection, admission: &mut OwnerAdmission, actor: Option<UserId>, audit: &Audit, now: i64) -> Result<(), DomainError> {
	sqlx::query("UPDATE owner_admission SET state = $2, decided_at = $3, void_reason = $4, version = $5 WHERE id = $1")
		.bind(admission.id().raw())
		.bind(admission.state().as_str())
		.bind(optional_ts(admission.decided_at()))
		.bind(admission.void_reason())
		.bind(admission.version() as i64)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;

	for peer in admission.peers() {
		sqlx::query("UPDATE owner_admission_peer SET vote = $3, voted_at = $4 WHERE admission_id = $1 AND user_id = $2")
			.bind(admission.id().raw())
			.bind(peer.user_id.raw())
			.bind(peer.vote.as_str())
			.bind(optional_ts(peer.voted_at))
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}

	let version = admission.version();
	let events = admission.drain_events();
	insert_events(conn, Subject::Admission(admission.id().raw()), version, events, actor, audit, now).await
}

async fn load_admission_peers(conn: &mut PgConnection, id: AdmissionId) -> Result<Vec<AdmissionPeer>, DomainError> {
	let rows = sqlx::query("SELECT user_id, vote, COALESCE(voted_at, 0) AS voted_at FROM owner_admission_peer WHERE admission_id = $1 ORDER BY user_id")
		.bind(id.raw())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	rows.iter()
		.map(|r| {
			Ok(AdmissionPeer {
				user_id: UserId::from_raw(r.try_get("user_id").map_err(repo_err)?),
				vote: AdmissionVote::parse(r.try_get::<&str, _>("vote").map_err(repo_err)?)?,
				voted_at: r.try_get("voted_at").map_err(repo_err)?,
			})
		})
		.collect()
}

fn rehydrate_admission(row: &sqlx::postgres::PgRow, peers: Vec<AdmissionPeer>) -> Result<OwnerAdmission, DomainError> {
	Ok(OwnerAdmission::rehydrate(
		AdmissionId::from_raw(row.try_get("id").map_err(repo_err)?),
		UserId::from_raw(row.try_get("candidate_user_id").map_err(repo_err)?),
		UserId::from_raw(row.try_get("initiator_user_id").map_err(repo_err)?),
		row.try_get::<String, _>("reason").map_err(repo_err)?,
		ProposalState::parse(row.try_get::<&str, _>("state").map_err(repo_err)?)?,
		row.try_get::<i32, _>("owner_count").map_err(repo_err)? as u32,
		peers,
		row.try_get("created_at").map_err(repo_err)?,
		row.try_get("expires_at").map_err(repo_err)?,
		row.try_get("decided_at").map_err(repo_err)?,
		row.try_get::<String, _>("void_reason").map_err(repo_err)?,
		row.try_get::<i64, _>("version").map_err(repo_err)? as u64,
	))
}

async fn load_admission_for_update(conn: &mut PgConnection, id: AdmissionId) -> Result<OwnerAdmission, DomainError> {
	let row = sqlx::query(concat!("SELECT ", admission_columns!(), " FROM owner_admission a WHERE a.id = $1 FOR UPDATE"))
		.bind(id.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound {
			entity: "owner admission",
			id: id.to_string(),
		})?;
	let peers = load_admission_peers(conn, id).await?;
	rehydrate_admission(&row, peers)
}

/// Carry a passed admission, re-reading the roster at THIS moment.
async fn settle_admission(conn: &mut PgConnection, admission: &mut OwnerAdmission, now: i64) -> Result<(), DomainError> {
	if !admission.state().is_open() || admission.outcome() != Outcome::Passes {
		return Ok(());
	}
	let owners = owner_ids_for_update(conn).await?;
	// It passed over the SNAPSHOT but not against the roster as it stands: every voter
	// who carried it has since lost their seat, so the eligible set is now empty and
	// unanimity over nobody must not pass. Void it rather than failing the vote — the
	// last voter did nothing wrong, and an open proposal that can never pass is a trap
	// for whoever reads the console. (It cannot be merely PENDING here: `outcome()`
	// already said every snapshotted voter answered.)
	if admission.outcome_among(&owners) != Outcome::Passes {
		admission.void("the owners who carried this no longer hold their seats", now)?;
		return Ok(());
	}
	if admission.execute(&owners, now)? == ProposalState::Executed {
		grant_seat(conn, admission.candidate()).await?;
	}
	Ok(())
}

fn expire_admission_if_due(admission: &mut OwnerAdmission, now: i64) -> bool {
	admission.state().is_open() && now >= admission.expires_at() && admission.expire(now).is_ok()
}

async fn admission_record_of(conn: &mut PgConnection, row: &sqlx::postgres::PgRow, now: i64) -> Result<AdmissionRecord, DomainError> {
	let id = AdmissionId::from_raw(row.try_get("id").map_err(repo_err)?);
	let peer_rows = sqlx::query(
		"SELECT p.user_id, p.vote, COALESCE(p.voted_at, 0) AS voted_at, COALESCE(u.email, '') AS email \
		 FROM owner_admission_peer p JOIN users u ON u.id = p.user_id WHERE p.admission_id = $1 ORDER BY p.user_id",
	)
	.bind(id.raw())
	.fetch_all(&mut *conn)
	.await
	.map_err(repo_err)?;

	let mut peers = Vec::with_capacity(peer_rows.len());
	let mut peer_emails = Vec::with_capacity(peer_rows.len());
	for r in &peer_rows {
		peers.push(AdmissionPeer {
			user_id: UserId::from_raw(r.try_get("user_id").map_err(repo_err)?),
			vote: AdmissionVote::parse(r.try_get::<&str, _>("vote").map_err(repo_err)?)?,
			voted_at: r.try_get("voted_at").map_err(repo_err)?,
		});
		peer_emails.push(r.try_get::<String, _>("email").map_err(repo_err)?);
	}

	let admission = rehydrate_admission(row, peers)?;
	let state = effective_state(admission.state(), admission.expires_at(), now);
	Ok(AdmissionRecord {
		admission,
		state,
		candidate_email: row.try_get("candidate_email").map_err(repo_err)?,
		initiator_email: row.try_get("initiator_email").map_err(repo_err)?,
		peer_emails,
	})
}

/// Carry a passed proposal, re-reading the roster at THIS moment. The aggregate
/// re-decides against it — dropping the votes of peers who have since lost their seat,
/// then re-checking the floor and the initiator's own seat — so a proposal that passed
/// but can no longer be carried becomes void rather than executing.
async fn settle(conn: &mut PgConnection, removal: &mut OwnerRemoval, now: i64) -> Result<(), DomainError> {
	if !removal.state().is_open() || removal.outcome() != Outcome::Passes {
		return Ok(());
	}
	let owners = owner_ids_for_update(conn).await?;
	if removal.execute(&owners, now)? == RemovalState::Executed {
		take_seat(conn, removal.target()).await?;
	}
	Ok(())
}

/// True when the proposal was due and has just been closed as expired.
fn expire_if_due(removal: &mut OwnerRemoval, now: i64) -> bool {
	removal.state().is_open() && now >= removal.expires_at() && removal.expire(now).is_ok()
}

/// Read one proposal with the addresses its surfaces render, projecting a due proposal
/// as expired without writing.
async fn record_of(conn: &mut PgConnection, row: &sqlx::postgres::PgRow, now: i64) -> Result<RemovalRecord, DomainError> {
	let id = RemovalId::from_raw(row.try_get("id").map_err(repo_err)?);
	let peer_rows = sqlx::query(
		"SELECT p.user_id, p.vote, COALESCE(p.voted_at, 0) AS voted_at, COALESCE(u.email, '') AS email \
		 FROM owner_removal_peer p JOIN users u ON u.id = p.user_id WHERE p.removal_id = $1 ORDER BY p.user_id",
	)
	.bind(id.raw())
	.fetch_all(&mut *conn)
	.await
	.map_err(repo_err)?;

	let mut peers = Vec::with_capacity(peer_rows.len());
	let mut peer_emails = Vec::with_capacity(peer_rows.len());
	for r in &peer_rows {
		peers.push(Peer {
			user_id: UserId::from_raw(r.try_get("user_id").map_err(repo_err)?),
			vote: Vote::parse(r.try_get::<&str, _>("vote").map_err(repo_err)?)?,
			voted_at: r.try_get("voted_at").map_err(repo_err)?,
		});
		peer_emails.push(r.try_get::<String, _>("email").map_err(repo_err)?);
	}

	let removal = rehydrate(row, peers)?;
	let state = effective_state(removal.state(), removal.expires_at(), now);
	Ok(RemovalRecord {
		removal,
		state,
		target_email: row.try_get("target_email").map_err(repo_err)?,
		initiator_email: row.try_get("initiator_email").map_err(repo_err)?,
		peer_emails,
	})
}

#[async_trait]
impl OwnerGenesisRepository for PgGovernance {
	/// Genesis: the ONE writer that can turn an empty registry into a fund.
	///
	/// It lives beside the consilium rather than beside `PgUsers` because it is a
	/// governance write. It takes [`lock_governance`] and then [`owner_ids_for_update`],
	/// the same two locks in the same order as every consilium path, so a genesis racing
	/// a consilium — or another replica's genesis — is serialized rather than
	/// interleaved. Reading the roster BEFORE that lock would let two pods each see an
	/// empty registry and seat it twice.
	///
	/// The seats go through [`grant_seat`], the same helper an executed admission uses,
	/// so every founder gets the `ROLE_CHANGED` outbox row the money plane pulls.
	///
	/// Every refusal returns early WITHOUT committing, so the revision bump
	/// [`lock_governance`] performs rolls back with it: a boot that seats nobody leaves
	/// the live feed alone.
	async fn seed_owners(&self, subjects: &[GenesisSubject]) -> Result<GenesisOutcome, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;

		let owners = owner_ids_for_update(&mut tx).await?;
		if !owners.is_empty() {
			return Ok(GenesisOutcome::Closed { owners: owners.len() as i64 });
		}

		let mut resolution = Resolution::default();
		for subject in subjects {
			match subject {
				GenesisSubject::Id(id) => {
					let exists = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id = $1")
						.bind(id.raw())
						.fetch_optional(&mut *tx)
						.await
						.map_err(repo_err)?;
					if exists.is_some() {
						remember(&mut resolution.found, *id);
					} else {
						remember(&mut resolution.missing_ids, *id);
					}
				}
				GenesisSubject::Mailbox(mailbox) => {
					// `lower(email)` rather than a bare `=`: both sides are already normalized by
					// `Email::parse`, but a row written before that normalization existed would
					// otherwise be invisible to a list the operator can see is correct. The table
					// is tiny and this runs once per boot, so the unindexed scan costs nothing.
					let matches = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE lower(email) = $1 ORDER BY id")
						.bind(mailbox.as_str())
						.fetch_all(&mut *tx)
						.await
						.map_err(repo_err)?;
					match matches.as_slice() {
						[] => resolution.missing_mailboxes.push(mailbox.clone()),
						[only] => remember(&mut resolution.found, UserId::from_raw(*only)),
						// `users.email` is deliberately NOT unique (a person may change it behind a
						// stable auth subject), so this is reachable — and a seat handed to the wrong
						// person is one the owner floor will not let anyone take back. Refuse the
						// whole roster rather than guess.
						many => {
							return Ok(GenesisOutcome::Ambiguous {
								mailbox: mailbox.clone(),
								matches: many.len() as i64,
							});
						}
					}
				}
			}
		}

		if resolution.found.len() < MIN_OWNERS {
			return Ok(GenesisOutcome::TooFew(resolution));
		}
		for id in &resolution.found {
			grant_seat(&mut tx, *id).await?;
		}
		tx.commit().await.map_err(repo_err)?;
		Ok(GenesisOutcome::Seated(resolution))
	}
}

/// Append `id` unless it is already there: the same person may be named twice, once by
/// id and once by mailbox, and they hold one seat either way.
fn remember(ids: &mut Vec<UserId>, id: UserId) {
	if !ids.contains(&id) {
		ids.push(id);
	}
}

#[async_trait]
impl GovernanceRepository for PgGovernance {
	async fn owners(&self) -> Result<Vec<OwnerRow>, DomainError> {
		// `owner_since` is the last time this plane recorded them BECOMING an owner —
		// the outbox is the only record of when a role changed — falling back to the
		// account's own creation for seats granted before the bridge carried roles.
		sqlx::query_as::<_, OwnerRow>(
			"SELECT u.id, u.email, COALESCE(NULLIF(u.preferred_name, ''), u.legal_name) AS display_name, \
			        COALESCE((SELECT max(o.occurred_at) FROM user_outbox o \
			                  WHERE o.user_id = u.id AND o.kind = 'ROLE_CHANGED' AND o.role = 'owner'), \
			                 EXTRACT(EPOCH FROM u.created_at)::BIGINT) AS owner_since \
			 FROM users u WHERE u.role = 'owner' ORDER BY owner_since ASC, u.id ASC",
		)
		.fetch_all(&self.pool)
		.await
		.map_err(repo_err)
	}

	async fn open_removal(&self, target: UserId, initiator: UserId, reason: &str, now: i64) -> Result<RemovalRecord, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;

		// A due proposal against this target still occupies the one-open-per-target
		// index. Close it first, so an expired attempt cannot block every future one.
		if let Some(stale) = sqlx::query_scalar::<_, Uuid>("SELECT id FROM owner_removal WHERE target_user_id = $1 AND state = 'open' AND expires_at <= $2")
			.bind(target.raw())
			.bind(now)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?
		{
			let mut due = load_for_update(&mut tx, RemovalId::from_raw(stale)).await?;
			if expire_if_due(&mut due, now) {
				persist(&mut tx, &mut due, None, &Audit::default(), now).await?;
			}
		}

		let owners = owner_ids_for_update(&mut tx).await?;
		let mut removal = OwnerRemoval::open(RemovalId::new(), target, initiator, reason, &owners, now, REMOVAL_TTL_SECS)?;

		sqlx::query(
			"INSERT INTO owner_removal (id, target_user_id, initiator_user_id, reason, state, owner_count, created_at, expires_at, version) \
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		)
		.bind(removal.id().raw())
		.bind(target.raw())
		.bind(initiator.raw())
		.bind(removal.reason())
		.bind(removal.state().as_str())
		.bind(removal.owner_count() as i32)
		.bind(removal.created_at())
		.bind(removal.expires_at())
		.bind(removal.version() as i64)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;

		for peer in removal.peers() {
			sqlx::query("INSERT INTO owner_removal_peer (removal_id, user_id) VALUES ($1, $2)")
				.bind(removal.id().raw())
				.bind(peer.user_id.raw())
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;
		}

		// Only the digests are stored. The plaintext exists exactly once more, in the
		// delivery row below, and the dispatcher nulls it the moment the mail is sent.
		let token = notifications::opaque_token();
		let code = secret_code();
		sqlx::query("INSERT INTO owner_removal_token (removal_id, token_hash, code_hash, expires_at) VALUES ($1, $2, $3, $4)")
			.bind(removal.id().raw())
			.bind(digest(&token))
			.bind(digest(&code))
			.bind(removal.expires_at())
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;

		let target_user = users::load_for_update(&mut tx, target).await?;
		let initiator_user = users::load_for_update(&mut tx, initiator).await?;
		let subscriber = notifications::upsert_subscriber(&mut tx, target.raw(), target_user.email().as_str(), target_user.email_verified()).await?;
		let payload = serde_json::json!({
			"initiator_email": initiator_user.email().as_str(),
			"reason": removal.reason(),
			"approval_url": format!("{}/{token}", self.approval_url_base),
			"code": code,
			"expires_at": removal.expires_at(),
		});
		notifications::enqueue_governance_mail(
			&mut tx,
			subscriber.id,
			target_user.email().as_str(),
			INVITE_MAIL_KIND,
			&format!("{INVITE_DEDUPE_PREFIX}:{}", removal.id()),
			&payload,
		)
		.await?;
		// Atomic with the mail: the flag can never claim a message that was not queued.
		removal.mark_target_notified();

		persist(&mut tx, &mut removal, Some(initiator), &Audit::default(), now).await?;
		tx.commit().await.map_err(repo_err)?;

		self.find_removal(removal.id(), now)
			.await?
			.ok_or_else(|| DomainError::Repository("the removal vanished after being opened".into()))
	}

	async fn find_removal(&self, id: RemovalId, now: i64) -> Result<Option<RemovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let row = sqlx::query(concat!(
			"SELECT ",
			removal_columns!(),
			", COALESCE(t.email, '') AS target_email, COALESCE(i.email, '') AS initiator_email \
			 FROM owner_removal r JOIN users t ON t.id = r.target_user_id JOIN users i ON i.id = r.initiator_user_id \
			 WHERE r.id = $1"
		))
		.bind(id.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
		match row {
			Some(row) => Ok(Some(record_of(&mut conn, &row, now).await?)),
			None => Ok(None),
		}
	}

	async fn list_removals(&self, limit: i64, now: i64) -> Result<Vec<RemovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let rows = sqlx::query(concat!(
			"SELECT ",
			removal_columns!(),
			", COALESCE(t.email, '') AS target_email, COALESCE(i.email, '') AS initiator_email \
			 FROM owner_removal r JOIN users t ON t.id = r.target_user_id JOIN users i ON i.id = r.initiator_user_id \
			 ORDER BY r.created_at DESC LIMIT $1"
		))
		.bind(limit)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		let mut records = Vec::with_capacity(rows.len());
		for row in &rows {
			records.push(record_of(&mut conn, row, now).await?);
		}
		Ok(records)
	}

	async fn peer_vote(&self, id: RemovalId, voter: UserId, vote: Vote, now: i64, audit: &Audit) -> Result<RemovalRecord, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;
		let mut removal = load_for_update(&mut tx, id).await?;
		if expire_if_due(&mut removal, now) {
			persist(&mut tx, &mut removal, None, &Audit::default(), now).await?;
			tx.commit().await.map_err(repo_err)?;
			return Err(DomainError::Conflict("the removal is expired".into()));
		}
		removal.peer_vote(voter, vote, now)?;
		settle(&mut tx, &mut removal, now).await?;
		persist(&mut tx, &mut removal, Some(voter), audit, now).await?;
		tx.commit().await.map_err(repo_err)?;
		self.find_removal(id, now).await?.ok_or_else(|| DomainError::NotFound {
			entity: "owner removal",
			id: id.to_string(),
		})
	}

	async fn cancel_removal(&self, id: RemovalId, by: UserId, now: i64) -> Result<RemovalRecord, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;
		let mut removal = load_for_update(&mut tx, id).await?;
		if expire_if_due(&mut removal, now) {
			persist(&mut tx, &mut removal, None, &Audit::default(), now).await?;
			tx.commit().await.map_err(repo_err)?;
			return Err(DomainError::Conflict("the removal is expired".into()));
		}
		removal.cancel(by, now)?;
		persist(&mut tx, &mut removal, Some(by), &Audit::default(), now).await?;
		tx.commit().await.map_err(repo_err)?;
		self.find_removal(id, now).await?.ok_or_else(|| DomainError::NotFound {
			entity: "owner removal",
			id: id.to_string(),
		})
	}

	/// Strictly read-only, because mail scanners issue automatic requests for every URL
	/// in a message. Nothing here counts an attempt, spends a token, or writes a row.
	async fn open_admission(&self, candidate: UserId, initiator: UserId, reason: &str, now: i64) -> Result<AdmissionRecord, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;

		// A due admission for this candidate still occupies the one-open-per-candidate
		// index. Close it first, so a lapsed attempt cannot block every future one.
		if let Some(stale) = sqlx::query_scalar::<_, Uuid>("SELECT id FROM owner_admission WHERE candidate_user_id = $1 AND state = 'open' AND expires_at <= $2")
			.bind(candidate.raw())
			.bind(now)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?
		{
			let mut due = load_admission_for_update(&mut tx, AdmissionId::from_raw(stale)).await?;
			if expire_admission_if_due(&mut due, now) {
				persist_admission(&mut tx, &mut due, None, &Audit::default(), now).await?;
			}
		}

		let owners = owner_ids_for_update(&mut tx).await?;
		let mut admission = OwnerAdmission::open(AdmissionId::new(), candidate, initiator, reason, &owners, now, REMOVAL_TTL_SECS)?;

		sqlx::query(
			"INSERT INTO owner_admission (id, candidate_user_id, initiator_user_id, reason, state, owner_count, created_at, expires_at, version) \
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		)
		.bind(admission.id().raw())
		.bind(candidate.raw())
		.bind(initiator.raw())
		.bind(admission.reason())
		.bind(admission.state().as_str())
		.bind(admission.owner_count() as i32)
		.bind(admission.created_at())
		.bind(admission.expires_at())
		.bind(admission.version() as i64)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;

		for peer in admission.peers() {
			sqlx::query("INSERT INTO owner_admission_peer (admission_id, user_id) VALUES ($1, $2)")
				.bind(admission.id().raw())
				.bind(peer.user_id.raw())
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;
		}

		persist_admission(&mut tx, &mut admission, Some(initiator), &Audit::default(), now).await?;
		tx.commit().await.map_err(repo_err)?;

		self.find_admission(admission.id(), now)
			.await?
			.ok_or_else(|| DomainError::Repository("the admission vanished after being opened".into()))
	}

	async fn find_admission(&self, id: AdmissionId, now: i64) -> Result<Option<AdmissionRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let row = sqlx::query(concat!(
			"SELECT ",
			admission_columns!(),
			", COALESCE(c.email, '') AS candidate_email, COALESCE(i.email, '') AS initiator_email \
			 FROM owner_admission a JOIN users c ON c.id = a.candidate_user_id JOIN users i ON i.id = a.initiator_user_id \
			 WHERE a.id = $1"
		))
		.bind(id.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
		match row {
			Some(row) => Ok(Some(admission_record_of(&mut conn, &row, now).await?)),
			None => Ok(None),
		}
	}

	async fn list_admissions(&self, limit: i64, now: i64) -> Result<Vec<AdmissionRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let rows = sqlx::query(concat!(
			"SELECT ",
			admission_columns!(),
			", COALESCE(c.email, '') AS candidate_email, COALESCE(i.email, '') AS initiator_email \
			 FROM owner_admission a JOIN users c ON c.id = a.candidate_user_id JOIN users i ON i.id = a.initiator_user_id \
			 ORDER BY a.created_at DESC LIMIT $1"
		))
		.bind(limit)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		let mut records = Vec::with_capacity(rows.len());
		for row in &rows {
			records.push(admission_record_of(&mut conn, row, now).await?);
		}
		Ok(records)
	}

	async fn admission_vote(&self, id: AdmissionId, voter: UserId, vote: AdmissionVote, now: i64, audit: &Audit) -> Result<AdmissionRecord, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;
		let mut admission = load_admission_for_update(&mut tx, id).await?;
		if expire_admission_if_due(&mut admission, now) {
			persist_admission(&mut tx, &mut admission, None, &Audit::default(), now).await?;
			tx.commit().await.map_err(repo_err)?;
			return Err(DomainError::Conflict("the admission is expired".into()));
		}
		admission.vote(voter, vote, now)?;
		settle_admission(&mut tx, &mut admission, now).await?;
		persist_admission(&mut tx, &mut admission, Some(voter), audit, now).await?;
		tx.commit().await.map_err(repo_err)?;
		self.find_admission(id, now).await?.ok_or_else(|| DomainError::NotFound {
			entity: "owner admission",
			id: id.to_string(),
		})
	}

	async fn cancel_admission(&self, id: AdmissionId, by: UserId, now: i64) -> Result<AdmissionRecord, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;
		let mut admission = load_admission_for_update(&mut tx, id).await?;
		if expire_admission_if_due(&mut admission, now) {
			persist_admission(&mut tx, &mut admission, None, &Audit::default(), now).await?;
			tx.commit().await.map_err(repo_err)?;
			return Err(DomainError::Conflict("the admission is expired".into()));
		}
		admission.cancel(by, now)?;
		persist_admission(&mut tx, &mut admission, Some(by), &Audit::default(), now).await?;
		tx.commit().await.map_err(repo_err)?;
		self.find_admission(id, now).await?.ok_or_else(|| DomainError::NotFound {
			entity: "owner admission",
			id: id.to_string(),
		})
	}

	async fn invitation(&self, token: &str, now: i64) -> Result<Option<InvitationRecord>, DomainError> {
		let row = sqlx::query(
			"SELECT r.id, r.state, r.reason, r.created_at, r.expires_at, r.target_decision, \
			        COALESCE(t.email, '') AS target_email, COALESCE(i.email, '') AS initiator_email, \
			        k.attempts, k.burned_at, k.used_at, k.expires_at AS token_expires_at \
			 FROM owner_removal_token k \
			 JOIN owner_removal r ON r.id = k.removal_id \
			 JOIN users t ON t.id = r.target_user_id \
			 JOIN users i ON i.id = r.initiator_user_id \
			 WHERE k.token_hash = $1",
		)
		.bind(digest(token))
		.fetch_optional(&self.pool)
		.await
		.map_err(repo_err)?;

		let Some(row) = row else { return Ok(None) };
		let burned: Option<i64> = row.try_get("burned_at").map_err(repo_err)?;
		let used: Option<i64> = row.try_get("used_at").map_err(repo_err)?;
		let token_expires_at: i64 = row.try_get("token_expires_at").map_err(repo_err)?;
		let expires_at: i64 = row.try_get("expires_at").map_err(repo_err)?;
		let state = effective_state(RemovalState::parse(row.try_get::<&str, _>("state").map_err(repo_err)?)?, expires_at, now);
		// Burned, spent, expired and wrong-state all collapse to the same absence, so a
		// caller cannot tell which of them they hit.
		if burned.is_some() || used.is_some() || now >= token_expires_at || !state.is_open() {
			return Ok(None);
		}
		let attempts: i32 = row.try_get("attempts").map_err(repo_err)?;
		Ok(Some(InvitationRecord {
			removal_id: row.try_get("id").map_err(repo_err)?,
			state,
			initiator_email: row.try_get("initiator_email").map_err(repo_err)?,
			target_email: row.try_get("target_email").map_err(repo_err)?,
			reason: row.try_get("reason").map_err(repo_err)?,
			created_at: row.try_get("created_at").map_err(repo_err)?,
			expires_at,
			decision: Vote::parse(row.try_get::<&str, _>("target_decision").map_err(repo_err)?)?,
			attempts_remaining: MAX_CODE_ATTEMPTS.saturating_sub(attempts).max(0) as u32,
		}))
	}

	async fn self_decision(&self, token: &str, code: &str, vote: Vote, now: i64, audit: &Audit) -> Result<SelfDecision, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;

		let row = sqlx::query("SELECT removal_id, code_hash, attempts, burned_at, expires_at, used_at FROM owner_removal_token WHERE token_hash = $1 FOR UPDATE")
			.bind(digest(token))
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		let Some(row) = row else { return Ok(SelfDecision::Unusable) };

		let removal_id = RemovalId::from_raw(row.try_get("removal_id").map_err(repo_err)?);
		let burned: Option<i64> = row.try_get("burned_at").map_err(repo_err)?;
		let token_expires_at: i64 = row.try_get("expires_at").map_err(repo_err)?;
		if burned.is_some() || now >= token_expires_at {
			return Ok(SelfDecision::Unusable);
		}

		let spent: Option<i64> = row.try_get("used_at").map_err(repo_err)?;
		let mut removal = load_for_update(&mut tx, removal_id).await?;

		// REFUSE BEFORE COUNTING. A token pointed at a proposal that is no longer
		// answerable costs the holder nothing: mail gateways follow links unbidden, and a
		// scanner hitting a closed proposal must not be able to spend a human's five
		// attempts. A SPENT token is deliberately excluded — it takes the idempotent path
		// further down, which has to verify the code before it will confirm anything.
		if spent.is_none() {
			if expire_if_due(&mut removal, now) {
				persist(&mut tx, &mut removal, None, &Audit::default(), now).await?;
				tx.commit().await.map_err(repo_err)?;
				return Ok(SelfDecision::Unusable);
			}
			if !removal.state().is_open() {
				return Ok(SelfDecision::Unusable);
			}
		}

		// Pitfall 7: the counter moves in THIS transaction, BEFORE the comparison, so
		// concurrent guesses queue behind the row lock instead of slipping past the cap.
		let attempts = sqlx::query_scalar::<_, i32>("UPDATE owner_removal_token SET attempts = attempts + 1 WHERE removal_id = $1 RETURNING attempts")
			.bind(removal_id.raw())
			.fetch_one(&mut *tx)
			.await
			.map_err(repo_err)?;

		let stored_hash: Vec<u8> = row.try_get("code_hash").map_err(repo_err)?;
		if !bool::from(digest(code).ct_eq(&stored_hash)) {
			if attempts >= MAX_CODE_ATTEMPTS {
				sqlx::query("UPDATE owner_removal_token SET burned_at = $2 WHERE removal_id = $1")
					.bind(removal_id.raw())
					.bind(now)
					.execute(&mut *tx)
					.await
					.map_err(repo_err)?;
			}
			// The increment (and any burn) must survive the wrong answer.
			tx.commit().await.map_err(repo_err)?;
			return Ok(SelfDecision::WrongCode {
				attempts_remaining: MAX_CODE_ATTEMPTS.saturating_sub(attempts).max(0) as u32,
			});
		}

		// The attempt counter is NOT reset by a correct answer. A token that has been
		// guessed at stays closer to burning: the guesses were still made, and whoever
		// made them is still out there. Both planes specify this identically — see the
		// "One specification for both planes" table in banking's docs/CONSILIUM.md.
		if spent.is_some() {
			// One-shot, but a repeat of the SAME answer is a no-op rather than an error —
			// a resubmitted form must not look like a failure. A DIFFERENT one is refused.
			if removal.decision() != vote {
				return Ok(SelfDecision::Unusable);
			}
			tx.commit().await.map_err(repo_err)?;
			return self.decided(removal_id, now).await;
		}

		let target = removal.target();
		removal.target_decision(vote, now)?;
		settle(&mut tx, &mut removal, now).await?;
		persist(&mut tx, &mut removal, Some(target), audit, now).await?;
		sqlx::query("UPDATE owner_removal_token SET used_at = $2 WHERE removal_id = $1")
			.bind(removal_id.raw())
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;
		Ok(self.decided(removal_id, now).await?)
	}

	async fn resign(&self, who: UserId, now: i64) -> Result<(), DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;
		let owners = owner_ids_for_update(&mut tx).await?;
		if !owners.contains(&who) {
			return Err(DomainError::Forbidden("you do not hold an owner seat".into()));
		}
		// Leaving voluntarily is subject to the SAME floor as being removed: the last
		// seats are not anyone's to vacate.
		check_floor(owners.len())?;

		// An open proposal against someone who has just left is moot; void it so the
		// one-open-per-target index does not keep a dead row.
		if let Some(open) = sqlx::query_scalar::<_, Uuid>("SELECT id FROM owner_removal WHERE target_user_id = $1 AND state = 'open'")
			.bind(who.raw())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?
		{
			let mut moot = load_for_update(&mut tx, RemovalId::from_raw(open)).await?;
			moot.void("the target resigned the seat", now)?;
			persist(&mut tx, &mut moot, Some(who), &Audit::default(), now).await?;
		}

		take_seat(&mut tx, who).await?;
		tx.commit().await.map_err(repo_err)
	}

	async fn revision(&self) -> Result<u64, DomainError> {
		let value = sqlx::query_scalar::<_, i64>("SELECT revision FROM governance_revision WHERE id")
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(value.max(0) as u64)
	}

	async fn enqueue_mail(&self, user_id: Uuid, recipient: &str, kind: &str, dedupe_key: &str, payload: &serde_json::Value) -> Result<bool, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let subscriber = notifications::upsert_subscriber(&mut conn, user_id, recipient, true).await?;
		notifications::enqueue_governance_mail(&mut conn, subscriber.id, recipient, kind, dedupe_key, payload).await
	}
}

impl PgGovernance {
	/// The invitation as it stands after an answer was accepted, for the response body.
	async fn decided(&self, id: RemovalId, now: i64) -> Result<SelfDecision, DomainError> {
		let record = self.find_removal(id, now).await?.ok_or_else(|| DomainError::NotFound {
			entity: "owner removal",
			id: id.to_string(),
		})?;
		Ok(SelfDecision::Decided(Box::new(InvitationRecord {
			removal_id: record.removal.id().raw(),
			state: record.state,
			initiator_email: record.initiator_email,
			target_email: record.target_email,
			reason: record.removal.reason().to_owned(),
			created_at: record.removal.created_at(),
			expires_at: record.removal.expires_at(),
			decision: record.removal.decision(),
			attempts_remaining: 0,
		})))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_code_alphabet_drops_the_characters_people_confuse() {
		assert_eq!(CODE_ALPHABET.len(), 32, "a power of two, so masking a random byte is uniform");
		for confusable in *b"ILOU" {
			assert!(!CODE_ALPHABET.contains(&confusable), "{} is read back wrong over the phone", confusable as char);
		}
		let code = secret_code();
		assert_eq!(code.chars().count(), CODE_LEN);
		assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
		assert_ne!(secret_code(), secret_code(), "two codes from the CSPRNG must not collide");
	}

	#[test]
	fn a_due_proposal_reads_as_expired_without_a_sweeper() {
		assert_eq!(effective_state(RemovalState::Open, 100, 99), RemovalState::Open);
		assert_eq!(effective_state(RemovalState::Open, 100, 100), RemovalState::Expired, "due exactly on the boundary");
		assert_eq!(
			effective_state(RemovalState::Executed, 100, 900),
			RemovalState::Executed,
			"a closed proposal is never re-labelled"
		);
	}

	#[test]
	fn digests_are_sha256_and_never_the_plaintext() {
		let hash = digest("hunter2");
		assert_eq!(hash.len(), 32, "the CHECK constraint enforces this width too");
		assert_ne!(hash, b"hunter2".to_vec());
		assert_eq!(hash, digest("hunter2"), "the same input must find the same row");
	}
}
