//! `governance` bounded context — the consilium that takes an owner's seat away.
//!
//! Pure and wasm-safe like [`crate::users`]: no I/O, no clock, no randomness. Ids,
//! timestamps and the owner roster are supplied by the (host-only) application layer,
//! so the rules stay exhaustively testable and identical for every caller.
//!
//! THE RULE (banking's `docs/CONSILIUM.md`). A removal passes when EITHER the target
//! accepts it from their own mailbox, OR every eligible peer voted to remove AND there
//! is at least one such peer. The peer set is `owners \ {target, initiator}`: the
//! initiator gets no vote, because proposing is not agreeing. With exactly two owners
//! that set is EMPTY, and "everyone in an empty set agreed" is vacuously true — which
//! would let either owner expel the other unilaterally, so path (b) additionally
//! demands a non-empty set.
//!
//! ADMISSION IS THE SAME SHAPE, and it is the reason the rest of this matters. Granting
//! a seat is a consilium too ([`OwnerAdmission`]): unanimity of `owners \ {initiator}`,
//! again with at least one such peer. Without it every control here is decorative — one
//! owner could mint sock puppets and then reach any quorum legitimately, and
//! snapshotting the roster does not help, because the stuffing happens BEFORE the
//! proposal opens. Unanimity rather than a majority, because a minority must never be
//! able to grow itself into a majority.
//!
//! [`MIN_OWNERS`] is a second, independent guard: a removal that would leave fewer
//! owners behind is refused at open AND re-checked at execution, because the roster
//! moves underneath an open proposal. A proposal that passed but can no longer be
//! carried out becomes [`ProposalState::Void`], never `Executed`.

use ev::architecture::{AggregateRoot, DomainEvent, EmitsEvents, Entity, Id};
use serde::{Deserialize, Serialize};

use crate::{error::DomainError, users::UserId};

/// Owners that must REMAIN after a removal.
///
/// Two, not three. An earlier draft of the policy used three, so that the money plane
/// could always still reach its `floor(N/2)+1` payout threshold — but at exactly three
/// owners that made a bad actor UNREMOVABLE: removal was blocked by the floor, and
/// admitting an ally to get past it needs the bad actor's own agreement. Dropping to two
/// suspends payouts, which is recoverable — two owners can admit a third and resume. A
/// permanent deadlock is not.
pub const MIN_OWNERS: usize = 2;

/// Owners below which the money plane can no longer authorize a payout at all: its
/// threshold is `floor(N/2)+1` over ALL owners while the initiator cannot vote, so two
/// owners can never reach it. Deliberately NOT [`MIN_OWNERS`] — this one is a WARNING
/// the roster surfaces, never a rule that blocks a removal.
pub const PAYOUT_MIN_OWNERS: usize = 3;
/// How long a proposal stays answerable. A stale approval must not execute.
pub const REMOVAL_TTL_SECS: i64 = 72 * 60 * 60;
/// Failed code attempts before the target's emailed token burns permanently.
pub const MAX_CODE_ATTEMPTS: i32 = 5;
/// Longest reason the initiator may write. Backed by a SQL CHECK.
pub const MAX_REASON_CHARS: usize = 500;

/// A removal proposal's identity (a UUID), distinct from every other id type.
pub type RemovalId = Id<RemovalTag>;
/// Phantom tag making [`RemovalId`] incompatible with [`UserId`].
pub struct RemovalTag;

/// An admission proposal's identity. A separate tag, so an admission id can never be
/// passed where a removal id is expected.
pub type AdmissionId = Id<AdmissionTag>;
/// Phantom tag making [`AdmissionId`] incompatible with [`RemovalId`].
pub struct AdmissionTag;

/// Where a proposal stands — the same six states for a removal and for an admission.
/// Only [`Self::Open`] accepts further transitions; every other state is terminal, and
/// none of them delete anything: a rejected, expired or void proposal stays readable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
	Open,
	/// The consilium passed and the seat was taken.
	Executed,
	Rejected,
	Expired,
	Cancelled,
	/// Passed, but the seat could not be taken — the floor, or an initiator who had
	/// themselves stopped being an owner.
	Void,
}

/// The name this state had when removal was the only consilium. Kept so the removal
/// code and its SQL read as they always did.
pub type RemovalState = ProposalState;

impl ProposalState {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Open => "open",
			Self::Executed => "executed",
			Self::Rejected => "rejected",
			Self::Expired => "expired",
			Self::Cancelled => "cancelled",
			Self::Void => "void",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"open" => Ok(Self::Open),
			"executed" => Ok(Self::Executed),
			"rejected" => Ok(Self::Rejected),
			"expired" => Ok(Self::Expired),
			"cancelled" => Ok(Self::Cancelled),
			"void" => Ok(Self::Void),
			other => Err(DomainError::Validation(format!("unknown proposal state: {other}"))),
		}
	}

	pub fn is_open(self) -> bool {
		self == Self::Open
	}
}

/// One answer, from a peer or from the target. `Remove` from the TARGET means they
/// accept their own removal; `Keep` means they refuse it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vote {
	#[default]
	Pending,
	Remove,
	Keep,
}

/// A peer's answer with the verb stripped off. Removal peers speak of REMOVE/KEEP and
/// admission peers of ADMIT/REJECT, but the passing rule does not care which word was
/// used — it cares only whether this peer is carrying the proposal or blocking it. This
/// projection is what lets [`unanimity`] be the single definition of that rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ballot {
	Pending,
	/// Carry the proposal.
	For,
	/// Block it. One of these ends a unanimity outright.
	Against,
}

impl Vote {
	/// REMOVE carries a removal; KEEP blocks it.
	pub fn ballot(self) -> Ballot {
		match self {
			Self::Pending => Ballot::Pending,
			Self::Remove => Ballot::For,
			Self::Keep => Ballot::Against,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::Remove => "remove",
			Self::Keep => "keep",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"pending" => Ok(Self::Pending),
			"remove" => Ok(Self::Remove),
			"keep" => Ok(Self::Keep),
			other => Err(DomainError::Validation(format!("unknown vote: {other}"))),
		}
	}

	pub fn is_cast(self) -> bool {
		self != Self::Pending
	}
}

/// One eligible peer and their answer. The set is SNAPSHOTTED at open, so an owner
/// added afterwards gets no say and an owner removed afterwards cannot be replaced —
/// changing the roster can only make a removal harder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Peer {
	pub user_id: UserId,
	pub vote: Vote,
	pub voted_at: i64,
}

impl Peer {
	pub fn pending(user_id: UserId) -> Self {
		Self {
			user_id,
			vote: Vote::Pending,
			voted_at: 0,
		}
	}
}

/// The verdict of the passing rule over the answers so far.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
	/// Still answerable.
	Pending,
	Passes,
	Fails,
}

/// Unanimity over a NON-EMPTY set of peers — the one rule both consilia share, defined
/// exactly once so a removal and an admission cannot drift apart.
///
/// The emptiness test is the whole of pitfall 18. "Everyone in an empty set agreed" is
/// vacuously TRUE, and a rule that returns `Passes` for nobody is a rule that lets one
/// owner act alone: a two-owner fund would expel by default, and a lone owner could
/// mint an ally. An empty set therefore yields [`Outcome::Fails`], never `Passes`.
pub fn unanimity(ballots: impl Iterator<Item = Ballot>) -> Outcome {
	let mut any = false;
	let mut all_for = true;
	for ballot in ballots {
		any = true;
		match ballot {
			// One block ends it: there is nothing left that could make this unanimous.
			Ballot::Against => return Outcome::Fails,
			Ballot::Pending => all_for = false,
			Ballot::For => {}
		}
	}
	match (any, all_for) {
		(true, true) => Outcome::Passes,
		(true, false) => Outcome::Pending,
		// Nobody may be asked, so nobody can ever carry it.
		(false, _) => Outcome::Fails,
	}
}

/// Simple majority over a NON-EMPTY set of peers — the rule the USER consilia
/// ([`UserProposal`]) pass under, as opposed to the unanimity the OWNER consilia demand.
///
/// WHY THE TWO DIFFER, since a weaker rule always deserves an argument.
///
/// [`unanimity`] guards the roster that decides everything else. Its reason is
/// self-amplification: a minority that could add owners by majority would grow itself
/// into a majority, so the rule must be unbreakable rather than merely hard. Neither
/// thing a [`UserProposal`] decides has that property. `admin` cannot vote in any
/// consilium and `SetRole` refuses `owner` to it, so admitting one adds no voting power
/// and cannot compound; and a suspension is DEFENSIVE and reversible by the same body
/// that imposed it.
///
/// Against that, unanimity here would actively cost safety. A hold lapses in
/// [`crate::users::HOLD_TTL_SECS`], so ratifying one is a race against a clock, and under
/// unanimity a single unreachable owner does not delay the verdict — they decide it, by
/// releasing a compromised account at the deadline. A rule whose failure mode is
/// "the fund unfreezes the attacker because somebody was asleep" is the wrong rule.
///
/// What survives unchanged is the property that actually matters: `needed >= 1` over a
/// non-empty peer set means no single actor ever acts alone — the initiator is excluded
/// from the set and at least one other owner must agree. At two and three owners the
/// majority IS the unanimity; the two only diverge from four owners up, which is
/// precisely where unanimity stops being achievable in an emergency.
///
/// An empty set yields [`Outcome::Fails`] for the same reason it does in [`unanimity`]:
/// a rule that passes for nobody is a rule that lets one owner act alone.
pub fn majority(ballots: impl Iterator<Item = Ballot>) -> Outcome {
	let mut total = 0usize;
	let mut for_ = 0usize;
	let mut against = 0usize;
	for ballot in ballots {
		total += 1;
		match ballot {
			Ballot::For => for_ += 1,
			Ballot::Against => against += 1,
			Ballot::Pending => {}
		}
	}
	if total == 0 {
		return Outcome::Fails;
	}
	let needed = needed_votes(total);
	if for_ >= needed {
		return Outcome::Passes;
	}
	// Even every remaining pending peer voting FOR could not reach the bar, so the
	// proposal is decided now rather than left open until it expires.
	if against > total - needed {
		return Outcome::Fails;
	}
	Outcome::Pending
}

/// How many of `peers` must agree for [`majority`] to pass: `floor(n/2) + 1`. Frozen onto
/// the row at open, so a reader can see the bar a live proposal is actually being
/// measured against rather than re-deriving it from a roster that has since moved.
pub fn needed_votes(peers: usize) -> usize {
	peers / 2 + 1
}

/// A removal's passing rule: EITHER the target accepts, OR the peers are unanimous.
///
/// A peer voting KEEP ends the whole proposal, not merely path (b): the consilium has
/// said no, and a target who WANTS to go resigns rather than accepting an expulsion the
/// fund refused to make.
pub fn outcome(target: Vote, peers: &[Peer]) -> Outcome {
	if target == Vote::Remove {
		return Outcome::Passes;
	}
	// One KEEP ends the WHOLE proposal, not merely path (b), and it does so before the
	// target has answered: the consilium has refused, so there is nothing left to ask.
	if peers.iter().any(|p| p.vote == Vote::Keep) {
		return Outcome::Fails;
	}
	match unanimity(peers.iter().map(|p| p.vote.ballot())) {
		Outcome::Passes => Outcome::Passes,
		// The peer set is EMPTY, so path (b) never existed. Only the target's own
		// mailbox can carry this — and if they have already refused, nothing can.
		Outcome::Fails =>
			if target == Vote::Keep {
				Outcome::Fails
			} else {
				Outcome::Pending
			},
		Outcome::Pending => Outcome::Pending,
	}
}

/// The lifecycle every consilium shares: whether it is still answerable, the single
/// transition that closes it, the version it is on, and the audit events it has raised.
///
/// [`OwnerRemoval`] and [`OwnerAdmission`] EMBED this rather than each restating it.
/// "May this still be answered?" and "what closes it?" must have one answer for both,
/// or the two will drift apart the first time one of them is edited.
#[derive(Clone, Debug)]
struct Lifecycle {
	state: ProposalState,
	created_at: i64,
	expires_at: i64,
	decided_at: i64,
	void_reason: String,
	version: u64,
	pending: Vec<GovernanceEvent>,
}

impl Lifecycle {
	fn opened(now: i64, ttl_secs: i64) -> Self {
		Self {
			state: ProposalState::Open,
			created_at: now,
			expires_at: now.saturating_add(ttl_secs),
			decided_at: 0,
			void_reason: String::new(),
			version: 0,
			pending: Vec::new(),
		}
	}

	fn rehydrate(state: ProposalState, created_at: i64, expires_at: i64, decided_at: i64, void_reason: String, version: u64) -> Self {
		Self {
			state,
			created_at,
			expires_at,
			decided_at,
			void_reason,
			version,
			pending: Vec::new(),
		}
	}

	/// `noun` names the proposal in the error, so a caller reads "the admission is
	/// expired" rather than a generic message.
	fn require_open(&self, noun: &str) -> Result<(), DomainError> {
		if self.state.is_open() {
			Ok(())
		} else {
			Err(DomainError::Conflict(format!("the {noun} is {}", self.state.as_str())))
		}
	}

	fn bump_and_emit(&mut self, event: GovernanceEvent) {
		self.version += 1;
		self.pending.push(event);
	}

	fn close(&mut self, state: ProposalState, event: GovernanceEvent, now: i64) {
		self.state = state;
		self.decided_at = now;
		self.bump_and_emit(event);
	}

	fn close_void(&mut self, reason: &str, now: i64) {
		self.void_reason = reason.chars().take(200).collect();
		self.close(ProposalState::Void, GovernanceEvent::Voided, now);
	}

	/// Time out an unanswered proposal, so a late approval can never carry it.
	fn expire(&mut self, noun: &str, now: i64) -> Result<(), DomainError> {
		if self.state == ProposalState::Expired {
			return Ok(());
		}
		self.require_open(noun)?;
		if now < self.expires_at {
			return Err(DomainError::Conflict("the proposal has not expired yet".into()));
		}
		self.close(ProposalState::Expired, GovernanceEvent::Expired, now);
		Ok(())
	}
}

/// A proposal to take one owner's seat. Construct with [`Self::open`] (raises
/// [`GovernanceEvent::Opened`]) or [`Self::rehydrate`] (loads from the store, silent).
/// Every mutating transition bumps [`Self::version`] and pushes an event the adapter
/// drains in the same transaction as the state change.
#[derive(Clone, Debug)]
pub struct OwnerRemoval {
	id: RemovalId,
	target: UserId,
	initiator: UserId,
	reason: String,
	owner_count: u32,
	peers: Vec<Peer>,
	decision: Vote,
	decided_as_target_at: i64,
	target_notified: bool,
	life: Lifecycle,
}

impl OwnerRemoval {
	/// Propose a removal against the roster as it stands. `owners` is every current
	/// `Role::Owner`; the peer set and `owner_count` are frozen from it here.
	pub fn open(id: RemovalId, target: UserId, initiator: UserId, reason: &str, owners: &[UserId], now: i64, ttl_secs: i64) -> Result<Self, DomainError> {
		let reason = validate_reason(reason)?;
		let reason = reason.as_str();
		if target == initiator {
			return Err(DomainError::Conflict("resign your own seat rather than proposing your own removal".into()));
		}
		if !owners.contains(&initiator) {
			return Err(DomainError::Forbidden("only a fund owner may open a removal".into()));
		}
		if !owners.contains(&target) {
			return Err(DomainError::Validation("the target does not hold an owner seat".into()));
		}
		check_floor(owners.len())?;

		let peers = owners.iter().copied().filter(|o| *o != target && *o != initiator).map(Peer::pending).collect();
		let mut removal = Self {
			id,
			target,
			initiator,
			reason: reason.to_owned(),
			owner_count: owners.len() as u32,
			peers,
			decision: Vote::Pending,
			decided_as_target_at: 0,
			target_notified: false,
			life: Lifecycle::opened(now, ttl_secs),
		};
		removal.life.bump_and_emit(GovernanceEvent::Opened);
		Ok(removal)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn rehydrate(
		id: RemovalId,
		target: UserId,
		initiator: UserId,
		reason: String,
		state: RemovalState,
		owner_count: u32,
		peers: Vec<Peer>,
		decision: Vote,
		decided_as_target_at: i64,
		target_notified: bool,
		created_at: i64,
		expires_at: i64,
		decided_at: i64,
		void_reason: String,
		version: u64,
	) -> Self {
		Self {
			id,
			target,
			initiator,
			reason,
			owner_count,
			peers,
			decision,
			decided_as_target_at,
			target_notified,
			life: Lifecycle::rehydrate(state, created_at, expires_at, decided_at, void_reason, version),
		}
	}

	/// A peer's answer. The target and the initiator are refused because they are not
	/// in the snapshotted set — there is no code path that could accept them.
	pub fn peer_vote(&mut self, voter: UserId, vote: Vote, now: i64) -> Result<(), DomainError> {
		self.require_open()?;
		require_cast(vote)?;
		let Some(peer) = self.peers.iter_mut().find(|p| p.user_id == voter) else {
			return Err(DomainError::Forbidden("you are not an eligible peer on this removal".into()));
		};
		if peer.vote == vote {
			return Ok(());
		}
		if peer.vote.is_cast() {
			return Err(DomainError::Conflict("a cast vote is final".into()));
		}
		peer.vote = vote;
		peer.voted_at = now;
		self.life.bump_and_emit(GovernanceEvent::PeerVoted);
		self.resolve(now);
		Ok(())
	}

	/// The target's own answer, arriving from their mailbox. Repeating the same answer
	/// is a no-op; contradicting it is refused.
	pub fn target_decision(&mut self, vote: Vote, now: i64) -> Result<(), DomainError> {
		self.require_open()?;
		require_cast(vote)?;
		if self.decision == vote {
			return Ok(());
		}
		if self.decision.is_cast() {
			return Err(DomainError::Conflict("this invitation was already answered".into()));
		}
		self.decision = vote;
		self.decided_as_target_at = now;
		self.life.bump_and_emit(GovernanceEvent::TargetDecided);
		self.resolve(now);
		Ok(())
	}

	/// Withdraw a proposal. Only the initiator may.
	pub fn cancel(&mut self, by: UserId, now: i64) -> Result<(), DomainError> {
		if by != self.initiator {
			return Err(DomainError::Forbidden("only the initiator may withdraw a removal".into()));
		}
		if self.state() == ProposalState::Cancelled {
			return Ok(());
		}
		self.require_open()?;
		self.life.close(ProposalState::Cancelled, GovernanceEvent::Cancelled, now);
		Ok(())
	}

	/// Time out an unanswered proposal, so a late approval can never carry it.
	pub fn expire(&mut self, now: i64) -> Result<(), DomainError> {
		self.life.expire("removal", now)
	}

	/// Take the seat, re-deciding against the roster as it stands at THIS moment.
	///
	/// Three things can have moved underneath an open proposal, and all three are
	/// re-checked here rather than trusted from the vote:
	///
	/// * a peer who is no longer an owner does not count, so their REMOVE is dropped
	///   from the tally (a KEEP closed the proposal outright and can never reach here,
	///   which is why re-validating can only make approval HARDER, never easier — and
	///   why a peer set emptied by attrition falls back to the vacuous-unanimity guard);
	/// * the floor: the fund must still be able to spare the seat;
	/// * the initiator's own seat, so a removal opened by someone who has since lost
	///   theirs is void rather than executed.
	///
	/// Returns the resulting state, so the adapter knows whether to flip the role.
	pub fn execute(&mut self, owners_now: &[UserId], now: i64) -> Result<RemovalState, DomainError> {
		if matches!(self.state(), ProposalState::Executed | ProposalState::Void) {
			return Ok(self.state());
		}
		self.require_open()?;
		if self.outcome_among(owners_now) != Outcome::Passes {
			return Err(DomainError::Conflict("the consilium has not passed against the current roster".into()));
		}
		if !owners_now.contains(&self.initiator) {
			self.life.close_void("the initiator no longer holds an owner seat", now);
		} else if owners_now.len().saturating_sub(1) < MIN_OWNERS {
			self.life.close_void("the fund would be left below the owner floor", now);
		} else {
			self.life.close(ProposalState::Executed, GovernanceEvent::Executed, now);
		}
		Ok(self.state())
	}

	/// The verdict counting only peers who still hold a seat.
	pub fn outcome_among(&self, owners_now: &[UserId]) -> Outcome {
		let eligible: Vec<Peer> = self.peers.iter().filter(|p| owners_now.contains(&p.user_id)).cloned().collect();
		outcome(self.decision, &eligible)
	}

	/// Close a passed-but-uncarryable proposal explicitly.
	pub fn void(&mut self, reason: &str, now: i64) -> Result<(), DomainError> {
		if self.state() == ProposalState::Void {
			return Ok(());
		}
		self.require_open()?;
		self.life.close_void(reason, now);
		Ok(())
	}

	/// Record that the target's invitation mail was enqueued.
	pub fn mark_target_notified(&mut self) {
		self.target_notified = true;
	}

	pub fn outcome(&self) -> Outcome {
		outcome(self.decision, &self.peers)
	}

	fn resolve(&mut self, now: i64) {
		if self.state().is_open() && self.outcome() == Outcome::Fails {
			self.life.close(ProposalState::Rejected, GovernanceEvent::Rejected, now);
		}
	}

	fn require_open(&self) -> Result<(), DomainError> {
		self.life.require_open("removal")
	}

	pub fn id(&self) -> RemovalId {
		self.id
	}

	pub fn target(&self) -> UserId {
		self.target
	}

	pub fn initiator(&self) -> UserId {
		self.initiator
	}

	pub fn reason(&self) -> &str {
		&self.reason
	}

	pub fn state(&self) -> ProposalState {
		self.life.state
	}

	pub fn owner_count(&self) -> u32 {
		self.owner_count
	}

	pub fn peers(&self) -> &[Peer] {
		&self.peers
	}

	pub fn decision(&self) -> Vote {
		self.decision
	}

	pub fn decided_as_target_at(&self) -> i64 {
		self.decided_as_target_at
	}

	pub fn target_notified(&self) -> bool {
		self.target_notified
	}

	pub fn created_at(&self) -> i64 {
		self.life.created_at
	}

	pub fn expires_at(&self) -> i64 {
		self.life.expires_at
	}

	pub fn decided_at(&self) -> i64 {
		self.life.decided_at
	}

	pub fn void_reason(&self) -> &str {
		&self.life.void_reason
	}

	pub fn version(&self) -> u64 {
		self.life.version
	}
}

/// The floor, as one function so `open` and `execute` cannot drift apart. `owners` is
/// the roster BEFORE the removal; one seat is about to go. Admission has no floor —
/// growing the roster can never breach one.
pub fn check_floor(owners: usize) -> Result<(), DomainError> {
	if owners.saturating_sub(1) < MIN_OWNERS {
		return Err(DomainError::Conflict(format!(
			"a fund must keep at least {MIN_OWNERS} owners, and this would leave {}",
			owners.saturating_sub(1)
		)));
	}
	Ok(())
}

/// The reason field both consilia carry, validated once. Trimmed, non-empty, and
/// bounded by the same SQL CHECK on either table.
fn validate_reason(reason: &str) -> Result<String, DomainError> {
	let reason = reason.trim();
	if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
		return Err(DomainError::Validation(format!("reason must be 1-{MAX_REASON_CHARS} characters")));
	}
	Ok(reason.to_owned())
}

fn require_cast(vote: Vote) -> Result<(), DomainError> {
	if vote.is_cast() {
		Ok(())
	} else {
		Err(DomainError::Validation("a vote must be REMOVE or KEEP".into()))
	}
}

/// The audit facts a proposal raises. Unlike [`crate::users::UserEvent`] these do NOT
/// cross the bridge — the money plane runs its own consilium over its own mirrored
/// roster. The seat change itself still emits `ROLE_CHANGED` through the `User`
/// aggregate, so banking sees the effect without trusting this plane's verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GovernanceEvent {
	Opened,
	PeerVoted,
	TargetDecided,
	Cancelled,
	Expired,
	Executed,
	Rejected,
	Voided,
}

impl GovernanceEvent {
	pub fn kind(self) -> &'static str {
		match self {
			Self::Opened => "OPENED",
			Self::PeerVoted => "PEER_VOTED",
			Self::TargetDecided => "TARGET_DECIDED",
			Self::Cancelled => "CANCELLED",
			Self::Expired => "EXPIRED",
			Self::Executed => "EXECUTED",
			Self::Rejected => "REJECTED",
			Self::Voided => "VOIDED",
		}
	}
}

/// One peer's answer on an admission. ADMIT carries it; REJECT blocks it outright,
/// because admission passes only on unanimity.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionVote {
	#[default]
	Pending,
	Admit,
	Reject,
}

impl AdmissionVote {
	/// ADMIT carries an admission; REJECT blocks it. The projection that lets
	/// [`unanimity`] be the one definition of the rule for both consilia.
	pub fn ballot(self) -> Ballot {
		match self {
			Self::Pending => Ballot::Pending,
			Self::Admit => Ballot::For,
			Self::Reject => Ballot::Against,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::Admit => "admit",
			Self::Reject => "reject",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"pending" => Ok(Self::Pending),
			"admit" => Ok(Self::Admit),
			"reject" => Ok(Self::Reject),
			other => Err(DomainError::Validation(format!("unknown admission vote: {other}"))),
		}
	}

	pub fn is_cast(self) -> bool {
		self != Self::Pending
	}
}

/// One eligible voter on an admission and their answer. Snapshotted at open exactly as
/// [`Peer`] is, for the same reason: the roster must not be able to move underneath a
/// live proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionPeer {
	pub user_id: UserId,
	pub vote: AdmissionVote,
	pub voted_at: i64,
}

impl AdmissionPeer {
	pub fn pending(user_id: UserId) -> Self {
		Self {
			user_id,
			vote: AdmissionVote::Pending,
			voted_at: 0,
		}
	}
}

/// A proposal to GRANT a seat — the control without which every other control in this
/// module is decorative.
///
/// `SetRole` used to let any single owner mint an owner. That is the whole attack: a bad
/// actor adds four sock puppets, and then a payout consilium of seven with a threshold
/// of four is carried by the puppets alone, legitimately, with every snapshot and every
/// re-validation working exactly as designed. Snapshotting cannot help, because the
/// stuffing happens BEFORE the proposal opens.
///
/// So admission is itself a consilium: unanimity of `owners \ {initiator}`, with at
/// least one such peer. UNANIMITY, not a majority — a minority that could add owners by
/// majority would grow itself into a majority, which is the same attack with extra
/// steps. There is no emailed token and no candidate vote: the candidate is not yet an
/// owner and has no say in their own admission, and every voter is a signed-in owner.
#[derive(Clone, Debug)]
pub struct OwnerAdmission {
	id: AdmissionId,
	candidate: UserId,
	initiator: UserId,
	reason: String,
	owner_count: u32,
	peers: Vec<AdmissionPeer>,
	life: Lifecycle,
}

impl OwnerAdmission {
	/// Propose a candidate against the roster as it stands.
	///
	/// An EMPTY peer set is refused here rather than left to fail later: admission has
	/// no second path, so a lone owner's proposal could never pass, and an open
	/// proposal that is already unpassable is a trap for whoever reads the console.
	pub fn open(id: AdmissionId, candidate: UserId, initiator: UserId, reason: &str, owners: &[UserId], now: i64, ttl_secs: i64) -> Result<Self, DomainError> {
		let reason = validate_reason(reason)?;
		if candidate == initiator {
			return Err(DomainError::Conflict("you cannot propose your own admission".into()));
		}
		if !owners.contains(&initiator) {
			return Err(DomainError::Forbidden("only a fund owner may open an admission".into()));
		}
		if owners.contains(&candidate) {
			return Err(DomainError::Conflict("the candidate already holds an owner seat".into()));
		}
		let peers: Vec<AdmissionPeer> = owners.iter().copied().filter(|o| *o != initiator).map(AdmissionPeer::pending).collect();
		if peers.is_empty() {
			return Err(DomainError::Conflict(
				"an admission needs at least one other owner to agree, and there is none — a lone owner cannot mint a second".into(),
			));
		}
		let mut admission = Self {
			id,
			candidate,
			initiator,
			reason,
			owner_count: owners.len() as u32,
			peers,
			life: Lifecycle::opened(now, ttl_secs),
		};
		admission.life.bump_and_emit(GovernanceEvent::Opened);
		Ok(admission)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn rehydrate(
		id: AdmissionId,
		candidate: UserId,
		initiator: UserId,
		reason: String,
		state: ProposalState,
		owner_count: u32,
		peers: Vec<AdmissionPeer>,
		created_at: i64,
		expires_at: i64,
		decided_at: i64,
		void_reason: String,
		version: u64,
	) -> Self {
		Self {
			id,
			candidate,
			initiator,
			reason,
			owner_count,
			peers,
			life: Lifecycle::rehydrate(state, created_at, expires_at, decided_at, void_reason, version),
		}
	}

	/// One peer's answer. The initiator and the candidate are refused because neither is
	/// in the snapshotted set — structural, not a check somebody can forget.
	pub fn vote(&mut self, voter: UserId, vote: AdmissionVote, now: i64) -> Result<(), DomainError> {
		self.require_open()?;
		if !vote.is_cast() {
			return Err(DomainError::Validation("a vote must be ADMIT or REJECT".into()));
		}
		let Some(peer) = self.peers.iter_mut().find(|p| p.user_id == voter) else {
			return Err(DomainError::Forbidden("you are not an eligible voter on this admission".into()));
		};
		if peer.vote == vote {
			return Ok(());
		}
		if peer.vote.is_cast() {
			return Err(DomainError::Conflict("a cast vote is final".into()));
		}
		peer.vote = vote;
		peer.voted_at = now;
		self.life.bump_and_emit(GovernanceEvent::PeerVoted);
		if self.state().is_open() && self.outcome() == Outcome::Fails {
			self.life.close(ProposalState::Rejected, GovernanceEvent::Rejected, now);
		}
		Ok(())
	}

	/// Withdraw a proposal. Only the initiator may.
	pub fn cancel(&mut self, by: UserId, now: i64) -> Result<(), DomainError> {
		if by != self.initiator {
			return Err(DomainError::Forbidden("only the initiator may withdraw an admission".into()));
		}
		if self.state() == ProposalState::Cancelled {
			return Ok(());
		}
		self.require_open()?;
		self.life.close(ProposalState::Cancelled, GovernanceEvent::Cancelled, now);
		Ok(())
	}

	pub fn expire(&mut self, now: i64) -> Result<(), DomainError> {
		self.life.expire("admission", now)
	}

	/// Grant the seat, re-deciding against the roster as it stands at THIS moment.
	///
	/// Two things can have moved underneath an open admission, and both are re-checked
	/// here rather than trusted from the vote:
	///
	/// * a voter who has since lost their own seat does not count, so their ADMIT is
	///   dropped from the tally — which is why a roster that moves can only make an
	///   admission HARDER, and why a set emptied by attrition falls back to the
	///   non-empty guard in [`unanimity`] and voids instead of passing vacuously;
	/// * the initiator's own seat, so an admission opened by someone who has since lost
	///   theirs is void rather than executed.
	pub fn execute(&mut self, owners_now: &[UserId], now: i64) -> Result<ProposalState, DomainError> {
		if matches!(self.state(), ProposalState::Executed | ProposalState::Void) {
			return Ok(self.state());
		}
		self.require_open()?;
		if self.outcome_among(owners_now) != Outcome::Passes {
			return Err(DomainError::Conflict("the consilium has not passed against the current roster".into()));
		}
		if !owners_now.contains(&self.initiator) {
			self.life.close_void("the initiator no longer holds an owner seat", now);
		} else if owners_now.contains(&self.candidate) {
			// Another admission already seated them; granting twice is not an error but
			// this proposal did not do it.
			self.life.close_void("the candidate already holds an owner seat", now);
		} else {
			self.life.close(ProposalState::Executed, GovernanceEvent::Executed, now);
		}
		Ok(self.state())
	}

	/// Close a passed-but-uncarryable admission explicitly, the way [`Self::execute`]
	/// closes the cases it can detect itself.
	pub fn void(&mut self, reason: &str, now: i64) -> Result<(), DomainError> {
		if self.state() == ProposalState::Void {
			return Ok(());
		}
		self.require_open()?;
		self.life.close_void(reason, now);
		Ok(())
	}

	/// The verdict counting only voters who still hold a seat.
	pub fn outcome_among(&self, owners_now: &[UserId]) -> Outcome {
		unanimity(self.peers.iter().filter(|p| owners_now.contains(&p.user_id)).map(|p| p.vote.ballot()))
	}

	pub fn outcome(&self) -> Outcome {
		unanimity(self.peers.iter().map(|p| p.vote.ballot()))
	}

	fn require_open(&self) -> Result<(), DomainError> {
		self.life.require_open("admission")
	}

	pub fn id(&self) -> AdmissionId {
		self.id
	}

	pub fn candidate(&self) -> UserId {
		self.candidate
	}

	pub fn initiator(&self) -> UserId {
		self.initiator
	}

	pub fn reason(&self) -> &str {
		&self.reason
	}

	pub fn state(&self) -> ProposalState {
		self.life.state
	}

	pub fn owner_count(&self) -> u32 {
		self.owner_count
	}

	pub fn peers(&self) -> &[AdmissionPeer] {
		&self.peers
	}

	pub fn created_at(&self) -> i64 {
		self.life.created_at
	}

	pub fn expires_at(&self) -> i64 {
		self.life.expires_at
	}

	pub fn decided_at(&self) -> i64 {
		self.life.decided_at
	}

	pub fn void_reason(&self) -> &str {
		&self.life.void_reason
	}

	pub fn version(&self) -> u64 {
		self.life.version
	}
}

impl Entity for OwnerAdmission {
	type Id = AdmissionId;

	fn id(&self) -> AdmissionId {
		self.id
	}
}

impl AggregateRoot for OwnerAdmission {
	const NAME: &'static str = "owner_admission";
}

impl EmitsEvents for OwnerAdmission {
	type Event = GovernanceEvent;

	fn drain_events(&mut self) -> Vec<GovernanceEvent> {
		core::mem::take(&mut self.life.pending)
	}
}

impl Entity for OwnerRemoval {
	type Id = RemovalId;

	fn id(&self) -> RemovalId {
		self.id
	}
}

impl AggregateRoot for OwnerRemoval {
	const NAME: &'static str = "owner_removal";
}

impl EmitsEvents for OwnerRemoval {
	type Event = GovernanceEvent;

	fn drain_events(&mut self) -> Vec<GovernanceEvent> {
		core::mem::take(&mut self.life.pending)
	}
}

impl DomainEvent for GovernanceEvent {
	const KIND: &'static str = "governance";
}

/// A user consilium's identity. Its own tag, so it can never be passed where an owner
/// proposal's id is expected.
pub type UserProposalId = Id<UserProposalTag>;
/// Phantom tag making [`UserProposalId`] incompatible with [`RemovalId`]/[`AdmissionId`].
pub struct UserProposalTag;

/// What a [`UserProposal`] decides. THREE KINDS, ONE AGGREGATE — deliberately, because
/// all three are the same question ("do the owners agree to change this person's
/// standing?") differing only in which field of the [`crate::users::User`] the verdict
/// writes. Three copies of the lifecycle, the snapshotting and the passing rule would
/// drift the first time one of them was edited, which is the same argument [`Lifecycle`]
/// itself is built on.
///
/// The execution effects are exhaustively matched wherever they are applied, so a fourth
/// kind breaks the build rather than silently executing as nothing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserProposalKind {
	/// Freeze the subject until the owners say otherwise — the permanent half of the
	/// verb whose emergency half is [`crate::users::User::hold`].
	Suspension,
	/// Lift a suspension the owners themselves imposed. It exists so that a single admin
	/// cannot overturn their verdict from the console: reinstatement stays one act for a
	/// hold, and becomes a proposal for a ratified suspension.
	Reinstatement,
	/// Grant `Role::Admin`. `SetRole` refuses that role and names this, for the same
	/// reason it already refuses `Role::Owner`: an operator who can appoint operators is
	/// an operator who can appoint accomplices, and every identity mutation except role
	/// granting comes with the seat.
	AdminAdmission,
}

impl UserProposalKind {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Suspension => "suspension",
			Self::Reinstatement => "reinstatement",
			Self::AdminAdmission => "admin_admission",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"suspension" => Ok(Self::Suspension),
			"reinstatement" => Ok(Self::Reinstatement),
			"admin_admission" => Ok(Self::AdminAdmission),
			other => Err(DomainError::Validation(format!("unknown user proposal kind: {other}"))),
		}
	}

	/// The RPC a refusal should name, so an operator who is told "no" is told where to go.
	pub fn rpc_name(self) -> &'static str {
		match self {
			Self::Suspension => "GovernanceService.OpenUserSuspension",
			Self::Reinstatement => "GovernanceService.OpenUserReinstatement",
			Self::AdminAdmission => "GovernanceService.OpenAdminAdmission",
		}
	}
}

/// One owner's answer on a [`UserProposal`].
///
/// The verbs are neutral — FOR and AGAINST — where the owner consilia use
/// remove/keep and admit/reject. Three kinds share this aggregate, so a stored verb
/// would have to be read against the kind to mean anything, and a vocabulary that is
/// only correct when cross-referenced is a vocabulary that will eventually be rendered
/// wrong. The kind-specific verb belongs on the SURFACE, which knows the kind; the
/// stored fact is which way the voter pushed, which is exactly [`Ballot`].
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalVote {
	#[default]
	Pending,
	For,
	Against,
}

impl ProposalVote {
	pub fn ballot(self) -> Ballot {
		match self {
			Self::Pending => Ballot::Pending,
			Self::For => Ballot::For,
			Self::Against => Ballot::Against,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::For => "for",
			Self::Against => "against",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"pending" => Ok(Self::Pending),
			"for" => Ok(Self::For),
			"against" => Ok(Self::Against),
			other => Err(DomainError::Validation(format!("unknown proposal vote: {other}"))),
		}
	}

	pub fn is_cast(self) -> bool {
		self != Self::Pending
	}
}

/// One eligible owner on a [`UserProposal`] and their answer. Snapshotted at open for
/// the same reason [`Peer`] and [`AdmissionPeer`] are: the roster must not be able to
/// move underneath a live proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalPeer {
	pub user_id: UserId,
	pub vote: ProposalVote,
	pub voted_at: i64,
}

impl ProposalPeer {
	pub fn pending(user_id: UserId) -> Self {
		Self {
			user_id,
			vote: ProposalVote::Pending,
			voted_at: 0,
		}
	}
}

/// The owners' verdict over one PERSON's standing — suspended, reinstated, or made an
/// admin.
///
/// It is the same shape as [`OwnerAdmission`] and embeds the same [`Lifecycle`], with two
/// deliberate differences.
///
/// It passes on [`majority`] rather than [`unanimity`] — argued in full on that function,
/// and the short form is that neither a suspension nor an `admin` seat can amplify
/// itself into control of the fund, while a hold racing a 24h clock makes an unreachable
/// owner into a decision-maker.
///
/// And the SUBJECT need not be an owner: these proposals are about any user, which is why
/// the roster checks that guard [`OwnerAdmission`] ("the candidate already holds a seat",
/// the floor) have no analogue here. The INITIATOR still must be an owner — the peer set
/// is `owners \ {initiator}`, so a non-owner initiator would not be excluded from the
/// body judging their own proposal.
#[derive(Clone, Debug)]
pub struct UserProposal {
	id: UserProposalId,
	kind: UserProposalKind,
	subject: UserId,
	initiator: UserId,
	reason: String,
	owner_count: u32,
	/// The bar, frozen at open: how many of the snapshotted peers must vote FOR. Stored
	/// rather than re-derived so a surface shows the bar this proposal is actually
	/// measured against.
	threshold: u32,
	peers: Vec<ProposalPeer>,
	life: Lifecycle,
}

impl UserProposal {
	/// Propose against the roster as it stands. An EMPTY peer set is refused here rather
	/// than left to fail later: a lone owner's proposal could never pass, and an open
	/// proposal that is already unpassable is a trap for whoever reads the console.
	#[allow(clippy::too_many_arguments)]
	pub fn open(id: UserProposalId, kind: UserProposalKind, subject: UserId, initiator: UserId, reason: &str, owners: &[UserId], now: i64, ttl_secs: i64) -> Result<Self, DomainError> {
		let reason = validate_reason(reason)?;
		if !owners.contains(&initiator) {
			return Err(DomainError::Forbidden("only a fund owner may open a user proposal".into()));
		}
		if subject == initiator {
			return Err(DomainError::Conflict("you cannot open a user proposal about yourself".into()));
		}
		let peers: Vec<ProposalPeer> = owners.iter().copied().filter(|o| *o != initiator).map(ProposalPeer::pending).collect();
		if peers.is_empty() {
			return Err(DomainError::Conflict(
				"a user proposal needs at least one other owner to agree, and there is none — one owner may not decide alone".into(),
			));
		}
		let threshold = needed_votes(peers.len()) as u32;
		let mut proposal = Self {
			id,
			kind,
			subject,
			initiator,
			reason,
			owner_count: owners.len() as u32,
			threshold,
			peers,
			life: Lifecycle::opened(now, ttl_secs),
		};
		proposal.life.bump_and_emit(GovernanceEvent::Opened);
		Ok(proposal)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn rehydrate(
		id: UserProposalId,
		kind: UserProposalKind,
		subject: UserId,
		initiator: UserId,
		reason: String,
		state: ProposalState,
		owner_count: u32,
		threshold: u32,
		peers: Vec<ProposalPeer>,
		created_at: i64,
		expires_at: i64,
		decided_at: i64,
		void_reason: String,
		version: u64,
	) -> Self {
		Self {
			id,
			kind,
			subject,
			initiator,
			reason,
			owner_count,
			threshold,
			peers,
			life: Lifecycle::rehydrate(state, created_at, expires_at, decided_at, void_reason, version),
		}
	}

	/// One owner's answer. The initiator is refused because they are not in the
	/// snapshotted set — structural, not a check somebody can forget.
	pub fn vote(&mut self, voter: UserId, vote: ProposalVote, now: i64) -> Result<(), DomainError> {
		self.require_open()?;
		if !vote.is_cast() {
			return Err(DomainError::Validation("a vote must be FOR or AGAINST".into()));
		}
		let Some(peer) = self.peers.iter_mut().find(|p| p.user_id == voter) else {
			return Err(DomainError::Forbidden("you are not an eligible voter on this proposal".into()));
		};
		if peer.vote == vote {
			return Ok(());
		}
		if peer.vote.is_cast() {
			return Err(DomainError::Conflict("a cast vote is final".into()));
		}
		peer.vote = vote;
		peer.voted_at = now;
		self.life.bump_and_emit(GovernanceEvent::PeerVoted);
		if self.state().is_open() && self.outcome() == Outcome::Fails {
			self.life.close(ProposalState::Rejected, GovernanceEvent::Rejected, now);
		}
		Ok(())
	}

	/// Withdraw a proposal. Only the initiator may.
	pub fn cancel(&mut self, by: UserId, now: i64) -> Result<(), DomainError> {
		if by != self.initiator {
			return Err(DomainError::Forbidden("only the initiator may withdraw a proposal".into()));
		}
		if self.state() == ProposalState::Cancelled {
			return Ok(());
		}
		self.require_open()?;
		self.life.close(ProposalState::Cancelled, GovernanceEvent::Cancelled, now);
		Ok(())
	}

	pub fn expire(&mut self, now: i64) -> Result<(), DomainError> {
		self.life.expire("proposal", now)
	}

	/// Carry the verdict, re-deciding against the roster as it stands at THIS moment.
	///
	/// Two things can have moved underneath an open proposal, and both are re-checked
	/// here rather than trusted from the vote: a voter who has since lost their seat does
	/// not count (so a set emptied by attrition falls back to the non-empty guard in
	/// [`majority`] and voids instead of passing over nobody), and the initiator's own
	/// seat, so a proposal opened by someone who has since lost theirs is void rather
	/// than executed.
	///
	/// Returns the resulting state, so the adapter knows whether to apply the effect.
	pub fn execute(&mut self, owners_now: &[UserId], now: i64) -> Result<ProposalState, DomainError> {
		if matches!(self.state(), ProposalState::Executed | ProposalState::Void) {
			return Ok(self.state());
		}
		self.require_open()?;
		if self.outcome_among(owners_now) != Outcome::Passes {
			return Err(DomainError::Conflict("the consilium has not passed against the current roster".into()));
		}
		if owners_now.contains(&self.initiator) {
			self.life.close(ProposalState::Executed, GovernanceEvent::Executed, now);
		} else {
			self.life.close_void("the initiator no longer holds an owner seat", now);
		}
		Ok(self.state())
	}

	/// Close a passed-but-uncarryable proposal explicitly.
	pub fn void(&mut self, reason: &str, now: i64) -> Result<(), DomainError> {
		if self.state() == ProposalState::Void {
			return Ok(());
		}
		self.require_open()?;
		self.life.close_void(reason, now);
		Ok(())
	}

	/// The verdict counting only voters who still hold a seat.
	pub fn outcome_among(&self, owners_now: &[UserId]) -> Outcome {
		majority(self.peers.iter().filter(|p| owners_now.contains(&p.user_id)).map(|p| p.vote.ballot()))
	}

	pub fn outcome(&self) -> Outcome {
		majority(self.peers.iter().map(|p| p.vote.ballot()))
	}

	fn require_open(&self) -> Result<(), DomainError> {
		self.life.require_open("proposal")
	}

	pub fn id(&self) -> UserProposalId {
		self.id
	}

	pub fn kind(&self) -> UserProposalKind {
		self.kind
	}

	pub fn subject(&self) -> UserId {
		self.subject
	}

	pub fn initiator(&self) -> UserId {
		self.initiator
	}

	pub fn reason(&self) -> &str {
		&self.reason
	}

	pub fn state(&self) -> ProposalState {
		self.life.state
	}

	pub fn owner_count(&self) -> u32 {
		self.owner_count
	}

	pub fn threshold(&self) -> u32 {
		self.threshold
	}

	pub fn peers(&self) -> &[ProposalPeer] {
		&self.peers
	}

	pub fn created_at(&self) -> i64 {
		self.life.created_at
	}

	pub fn expires_at(&self) -> i64 {
		self.life.expires_at
	}

	pub fn decided_at(&self) -> i64 {
		self.life.decided_at
	}

	pub fn void_reason(&self) -> &str {
		&self.life.void_reason
	}

	pub fn version(&self) -> u64 {
		self.life.version
	}
}

impl Entity for UserProposal {
	type Id = UserProposalId;

	fn id(&self) -> UserProposalId {
		self.id
	}
}

impl AggregateRoot for UserProposal {
	const NAME: &'static str = "user_proposal";
}

impl EmitsEvents for UserProposal {
	type Event = GovernanceEvent;

	fn drain_events(&mut self) -> Vec<GovernanceEvent> {
		core::mem::take(&mut self.life.pending)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn ids(n: usize) -> Vec<UserId> {
		(0..n).map(|_| UserId::new()).collect()
	}

	fn peers_voting(votes: &[Vote]) -> Vec<Peer> {
		votes
			.iter()
			.map(|v| Peer {
				user_id: UserId::new(),
				vote: *v,
				voted_at: if v.is_cast() { 1 } else { 0 },
			})
			.collect()
	}

	/// `open` on a roster of `n`, target and initiator being the first two owners.
	fn opened(n: usize) -> Result<OwnerRemoval, DomainError> {
		let owners = ids(n);
		OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 1_000, REMOVAL_TTL_SECS)
	}

	fn admission(n: usize) -> (Vec<UserId>, UserId, OwnerAdmission) {
		let owners = ids(n);
		let candidate = UserId::new();
		let admission = OwnerAdmission::open(AdmissionId::new(), candidate, owners[0], "a new partner", &owners, 1_000, REMOVAL_TTL_SECS).expect("open");
		(owners, candidate, admission)
	}

	/// Pitfall 18's rule, stated on the shared helper itself: a rule that passes for
	/// nobody is a rule that lets one person act alone.
	#[test]
	fn unanimity_over_an_empty_set_never_passes() {
		assert_eq!(unanimity([].into_iter()), Outcome::Fails);
		assert_eq!(unanimity([Ballot::For].into_iter()), Outcome::Passes);
		assert_eq!(unanimity([Ballot::For, Ballot::Pending].into_iter()), Outcome::Pending);
		assert_eq!(unanimity([Ballot::For, Ballot::Against].into_iter()), Outcome::Fails);
		assert_eq!(
			unanimity([Ballot::Pending, Ballot::Against].into_iter()),
			Outcome::Fails,
			"one block ends it before the rest answer"
		);
	}

	/// Pitfall 21. This is the whole point of the admission consilium: if one owner
	/// could mint another, they could mint four and carry any quorum legitimately.
	#[test]
	fn a_lone_owner_cannot_mint_a_second() {
		let owners = ids(1);
		let err = OwnerAdmission::open(AdmissionId::new(), UserId::new(), owners[0], "my friend", &owners, 0, 100).unwrap_err();
		assert!(matches!(err, DomainError::Conflict(_)), "a lone owner has no peer to agree: {err}");
	}

	#[test]
	fn admission_passes_only_on_unanimity_of_every_other_owner() {
		let (owners, _, mut admission) = admission(3);
		assert_eq!(admission.peers().len(), 2, "owners \\ {{initiator}}");

		admission.vote(owners[1], AdmissionVote::Admit, 1).unwrap();
		assert_eq!(admission.outcome(), Outcome::Pending, "a majority is not enough — a minority must not grow itself");
		assert_eq!(admission.state(), RemovalState::Open);

		admission.vote(owners[2], AdmissionVote::Admit, 2).unwrap();
		assert_eq!(admission.outcome(), Outcome::Passes);
		assert_eq!(admission.execute(&owners, 3).unwrap(), RemovalState::Executed);
		assert_eq!(admission.execute(&owners, 4).unwrap(), RemovalState::Executed, "execution is idempotent");
	}

	#[test]
	fn one_reject_ends_an_admission_immediately() {
		let (owners, _, mut admission) = admission(3);
		admission.vote(owners[1], AdmissionVote::Reject, 1).unwrap();
		assert_eq!(admission.state(), RemovalState::Rejected, "no need to wait for the rest");
		let err = admission.vote(owners[2], AdmissionVote::Admit, 2).unwrap_err();
		assert!(matches!(err, DomainError::Conflict(_)), "a closed admission takes no more votes: {err}");
	}

	#[test]
	fn neither_the_candidate_nor_the_initiator_votes_on_an_admission() {
		let (owners, candidate, mut admission) = admission(3);
		let voters: Vec<UserId> = admission.peers().iter().map(|p| p.user_id).collect();
		assert!(!voters.contains(&owners[0]), "the initiator is not a voter — proposing is not agreeing");
		assert!(!voters.contains(&candidate), "the candidate has no say in their own admission");

		for who in [owners[0], candidate, UserId::new()] {
			let err = admission.vote(who, AdmissionVote::Admit, 1).unwrap_err();
			assert!(matches!(err, DomainError::Forbidden(_)), "{who} must not be able to vote: {err}");
		}
	}

	#[test]
	fn an_admission_cannot_seat_someone_who_already_has_a_seat() {
		let owners = ids(3);
		let err = OwnerAdmission::open(AdmissionId::new(), owners[1], owners[0], "again", &owners, 0, 100).unwrap_err();
		assert!(matches!(err, DomainError::Conflict(_)), "{err}");
	}

	/// The execution-time re-check, mirroring the removal's: the roster moving can only
	/// make an admission harder.
	#[test]
	fn an_admission_voids_when_the_roster_moved_underneath_it() {
		let (owners, candidate, _) = admission(3);
		let passed = || {
			let mut a = OwnerAdmission::open(AdmissionId::new(), candidate, owners[0], "a new partner", &owners, 0, 100).unwrap();
			a.vote(owners[1], AdmissionVote::Admit, 1).unwrap();
			a.vote(owners[2], AdmissionVote::Admit, 2).unwrap();
			a
		};

		// The initiator lost their own seat between the vote and the execution.
		let without_initiator: Vec<UserId> = owners.iter().copied().filter(|o| *o != owners[0]).collect();
		let mut lost_seat = passed();
		assert_eq!(lost_seat.execute(&without_initiator, 3).unwrap(), RemovalState::Void);
		assert!(lost_seat.void_reason().contains("initiator"));

		// Somebody else seated the candidate first.
		let already: Vec<UserId> = owners.iter().copied().chain([candidate]).collect();
		let mut duplicate = passed();
		assert_eq!(duplicate.execute(&already, 3).unwrap(), RemovalState::Void);
		assert!(duplicate.void_reason().contains("already holds"));

		// Attrition emptied the voter set: their ADMITs no longer count, and unanimity
		// over nobody must NOT pass.
		let mut attrition = passed();
		let err = attrition.execute(&[owners[0]], 3).unwrap_err();
		assert!(matches!(err, DomainError::Conflict(_)), "an emptied voter set cannot carry it: {err}");
		assert_eq!(attrition.state(), RemovalState::Open, "and it is not silently executed either");
	}

	#[test]
	fn an_expired_admission_takes_no_votes() {
		let (owners, _, mut admission) = admission(3);
		admission.expire(1_000 + REMOVAL_TTL_SECS).unwrap();
		assert_eq!(admission.state(), RemovalState::Expired);
		let err = admission.vote(owners[1], AdmissionVote::Admit, 1_000 + REMOVAL_TTL_SECS + 1).unwrap_err();
		assert!(matches!(err, DomainError::Conflict(_)), "{err}");
	}

	#[test]
	fn admission_vote_round_trips_and_only_the_initiator_cancels() {
		for vote in [AdmissionVote::Pending, AdmissionVote::Admit, AdmissionVote::Reject] {
			assert_eq!(AdmissionVote::parse(vote.as_str()).unwrap(), vote);
		}
		assert!(AdmissionVote::parse("maybe").is_err());

		let (owners, _, mut admission) = admission(3);
		assert!(matches!(admission.cancel(owners[1], 1).unwrap_err(), DomainError::Forbidden(_)));
		admission.cancel(owners[0], 1).unwrap();
		assert_eq!(admission.state(), RemovalState::Cancelled);
		admission.cancel(owners[0], 2).unwrap();
	}

	#[test]
	fn state_and_vote_round_trip_through_str() {
		for state in [
			RemovalState::Open,
			RemovalState::Executed,
			RemovalState::Rejected,
			RemovalState::Expired,
			RemovalState::Cancelled,
			RemovalState::Void,
		] {
			assert_eq!(RemovalState::parse(state.as_str()).unwrap(), state);
		}
		for vote in [Vote::Pending, Vote::Remove, Vote::Keep] {
			assert_eq!(Vote::parse(vote.as_str()).unwrap(), vote);
		}
		assert!(RemovalState::parse("nope").is_err());
		assert!(Vote::parse("maybe").is_err());
	}

	/// Pitfall 18. The peer set for `N` owners is `N - 2`; at `N = 2` it is EMPTY, and
	/// an all-of over an empty set is vacuously true. Path (b) must not pass there.
	#[test]
	fn vacuous_unanimity_cannot_expel_a_two_owner_fund() {
		assert_eq!(outcome(Vote::Pending, &[]), Outcome::Pending, "with no peers, only the target can carry it");
		assert_eq!(outcome(Vote::Keep, &[]), Outcome::Fails, "and if they refuse, there is nothing left to wait for");
		assert_eq!(outcome(Vote::Remove, &[]), Outcome::Passes, "path (a) is the ONLY route at two owners");
	}

	#[test]
	fn passing_rule_over_every_roster_size() {
		// (owners, target answer, peer answers) → verdict. Peers are always N - 2.
		let cases: &[(usize, Vote, &[Vote], Outcome)] = &[
			(2, Vote::Pending, &[], Outcome::Pending),
			(2, Vote::Remove, &[], Outcome::Passes),
			(2, Vote::Keep, &[], Outcome::Fails),
			(3, Vote::Pending, &[Vote::Pending], Outcome::Pending),
			(3, Vote::Pending, &[Vote::Remove], Outcome::Passes),
			(3, Vote::Keep, &[Vote::Remove], Outcome::Passes),
			(3, Vote::Pending, &[Vote::Keep], Outcome::Fails),
			(4, Vote::Pending, &[Vote::Remove, Vote::Pending], Outcome::Pending),
			(4, Vote::Pending, &[Vote::Remove, Vote::Remove], Outcome::Passes),
			(4, Vote::Pending, &[Vote::Remove, Vote::Keep], Outcome::Fails),
			(4, Vote::Remove, &[Vote::Keep, Vote::Keep], Outcome::Passes),
			(5, Vote::Pending, &[Vote::Remove, Vote::Remove, Vote::Pending], Outcome::Pending),
			(5, Vote::Pending, &[Vote::Remove, Vote::Remove, Vote::Remove], Outcome::Passes),
			(6, Vote::Pending, &[Vote::Remove, Vote::Remove, Vote::Remove, Vote::Keep], Outcome::Fails),
			(7, Vote::Pending, &[Vote::Remove; 5], Outcome::Passes),
			(7, Vote::Keep, &[Vote::Remove, Vote::Remove, Vote::Remove, Vote::Remove, Vote::Pending], Outcome::Pending),
		];
		for (n, target, votes, expected) in cases {
			assert_eq!(votes.len(), n - 2, "the peer set for {n} owners is N - 2");
			assert_eq!(outcome(*target, &peers_voting(votes)), *expected, "N={n}, target={:?}, peers={votes:?}", target);
		}
	}

	/// Path (a) is unconditional: an owner who accepts their own removal carries it
	/// even against a peer set that refused.
	#[test]
	fn target_acceptance_outranks_a_keeping_peer() {
		assert_eq!(outcome(Vote::Remove, &peers_voting(&[Vote::Keep, Vote::Keep])), Outcome::Passes);
	}

	#[test]
	fn floor_refuses_a_removal_that_would_leave_too_few() {
		for owners in 0..=MIN_OWNERS {
			assert!(check_floor(owners).is_err(), "{owners} owners cannot spare one");
		}
		assert!(check_floor(MIN_OWNERS + 1).is_ok(), "one to spare is exactly enough");
		let err = opened(2).unwrap_err();
		assert!(matches!(err, DomainError::Conflict(_)), "two owners cannot spare one: {err}");
		assert!(opened(3).is_ok(), "three owners may drop to two — the floor is 2, not 3");
	}

	/// The case the floor was lowered FOR. At three owners the peer set is exactly one,
	/// so the two honest owners can expel the third and land on two; under the old floor
	/// of three this was refused, which made a bad actor in a fund of three permanently
	/// unremovable — removal blocked by the floor, and admitting an ally to get past it
	/// needing the bad actor's own agreement.
	#[test]
	fn a_fund_of_three_removes_its_bad_actor_and_lands_on_two() {
		let owners = ids(3);
		let (target, initiator, peer) = (owners[0], owners[1], owners[2]);
		let mut removal = OwnerRemoval::open(RemovalId::new(), target, initiator, "cause", &owners, 0, 100).unwrap();
		assert_eq!(removal.peers().len(), 1, "owners \\ {{target, initiator}} is exactly one");

		removal.peer_vote(peer, Vote::Remove, 1).unwrap();
		assert_eq!(removal.outcome(), Outcome::Passes, "unanimity of one is still unanimity — the set is not empty");
		assert_eq!(removal.execute(&owners, 2).unwrap(), RemovalState::Executed);
	}

	#[test]
	fn open_snapshots_peers_excluding_the_target_and_the_initiator() {
		let owners = ids(5);
		let removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 1_000, 100).unwrap();
		assert_eq!(removal.owner_count(), 5, "the initiator stays in the denominator");
		assert_eq!(removal.peers().len(), 3);
		assert!(!removal.peers().iter().any(|p| p.user_id == owners[0]), "the target is never a peer");
		assert!(!removal.peers().iter().any(|p| p.user_id == owners[1]), "the initiator is never a peer");
		assert_eq!(removal.expires_at(), 1_100);
		assert_eq!(removal.version(), 1);
	}

	#[test]
	fn open_refuses_self_removal_and_non_owners() {
		let owners = ids(5);
		let stranger = UserId::new();
		let open = |target, initiator| OwnerRemoval::open(RemovalId::new(), target, initiator, "cause", &owners, 0, 100);
		assert!(matches!(open(owners[0], owners[0]).unwrap_err(), DomainError::Conflict(_)), "resignation is a separate RPC");
		assert!(matches!(open(owners[0], stranger).unwrap_err(), DomainError::Forbidden(_)));
		assert!(matches!(open(stranger, owners[1]).unwrap_err(), DomainError::Validation(_)));
		assert!(
			OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "   ", &owners, 0, 100).is_err(),
			"a reason is mandatory"
		);
	}

	/// Pitfall 4 as a transition: the initiator cannot vote, and neither can the
	/// target, because neither is in the set the vote is looked up in.
	#[test]
	fn neither_the_initiator_nor_the_target_can_peer_vote() {
		let owners = ids(5);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		for barred in [owners[0], owners[1], UserId::new()] {
			assert!(matches!(removal.peer_vote(barred, Vote::Remove, 1).unwrap_err(), DomainError::Forbidden(_)));
		}
		assert!(removal.peer_vote(owners[2], Vote::Remove, 1).is_ok());
	}

	#[test]
	fn a_cast_vote_is_idempotent_but_not_changeable() {
		let owners = ids(5);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		removal.peer_vote(owners[2], Vote::Remove, 1).unwrap();
		let version = removal.version();
		removal.peer_vote(owners[2], Vote::Remove, 9).unwrap();
		assert_eq!(removal.version(), version, "a repeat writes nothing");
		assert!(matches!(removal.peer_vote(owners[2], Vote::Keep, 9).unwrap_err(), DomainError::Conflict(_)));
		assert!(matches!(removal.peer_vote(owners[3], Vote::Pending, 9).unwrap_err(), DomainError::Validation(_)));
	}

	#[test]
	fn one_keeping_peer_rejects_the_proposal() {
		let owners = ids(5);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		removal.peer_vote(owners[2], Vote::Remove, 1).unwrap();
		assert!(removal.state().is_open());
		removal.peer_vote(owners[3], Vote::Keep, 2).unwrap();
		assert_eq!(removal.state(), RemovalState::Rejected);
		assert_eq!(removal.decided_at(), 2);
		assert!(matches!(removal.peer_vote(owners[4], Vote::Remove, 3).unwrap_err(), DomainError::Conflict(_)));
	}

	#[test]
	fn unanimous_peers_pass_but_do_not_execute_on_their_own() {
		let owners = ids(4);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		removal.peer_vote(owners[2], Vote::Remove, 1).unwrap();
		removal.peer_vote(owners[3], Vote::Remove, 2).unwrap();
		assert_eq!(removal.outcome(), Outcome::Passes);
		assert_eq!(removal.state(), RemovalState::Open, "the seat is taken by execute(), after the roster is re-checked");
		assert_eq!(removal.execute(&owners, 3).unwrap(), RemovalState::Executed);
		assert_eq!(removal.execute(&owners, 4).unwrap(), RemovalState::Executed, "execution is idempotent");
	}

	/// Pitfalls 19 and 20 at the second check: the roster moved after the vote.
	#[test]
	fn execution_voids_when_the_roster_moved_underneath_it() {
		let owners = ids(4);
		let pass = || {
			let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
			removal.target_decision(Vote::Remove, 1).unwrap();
			removal
		};

		// Two owners left, so taking a seat would leave ONE — below the floor of 2.
		let mut floor_breach = pass();
		assert_eq!(floor_breach.execute(&owners[..2], 2).unwrap(), RemovalState::Void);
		assert!(floor_breach.void_reason().contains("floor"));

		// The initiator is owners[1]; a roster without them is one they cannot act on.
		let without_initiator: Vec<UserId> = owners.iter().copied().filter(|o| *o != owners[1]).chain([UserId::new()]).collect();
		let mut lost_seat = pass();
		assert_eq!(lost_seat.execute(&without_initiator, 2).unwrap(), RemovalState::Void);
		assert!(lost_seat.void_reason().contains("initiator"));
		assert_eq!(lost_seat.execute(&owners, 3).unwrap(), RemovalState::Void, "voiding is terminal and idempotent");
	}

	#[test]
	fn execute_refuses_a_proposal_that_has_not_passed() {
		let owners = ids(4);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		assert!(matches!(removal.execute(&owners, 1).unwrap_err(), DomainError::Conflict(_)));
		removal.peer_vote(owners[2], Vote::Remove, 1).unwrap();
		assert!(matches!(removal.execute(&owners, 2).unwrap_err(), DomainError::Conflict(_)), "one of two peers is not unanimity");
	}

	/// Pitfalls 1 and 2. Kicking an approver after they voted must not carry a proposal
	/// their vote no longer supports, and it must never LOWER the bar.
	#[test]
	fn a_peer_who_lost_their_seat_stops_counting_at_execution() {
		let owners = ids(5);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		removal.peer_vote(owners[2], Vote::Remove, 1).unwrap();
		removal.peer_vote(owners[3], Vote::Remove, 2).unwrap();
		removal.peer_vote(owners[4], Vote::Remove, 3).unwrap();
		assert_eq!(removal.outcome(), Outcome::Passes);

		// owners[4] is kicked between the vote and the execution: their REMOVE is dropped,
		// which leaves two of three eligible peers — no longer unanimity.
		let remaining: Vec<UserId> = owners[..4].to_vec();
		assert_eq!(removal.outcome_among(&remaining), Outcome::Passes, "the other two still cover the eligible set");

		// Now drop a peer who never voted INTO the roster: the snapshot is frozen, so a
		// newly minted owner cannot be used to reach quorum either.
		let mut stuffed = remaining.clone();
		stuffed.push(UserId::new());
		assert_eq!(removal.outcome_among(&stuffed), Outcome::Passes, "an owner minted after the open has no say");

		// And a roster that has lost EVERY eligible peer falls back to the vacuous
		// unanimity guard rather than passing over an empty set.
		let stripped: Vec<UserId> = vec![owners[0], owners[1], UserId::new(), UserId::new()];
		assert_eq!(removal.outcome_among(&stripped), Outcome::Pending, "unanimity over nobody is not unanimity");
		let mut orphaned = removal.clone();
		assert!(matches!(orphaned.execute(&stripped, 4).unwrap_err(), DomainError::Conflict(_)));
	}

	#[test]
	fn the_target_answer_is_one_shot() {
		let owners = ids(4);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		removal.target_decision(Vote::Keep, 1).unwrap();
		assert_eq!(removal.state(), RemovalState::Open, "refusing leaves path (b) alive");
		removal.target_decision(Vote::Keep, 2).unwrap();
		assert!(matches!(removal.target_decision(Vote::Remove, 3).unwrap_err(), DomainError::Conflict(_)));
	}

	#[test]
	fn cancel_belongs_to_the_initiator_and_expiry_to_the_clock() {
		let owners = ids(4);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		assert!(matches!(removal.cancel(owners[2], 1).unwrap_err(), DomainError::Forbidden(_)));
		assert!(matches!(removal.expire(99).unwrap_err(), DomainError::Conflict(_)), "not due yet");
		removal.cancel(owners[1], 5).unwrap();
		assert_eq!(removal.state(), RemovalState::Cancelled);
		removal.cancel(owners[1], 6).unwrap();
		assert!(matches!(removal.expire(200).unwrap_err(), DomainError::Conflict(_)), "a cancelled proposal cannot expire");

		let mut stale = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		stale.expire(100).unwrap();
		assert_eq!(stale.state(), RemovalState::Expired);
		assert!(
			matches!(stale.target_decision(Vote::Remove, 101).unwrap_err(), DomainError::Conflict(_)),
			"a late approval cannot carry it"
		);
	}

	#[test]
	fn every_transition_bumps_the_version_and_emits_exactly_once() {
		let owners = ids(4);
		let mut removal = OwnerRemoval::open(RemovalId::new(), owners[0], owners[1], "cause", &owners, 0, 100).unwrap();
		assert_eq!(removal.drain_events(), [GovernanceEvent::Opened]);
		removal.peer_vote(owners[2], Vote::Remove, 1).unwrap();
		removal.peer_vote(owners[3], Vote::Keep, 2).unwrap();
		assert_eq!(removal.drain_events(), [GovernanceEvent::PeerVoted, GovernanceEvent::PeerVoted, GovernanceEvent::Rejected]);
		assert_eq!(removal.version(), 4, "open + two votes + the close");
		assert!(removal.drain_events().is_empty());
	}

	// -----------------------------------------------------------------------------
	// The USER consilia: a majority, not unanimity.
	// -----------------------------------------------------------------------------

	/// The same rule `unanimity_over_an_empty_set_never_passes` states, on the other
	/// helper: a threshold met by nobody is a threshold that lets one person act alone.
	#[test]
	fn majority_over_an_empty_set_never_passes() {
		assert_eq!(majority([].into_iter()), Outcome::Fails);
	}

	#[test]
	fn majority_needs_more_than_half_and_decides_as_soon_as_it_can() {
		// One peer: that peer IS the majority, so the initiator still cannot act alone.
		assert_eq!(majority([Ballot::For].into_iter()), Outcome::Passes);
		assert_eq!(majority([Ballot::Against].into_iter()), Outcome::Fails);
		assert_eq!(majority([Ballot::Pending].into_iter()), Outcome::Pending);

		// Two peers (a three-owner fund): the bar is two, which is unanimity — the two
		// rules only diverge above this size.
		assert_eq!(needed_votes(2), 2);
		assert_eq!(majority([Ballot::For, Ballot::Pending].into_iter()), Outcome::Pending);
		assert_eq!(majority([Ballot::For, Ballot::For].into_iter()), Outcome::Passes);
		assert_eq!(majority([Ballot::For, Ballot::Against].into_iter()), Outcome::Fails);

		// Three peers (a four-owner fund): two carry it, and one AGAINST no longer ends
		// it. This is the divergence, and the reason for it — an owner who cannot be
		// reached must not decide a 24h deadline by not answering.
		assert_eq!(needed_votes(3), 2);
		assert_eq!(majority([Ballot::For, Ballot::For, Ballot::Pending].into_iter()), Outcome::Passes);
		assert_eq!(majority([Ballot::Against, Ballot::Pending, Ballot::Pending].into_iter()), Outcome::Pending);
		// Two AGAINST leave one peer, who cannot reach two alone: decided now rather than
		// left open until it expires.
		assert_eq!(majority([Ballot::Against, Ballot::Against, Ballot::Pending].into_iter()), Outcome::Fails);
	}

	fn proposal(kind: UserProposalKind, owners: &[UserId], subject: UserId) -> UserProposal {
		UserProposal::open(UserProposalId::new(), kind, subject, owners[0], "cause", owners, 1_000, REMOVAL_TTL_SECS).expect("open")
	}

	#[test]
	fn a_lone_owner_cannot_open_a_user_proposal() {
		let owners = ids(1);
		let err = UserProposal::open(
			UserProposalId::new(),
			UserProposalKind::Suspension,
			UserId::new(),
			owners[0],
			"cause",
			&owners,
			1_000,
			REMOVAL_TTL_SECS,
		)
		.expect_err("unanimity over nobody and a majority of nobody are the same hole");
		assert!(matches!(err, DomainError::Conflict(_)));
	}

	#[test]
	fn only_an_owner_may_open_and_never_about_themselves() {
		let owners = ids(3);
		let outsider = UserId::new();
		assert!(matches!(
			UserProposal::open(
				UserProposalId::new(),
				UserProposalKind::Suspension,
				owners[1],
				outsider,
				"cause",
				&owners,
				1_000,
				REMOVAL_TTL_SECS
			),
			Err(DomainError::Forbidden(_))
		));
		assert!(matches!(
			UserProposal::open(
				UserProposalId::new(),
				UserProposalKind::Suspension,
				owners[0],
				owners[0],
				"cause",
				&owners,
				1_000,
				REMOVAL_TTL_SECS
			),
			Err(DomainError::Conflict(_))
		));
	}

	/// The peer set is `owners \ {initiator}` and the initiator gets no vote — structural,
	/// exactly as it is for the two owner consilia.
	#[test]
	fn the_initiator_is_not_among_their_own_voters() {
		let owners = ids(3);
		let subject = UserId::new();
		let mut p = proposal(UserProposalKind::Suspension, &owners, subject);
		assert_eq!(p.peers().len(), 2);
		assert_eq!(p.threshold(), 2, "two peers means both, which is where majority and unanimity coincide");
		assert!(matches!(p.vote(owners[0], ProposalVote::For, 1_100), Err(DomainError::Forbidden(_))));
	}

	/// The SUBJECT is any user, not an owner — the difference from `OwnerAdmission`, and
	/// the reason it has no floor and no "already holds a seat" check.
	#[test]
	fn the_subject_need_not_be_an_owner() {
		let owners = ids(3);
		let p = proposal(UserProposalKind::AdminAdmission, &owners, UserId::new());
		assert_eq!(p.owner_count(), 3);
		assert_eq!(p.state(), ProposalState::Open);
	}

	#[test]
	fn a_reached_threshold_passes_and_a_blocked_one_rejects() {
		let owners = ids(4);
		let subject = UserId::new();

		let mut carried = proposal(UserProposalKind::Suspension, &owners, subject);
		assert_eq!(carried.threshold(), 2, "three peers, so two carry it");
		carried.vote(owners[1], ProposalVote::For, 1_100).expect("first vote");
		assert_eq!(carried.outcome(), Outcome::Pending);
		carried.vote(owners[2], ProposalVote::For, 1_200).expect("second vote");
		assert_eq!(carried.outcome(), Outcome::Passes, "it passes without waiting for the third owner");

		let mut blocked = proposal(UserProposalKind::Suspension, &owners, subject);
		blocked.vote(owners[1], ProposalVote::Against, 1_100).expect("first vote");
		assert_eq!(blocked.state(), ProposalState::Open, "one AGAINST out of three peers decides nothing");
		blocked.vote(owners[2], ProposalVote::Against, 1_200).expect("second vote");
		assert_eq!(blocked.state(), ProposalState::Rejected, "the bar is now unreachable");
	}

	/// A cast vote is final and repeating it is free — the same contract the owner
	/// consilia carry, asserted here so the shared aggregate cannot drift from them.
	#[test]
	fn a_cast_vote_is_final_and_repeating_it_is_free() {
		let owners = ids(4);
		let mut p = proposal(UserProposalKind::Suspension, &owners, UserId::new());
		p.vote(owners[1], ProposalVote::For, 1_100).expect("cast");
		p.vote(owners[1], ProposalVote::For, 1_200).expect("repeating is a no-op");
		assert!(matches!(p.vote(owners[1], ProposalVote::Against, 1_300), Err(DomainError::Conflict(_))));
	}

	/// The roster moving underneath an open proposal can only make it HARDER: voters who
	/// lost their seats drop out of the tally, and a set emptied by attrition falls back
	/// to the non-empty guard rather than passing over nobody.
	#[test]
	fn execution_re_decides_against_the_roster_of_the_moment() {
		let owners = ids(3);
		let mut p = proposal(UserProposalKind::Suspension, &owners, UserId::new());
		p.vote(owners[1], ProposalVote::For, 1_100).expect("vote");
		p.vote(owners[2], ProposalVote::For, 1_200).expect("vote");
		assert_eq!(p.outcome(), Outcome::Passes);
		// Both carriers have since lost their seats.
		assert_eq!(p.outcome_among(&[owners[0]]), Outcome::Fails);
		assert!(matches!(p.execute(&[owners[0]], 1_300), Err(DomainError::Conflict(_))));

		// The initiator losing theirs voids rather than executes.
		let mut q = proposal(UserProposalKind::Suspension, &owners, UserId::new());
		q.vote(owners[1], ProposalVote::For, 1_100).expect("vote");
		q.vote(owners[2], ProposalVote::For, 1_200).expect("vote");
		assert_eq!(q.execute(&owners[1..], 1_300).expect("re-decided"), ProposalState::Void);
		assert!(q.void_reason().contains("initiator"));
	}

	#[test]
	fn only_the_initiator_may_cancel_and_a_closed_proposal_is_final() {
		let owners = ids(3);
		let mut p = proposal(UserProposalKind::Reinstatement, &owners, UserId::new());
		assert!(matches!(p.cancel(owners[1], 1_100), Err(DomainError::Forbidden(_))));
		p.cancel(owners[0], 1_100).expect("the initiator may withdraw");
		p.cancel(owners[0], 1_200).expect("repeating is a no-op");
		assert_eq!(p.state(), ProposalState::Cancelled);
		assert!(matches!(p.vote(owners[1], ProposalVote::For, 1_300), Err(DomainError::Conflict(_))));
	}

	#[test]
	fn an_expired_proposal_can_no_longer_be_carried() {
		let owners = ids(3);
		let mut p = proposal(UserProposalKind::Suspension, &owners, UserId::new());
		assert!(p.expire(1_100).is_err(), "it is not due yet");
		p.expire(1_000 + REMOVAL_TTL_SECS).expect("due");
		assert_eq!(p.state(), ProposalState::Expired);
		assert!(matches!(p.vote(owners[1], ProposalVote::For, 1_000 + REMOVAL_TTL_SECS + 1), Err(DomainError::Conflict(_))));
	}

	#[test]
	fn a_reason_is_required_and_bounded() {
		let owners = ids(3);
		for bad in ["", "   "] {
			assert!(matches!(
				UserProposal::open(
					UserProposalId::new(),
					UserProposalKind::Suspension,
					UserId::new(),
					owners[0],
					bad,
					&owners,
					1_000,
					REMOVAL_TTL_SECS
				),
				Err(DomainError::Validation(_))
			));
		}
		let too_long = "x".repeat(MAX_REASON_CHARS + 1);
		assert!(matches!(
			UserProposal::open(
				UserProposalId::new(),
				UserProposalKind::Suspension,
				UserId::new(),
				owners[0],
				&too_long,
				&owners,
				1_000,
				REMOVAL_TTL_SECS
			),
			Err(DomainError::Validation(_))
		));
	}

	#[test]
	fn proposal_vocabulary_round_trips() {
		for kind in [UserProposalKind::Suspension, UserProposalKind::Reinstatement, UserProposalKind::AdminAdmission] {
			assert_eq!(UserProposalKind::parse(kind.as_str()).unwrap(), kind);
		}
		assert!(UserProposalKind::parse("nope").is_err());
		for vote in [ProposalVote::Pending, ProposalVote::For, ProposalVote::Against] {
			assert_eq!(ProposalVote::parse(vote.as_str()).unwrap(), vote);
		}
		assert!(ProposalVote::parse("maybe").is_err());
	}
}
