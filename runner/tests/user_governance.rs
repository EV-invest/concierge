//! Real-Postgres coverage for the split suspension verb and the user consilia.
//!
//! These hit a **real** Postgres (no mocks, per the project rules). They run when
//! `DATABASE_URL` is set and skip cleanly otherwise. What only a live server can prove is
//! exactly what matters here: that a verdict, the identity write it causes, the
//! cross-plane `user_outbox` row the money plane pulls and the `admin_action` row all
//! commit together or not at all; that the `suspended_by` column is what decides who may
//! reinstate; and that a hold's lapse is a WRITE, because a projection would never reach
//! the money plane.
//!
//! ⚠️ THIS SUITE OWNS THE OWNER ROSTER, like `governance.rs` and `authz_gate.rs`: the
//! voter set is counted from `users.role = 'owner'` globally, so a test cannot scope
//! itself to its own fixtures. It takes the SAME session advisory lock those two take, so
//! the three serialize instead of racing.
//!
//! The clock is an argument to every call, so time is simulated rather than waited on: a
//! hold is reached by passing a later `now`, never by sleeping through 24 hours.

use std::sync::Arc;

mod common;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	governance::Governance,
	infrastructure::{
		db,
		governance::{Audit, PgGovernance},
		users::{AdminAction, PgUsers},
	},
	ports::{GovernanceRepository, UserDirectoryRepository},
};
use domain::{
	authz::Role,
	governance::{ProposalState, UserProposalId},
	users::{AuthSubject, Email, HOLD_COOLDOWN_SECS, HOLD_TTL_SECS, Suspension, UserId, UserStatus},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	CancelUserProposalRequest, DisableUserRequest, HoldUserRequest, OpenAdminAdmissionRequest, OpenUserReinstatementRequest, OpenUserSuspensionRequest, ProposalVote as ProposalVoteMsg,
	ReinstateUserRequest, RevokeTokensRequest, SetKycLevelRequest, SubmitUserProposalVoteRequest, governance_service_server::GovernanceService, user_directory_server::UserDirectory,
};
use sqlx::{Connection, PgConnection, PgPool, Row};
use tonic::{Code, Request};
use uuid::Uuid;

/// The key `governance.rs` and `authz_gate.rs` serialize on — deliberately the same one.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
/// A fixed instant, so every assertion about a deadline is exact rather than racy.
const T0: i64 = 1_800_000_000;
/// A clock far past any sweep another test in this binary runs. The sweep is GLOBAL —
/// `lapse_due_holds(now)` releases every hold due by `now` in the database — so a hold
/// placed at a real-world instant can be released by a neighbour's sweep mid-test. A
/// hold placed here is due in 2096 and nobody sweeps that far.
const T_FAR: i64 = 4_000_000_000;

struct Fixture {
	governance: Arc<PgGovernance>,
	users: Arc<PgUsers>,
	pool: PgPool,
	/// Holding this connection open holds the advisory lock; dropping it releases.
	_roster_lock: PgConnection,
}

async fn setup() -> Option<Fixture> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	common::assert_disposable_database();
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let mut roster_lock = PgConnection::connect(&url).await.expect("a dedicated connection for the roster lock");
	sqlx::query("SELECT pg_advisory_lock($1)")
		.bind(ROSTER_LOCK)
		.execute(&mut roster_lock)
		.await
		.expect("take the roster lock");

	sqlx::query("UPDATE users SET role = 'investor' WHERE role = 'owner'")
		.execute(&pool)
		.await
		.expect("clear the roster");

	Some(Fixture {
		governance: Arc::new(PgGovernance::new(pool.clone(), "https://example.test/governance/removal".into())),
		users: Arc::new(PgUsers::new(pool.clone())),
		pool,
		_roster_lock: roster_lock,
	})
}

impl Fixture {
	async fn user(&self) -> UserId {
		let subject = AuthSubject::parse(&format!("ug-itest-{}", Uuid::new_v4())).unwrap();
		let email = Email::parse(&format!("ug-{}@example.com", Uuid::new_v4())).unwrap();
		self.users.provision(subject, email, true).await.expect("provision").id()
	}

	/// Mint an owner straight through the repository: `SetRole` deliberately refuses to,
	/// and a fixture must not be able to do what the RPC cannot.
	async fn owner(&self) -> UserId {
		let id = self.user().await;
		self.users.set_role(id, Role::Owner).await.expect("grant the seat");
		id
	}

	/// An admin seat, straight through the repository for the reason `owner` gives.
	async fn admin(&self) -> UserId {
		let id = self.user().await;
		self.users.set_role(id, Role::Admin).await.expect("grant the seat");
		id
	}

	async fn roster(&self, n: usize) -> Vec<UserId> {
		let mut owners = Vec::with_capacity(n);
		for _ in 0..n {
			owners.push(self.owner().await);
		}
		owners
	}

	fn directory(&self) -> Directory {
		Directory::new(self.users.clone(), Arc::new(BreakGlass::new(Vec::new())))
	}

	fn service(&self) -> Governance {
		let (revisions, _) = tokio::sync::broadcast::channel(8);
		Governance::new(self.users.clone(), Arc::new(BreakGlass::new(Vec::new())), self.governance.clone(), revisions)
	}

	async fn reload(&self, id: UserId) -> domain::users::User {
		self.users.find_by_id(id).await.expect("read").expect("the user exists")
	}

	/// The cross-plane kinds emitted for one user, oldest first — what the money plane
	/// will actually pull.
	async fn outbox_kinds(&self, id: UserId) -> Vec<String> {
		sqlx::query("SELECT kind FROM user_outbox WHERE user_id = $1 ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the outbox")
			.iter()
			.map(|r| r.get::<String, _>("kind"))
			.collect()
	}

	/// One operator pulling the brake through the console.
	async fn hold(&self, actor: UserId, target: UserId, reason: &str) -> Result<i64, tonic::Status> {
		self.directory()
			.hold_user(as_user(
				actor,
				HoldUserRequest {
					user_id: target.to_string(),
					reason: reason.into(),
				},
			))
			.await
			.map(|response| response.into_inner().hold_expires_at)
	}

	/// The brake straight through the port at a chosen instant — see `T_FAR`.
	async fn hold_at(&self, actor: UserId, target: UserId, now: i64) -> Result<i64, domain::error::DomainError> {
		let action = AdminAction::by(actor, "held", &Audit::default()).with_reason("credential stuffing");
		self.users
			.hold_user(target, &action, Role::Owner, now)
			.await
			.map(|user| user.suspension().and_then(Suspension::hold_expires_at).unwrap())
	}

	/// The `detail` JSON of every `held` row for one subject, oldest first.
	async fn held_details(&self, id: UserId) -> Vec<serde_json::Value> {
		sqlx::query_scalar("SELECT detail FROM admin_action WHERE subject_user_id = $1 AND action = 'held' ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the held rows")
	}

	/// `(action, actor, reason)` for one subject, oldest first.
	async fn audit(&self, id: UserId) -> Vec<(String, Option<Uuid>, String)> {
		sqlx::query("SELECT action, actor_user_id, reason FROM admin_action WHERE subject_user_id = $1 ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the audit log")
			.iter()
			.map(|r| (r.get("action"), r.get("actor_user_id"), r.get("reason")))
			.collect()
	}

	/// Every consilium event recorded against one proposal.
	async fn proposal_events(&self, id: UserProposalId) -> Vec<String> {
		sqlx::query("SELECT kind FROM governance_event WHERE user_proposal_id = $1 ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the consilium log")
			.iter()
			.map(|r| r.get::<String, _>("kind"))
			.collect()
	}

	/// Stamp an account with the owners' verdict without standing up a whole consilium —
	/// the SETUP for the tests that are about what happens afterwards, which is a
	/// different question from how the verdict is reached (covered by
	/// `a_suspension_executes_with_its_effect_in_one_transaction`).
	///
	/// Written straight to the two columns, deliberately: no port method imposes a
	/// governance suspension outside the consilium, and adding one so a fixture could use
	/// it would put a second writer of that state into production code.
	async fn stamp_governance_suspension(&self, id: UserId) {
		sqlx::query("UPDATE users SET status = 'disabled', suspended_by = 'governance', hold_expires_at = NULL WHERE id = $1")
			.bind(id.raw())
			.execute(&self.pool)
			.await
			.expect("impose the verdict");
	}

	/// Carry a proposal to its threshold with FOR votes from `voters`.
	async fn carry(&self, id: UserProposalId, voters: &[UserId]) {
		let service = self.service();
		for voter in voters {
			service
				.submit_user_proposal_vote(as_user(
					*voter,
					SubmitUserProposalVoteRequest {
						proposal_id: id.to_string(),
						vote: ProposalVoteMsg::For as i32,
					},
				))
				.await
				.expect("vote");
		}
	}
}

fn as_user<T>(id: UserId, inner: T) -> Request<T> {
	let mut request = Request::new(inner);
	request.extensions_mut().insert(Claims {
		sub: id.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
	});
	request
}

fn proposal_id(raw: &str) -> UserProposalId {
	UserProposalId::from_raw(Uuid::parse_str(raw).expect("a proposal id"))
}

// ---------------------------------------------------------------------------------
// The retired verb.
// ---------------------------------------------------------------------------------

/// `DisableUser` meant two things at once and now means neither. The refusal has to name
/// BOTH replacements, because the caller is the only one who knows which they wanted.
#[tokio::test]
async fn disable_user_refuses_and_names_both_halves_of_the_verb() {
	let Some(fx) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx.directory().disable_user(as_user(owner, DisableUserRequest { user_id: target.to_string() })).await.unwrap_err();

	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("HoldUser"), "the emergency half is named: {err}");
	assert!(err.message().contains("OpenUserSuspension"), "the permanent half is named: {err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "a refusal changes nothing");
	assert!(fx.audit(target).await.is_empty(), "and records nothing");
}

// ---------------------------------------------------------------------------------
// The hold: instant, one actor, and self-cancelling.
// ---------------------------------------------------------------------------------

/// The whole point of the split, end to end. One operator freezes the account instantly —
/// which is what stops money already queued — and the freeze undoes ITSELF, so the same
/// operator cannot make it permanent.
///
/// The lapse being a WRITE is the load-bearing part: the money plane learns an account is
/// unfrozen only from a `user_outbox` row, so a lapse that were merely projected at read
/// time would release the account here and leave it frozen there, permanently.
#[tokio::test]
async fn a_hold_freezes_instantly_and_lapses_unratified_across_the_bridge() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let held = fx
		.directory()
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "credential stuffing from a new ASN".into(),
			},
		))
		.await
		.expect("one operator may pull the brake")
		.into_inner();

	let user = fx.reload(target).await;
	assert_eq!(user.status(), UserStatus::Disabled);
	assert!(matches!(user.suspension(), Some(Suspension::AdminHold { .. })), "stamped as a hold, not a verdict");
	assert_eq!(user.suspension().unwrap().hold_expires_at(), Some(held.hold_expires_at));
	assert_eq!(fx.outbox_kinds(target).await, ["CREATED", "SUSPENDED"], "the money plane freezes at once");

	let audit = fx.audit(target).await;
	assert_eq!(audit.len(), 1);
	assert_eq!(audit[0].0, "held");
	assert_eq!(audit[0].1, Some(owner.raw()), "the operator is on the record");
	assert_eq!(audit[0].2, "credential stuffing from a new ASN");

	// A minute before the deadline the sweep leaves it alone — the brake is real until it
	// is not.
	// Asserted on THIS target: the sweep is global, and what another test left due by
	// this instant is not this test's business.
	assert!(
		!fx.users.lapse_due_holds(held.hold_expires_at - 60, 10).await.expect("sweep").contains(&target),
		"a hold that is not due must not be released early"
	);
	assert_eq!(fx.reload(target).await.status(), UserStatus::Disabled);

	let lapsed = fx.users.lapse_due_holds(held.hold_expires_at, 10).await.expect("sweep");
	assert!(lapsed.contains(&target), "the deadline released it");

	let user = fx.reload(target).await;
	assert_eq!(user.status(), UserStatus::Active);
	assert_eq!(user.suspension(), None);
	assert_eq!(
		fx.outbox_kinds(target).await,
		["CREATED", "SUSPENDED", "REINSTATED"],
		"the lapse crosses the bridge, or the money plane stays frozen forever"
	);
	assert_eq!(fx.audit(target).await.last().map(|a| a.0.clone()), Some("hold_lapsed".into()));
	assert_eq!(fx.audit(target).await.last().unwrap().1, None, "nobody acted, and the log says so");
	assert_eq!(user.hold_ended_at(), Some(held.hold_expires_at), "the lapse is what the next hold's cooldown counts from");
}

/// A reason is required because the owners asked to ratify a hold are reading exactly
/// this sentence, and a freeze with no stated cause cannot be reviewed by anyone.
#[tokio::test]
async fn a_hold_without_a_reason_is_refused_before_anything_is_written() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx
		.directory()
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "   ".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "{err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active);
	assert!(fx.audit(target).await.is_empty());
}

/// A hold lapses, and that has to mean something. Pressed again while it is live, the
/// button used to restart the clock — so one admin pressing it daily held an investor
/// indefinitely with no owner asked, or held every other owner out of the votes that
/// could stop it. Now it is refused, the deadline stands, and nothing is written.
#[tokio::test]
async fn a_hold_is_not_renewed_by_holding_again() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	let first = fx.hold_at(owner, target, T_FAR).await.expect("the first brake");

	let err = fx.hold(owner, target, "still stuffing").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("OpenUserSuspension"), "the refusal names the proposal to open instead: {err}");
	assert_eq!(fx.reload(target).await.suspension().unwrap().hold_expires_at(), Some(first), "the deadline did not move");
	assert_eq!(fx.audit(target).await.len(), 1, "a refusal is not an action");
	assert_eq!(fx.outbox_kinds(target).await, ["CREATED", "SUSPENDED"], "and the money plane heard of one freeze");
}

/// After a lapse the next hold waits out `HOLD_COOLDOWN_SECS`, or the lapse would be a
/// formality: a day on, one sweep off, forever. The owners are the only way past it.
#[tokio::test]
async fn a_lapsed_hold_starts_a_cooldown() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	fx.hold_at(owner, target, T_FAR).await.expect("hold");
	// Lifted by one act rather than swept: the sweep is global (see `T_FAR`), and the
	// aggregate records the end the same way for both — the lapse path is proved in
	// `a_hold_freezes_instantly_and_lapses_unratified_across_the_bridge`.
	let ended = T_FAR + HOLD_TTL_SECS;
	fx.users.enable_user(target, ended).await.expect("lifted");
	assert_eq!(fx.reload(target).await.hold_ended_at(), Some(ended));

	let err = fx.hold_at(owner, target, ended + HOLD_COOLDOWN_SECS - 1).await.unwrap_err();
	assert!(matches!(err, domain::error::DomainError::Forbidden(_)), "inside the cooldown: {err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "nothing was written");
	assert_eq!(fx.held_details(target).await.len(), 1, "and no audit row claims otherwise");

	// The console sees the same refusal as a precondition it can act on.
	let err = fx.hold(owner, target, "again").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");

	fx.hold_at(owner, target, ended + HOLD_COOLDOWN_SECS)
		.await
		.expect("the cooldown is over; one actor may brake again");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Disabled);
}

/// The one legitimate reason to keep an account frozen past a day is that the owners are
/// deciding whether to: while a suspension proposal is open, the hold extends. The
/// moment it is not, the ordinary rule is back.
#[tokio::test]
async fn an_open_suspension_lets_the_hold_extend_until_the_verdict() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let target = fx.user().await;
	let first = fx.hold_at(owners[0], target, T_FAR).await.expect("the brake");

	let opened = fx
		.service()
		.open_user_suspension(as_user(
			owners[0],
			OpenUserSuspensionRequest {
				user_id: target.to_string(),
				reason: "ratify the hold".into(),
			},
		))
		.await
		.expect("an owner proposes")
		.into_inner();

	// Through the console, at the real clock: the proposal is open NOW, so the check
	// inside the write transaction sees it and the hold is restamped from now.
	let extended = fx
		.hold(owners[1], target, "keeping it frozen while you decide")
		.await
		.expect("the owners are deciding, so the hold extends");
	assert_ne!(extended, first, "the deadline was restamped");
	let details = fx.held_details(target).await;
	assert_eq!(details.len(), 2);
	assert_eq!(details[0]["ratification_pending"], false, "the first press was a fresh brake");
	assert_eq!(details[1]["ratification_pending"], true, "the second was an extension, and the log says so");

	fx.service()
		.cancel_user_proposal(as_user(owners[0], CancelUserProposalRequest { proposal_id: opened.id }))
		.await
		.expect("withdrawn");
	let err = fx.hold(owners[1], target, "once more").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "with nobody deciding, the ordinary rule is back: {err}");
	// The extension left a hold due at a real-world instant; lift it so a neighbour's
	// sweep is not handed somebody else's release to count.
	fx.users.enable_user(target, T_FAR).await.expect("cleanup");
}

/// The votes on every user proposal need a session, so an admin who could hold the
/// owners could hold them out of the consilium that decides whether the hold stands.
/// Only an owner holds a seat. The refusal names the proposal, and writes nothing.
#[tokio::test]
async fn a_seat_is_held_only_by_an_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let admin = fx.admin().await;
	let another_admin = fx.admin().await;

	for target in [owner, another_admin] {
		let err = fx.hold(admin, target, "silence the roster").await.unwrap_err();
		assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
		assert!(err.message().contains("OpenUserSuspension"), "{err}");
		assert_eq!(fx.reload(target).await.status(), UserStatus::Active);
		assert!(fx.audit(target).await.is_empty(), "a refusal is not an action");
	}

	// The control over a rogue operator: an owner may hold an admin.
	fx.hold(owner, another_admin, "rogue operator").await.expect("an owner holds a seat");
	assert_eq!(fx.reload(another_admin).await.status(), UserStatus::Disabled);
	fx.users.enable_user(another_admin, T_FAR).await.expect("cleanup — see T_FAR");
}

/// A hold on yourself ends your own session, and with it your ability to explain, lift
/// or ratify it. Refused before anything is read or written.
#[tokio::test]
async fn nobody_holds_their_own_account() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let err = fx.hold(owner, owner, "stepping back").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("OpenUserSuspension"), "{err}");
	assert_eq!(fx.reload(owner).await.status(), UserStatus::Active);
	assert!(fx.audit(owner).await.is_empty());
}

// ---------------------------------------------------------------------------------
// Reinstatement: one act for a hold, the owners' business for their own verdict.
// ---------------------------------------------------------------------------------

/// Without the refusal the suspension consilium is advisory: the owners vote to freeze an
/// account and any one admin presses "reinstate".
#[tokio::test]
async fn reinstate_lifts_a_hold_in_one_act_and_refuses_the_owners_verdict() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	let directory = fx.directory();

	directory
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "suspicious sign-in".into(),
			},
		))
		.await
		.expect("hold");

	// A hold is one admin's to lift, because it was one admin's to make.
	directory
		.reinstate_user(as_user(
			owner,
			ReinstateUserRequest {
				user_id: target.to_string(),
				reason: "false positive".into(),
			},
		))
		.await
		.expect("a hold lifts in one act");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active);

	// The owners' verdict is not.
	fx.stamp_governance_suspension(target).await;
	let err = directory
		.reinstate_user(as_user(
			owner,
			ReinstateUserRequest {
				user_id: target.to_string(),
				reason: "changed my mind".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("OpenUserReinstatement"), "the refusal points at the proposal: {err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Disabled, "the verdict stands");
	assert!(
		!fx.audit(target).await.iter().any(|a| a.2 == "changed my mind"),
		"a refusal writes no audit row, because nothing happened to audit"
	);
}

// ---------------------------------------------------------------------------------
// The consilia.
// ---------------------------------------------------------------------------------

/// The quorum and its effect are ONE transaction: the vote that meets the threshold also
/// writes the status, the cross-plane event and the audit row, and a reader can never see
/// an executed proposal beside an account that is still active.
#[tokio::test]
async fn a_suspension_executes_with_its_effect_in_one_transaction() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let target = fx.user().await;
	let service = fx.service();

	let opened = service
		.open_user_suspension(as_user(
			owners[0],
			OpenUserSuspensionRequest {
				user_id: target.to_string(),
				reason: "confirmed account takeover".into(),
			},
		))
		.await
		.expect("an owner may propose")
		.into_inner();
	let id = proposal_id(&opened.id);
	assert_eq!(opened.threshold, 2, "two peers, so both must agree");
	assert_eq!(opened.peers.len(), 2, "the initiator is not among their own voters");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "opening decides nothing");

	// One vote is not the threshold.
	fx.carry(id, &owners[1..2]).await;
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "a majority of two is two");

	fx.carry(id, &owners[2..3]).await;

	let user = fx.reload(target).await;
	assert_eq!(user.status(), UserStatus::Disabled);
	assert_eq!(user.suspension(), Some(Suspension::Governance), "stamped as the owners', so one admin cannot lift it");
	assert_eq!(user.suspension().unwrap().hold_expires_at(), None, "a verdict does not expire");
	assert_eq!(fx.outbox_kinds(target).await, ["CREATED", "SUSPENDED"]);

	let record = fx.governance.find_user_proposal(id, T0).await.expect("read").expect("it exists");
	assert_eq!(record.state, ProposalState::Executed);

	let audit = fx.audit(target).await;
	assert_eq!(audit.len(), 1);
	assert_eq!(audit[0].0, "suspended_by_consilium");
	assert_eq!(audit[0].2, "confirmed account takeover", "the initiator's words reach the log");

	let events = fx.proposal_events(id).await;
	assert_eq!(events, ["OPENED", "PEER_VOTED", "PEER_VOTED", "EXECUTED"], "the proposal's own history is in the consilium log");
}

/// The other half of the reinstatement rule: what one admin may not do, the owners may.
#[tokio::test]
async fn a_reinstatement_proposal_lifts_what_the_owners_imposed() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let target = fx.user().await;
	fx.stamp_governance_suspension(target).await;

	let opened = fx
		.service()
		.open_user_reinstatement(as_user(
			owners[0],
			OpenUserReinstatementRequest {
				user_id: target.to_string(),
				reason: "the takeover was contained and the account is clean".into(),
			},
		))
		.await
		.expect("propose")
		.into_inner();
	fx.carry(proposal_id(&opened.id), &owners[1..3]).await;

	let user = fx.reload(target).await;
	assert_eq!(user.status(), UserStatus::Active);
	assert_eq!(user.suspension(), None);
	assert!(fx.outbox_kinds(target).await.contains(&"REINSTATED".to_string()), "the money plane unfreezes");
	assert_eq!(fx.audit(target).await.last().map(|a| a.0.clone()), Some("reinstated_by_consilium".into()));
}

/// A reinstatement whose subject is no longer the owners' to release must not execute —
/// checked under the row lock at EXECUTION, because 72h is long enough for the suspension
/// it was opened about to have been lifted by something else entirely.
#[tokio::test]
async fn a_reinstatement_voids_when_there_is_no_verdict_left_to_lift() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let target = fx.user().await;
	fx.stamp_governance_suspension(target).await;

	let opened = fx
		.service()
		.open_user_reinstatement(as_user(
			owners[0],
			OpenUserReinstatementRequest {
				user_id: target.to_string(),
				reason: "cleared".into(),
			},
		))
		.await
		.expect("propose")
		.into_inner();

	// The suspension goes away underneath the open proposal.
	fx.users.enable_user(target, T0).await.expect("lifted by something else");

	fx.carry(proposal_id(&opened.id), &owners[1..3]).await;
	let record = fx.governance.find_user_proposal(proposal_id(&opened.id), T0).await.expect("read").expect("exists");
	assert_eq!(record.state, ProposalState::Void, "it passed, but there was nothing left to carry out");
	assert!(record.proposal.void_reason().contains("no longer suspended"));
}

/// The appointment path, and the refusal that makes it the only one.
#[tokio::test]
async fn an_admin_admission_grants_the_role_the_console_may_no_longer_grant() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let candidate = fx.user().await;

	let opened = fx
		.service()
		.open_admin_admission(as_user(
			owners[0],
			OpenAdminAdmissionRequest {
				user_id: candidate.to_string(),
				reason: "joining the operations rota".into(),
			},
		))
		.await
		.expect("propose")
		.into_inner();
	fx.carry(proposal_id(&opened.id), &owners[1..3]).await;

	assert_eq!(fx.reload(candidate).await.role(), Role::Admin);
	assert!(fx.outbox_kinds(candidate).await.contains(&"ROLE_CHANGED".to_string()), "the money plane mirrors the role");
	assert_eq!(fx.audit(candidate).await.last().map(|a| a.0.clone()), Some("admin_granted_by_consilium".into()));
}

/// An admin admission aimed at an OWNER would write `admin` over `owner` — an expulsion
/// with no removal consilium, no floor check and no audit of the seat. It is the refusal
/// `set_role_outside_ownership` makes, reached by another door, so it is closed at the
/// same place every other execution check lives: under the subject's row lock.
#[tokio::test]
async fn an_admin_admission_can_never_demote_an_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let subject = owners[3];

	let opened = fx
		.service()
		.open_admin_admission(as_user(
			owners[0],
			OpenAdminAdmissionRequest {
				user_id: subject.to_string(),
				reason: "an appointment that is really a demotion".into(),
			},
		))
		.await
		.expect("nothing stops it being PROPOSED")
		.into_inner();
	fx.carry(proposal_id(&opened.id), &owners[1..3]).await;

	let record = fx.governance.find_user_proposal(proposal_id(&opened.id), T0).await.expect("read").expect("exists");
	assert_eq!(record.state, ProposalState::Void, "it passed and was still refused");
	assert!(record.proposal.void_reason().contains("owner seat"));
	assert_eq!(fx.reload(subject).await.role(), Role::Owner, "the seat is untouched");
}

/// One owner is never a consilium, whatever the threshold arithmetic says. `owners \
/// {initiator}` is empty here, and a bar met by nobody is a bar that lets one person act
/// alone — the same hole `owner_admission_needs_a_peer` closes.
#[tokio::test]
async fn a_lone_owner_cannot_open_a_user_proposal() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx
		.service()
		.open_user_suspension(as_user(
			owner,
			OpenUserSuspensionRequest {
				user_id: target.to_string(),
				reason: "there is nobody to agree".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::AlreadyExists, "{err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active);
}

/// Enough AGAINST votes to put the threshold out of reach decide the proposal NOW rather
/// than leaving it open until it expires, and nothing is applied.
#[tokio::test]
async fn a_blocked_proposal_rejects_and_applies_nothing() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let target = fx.user().await;
	let service = fx.service();

	let opened = service
		.open_user_suspension(as_user(
			owners[0],
			OpenUserSuspensionRequest {
				user_id: target.to_string(),
				reason: "contested".into(),
			},
		))
		.await
		.expect("propose")
		.into_inner();

	service
		.submit_user_proposal_vote(as_user(
			owners[1],
			SubmitUserProposalVoteRequest {
				proposal_id: opened.id.clone(),
				vote: ProposalVoteMsg::Against as i32,
			},
		))
		.await
		.expect("vote");

	let record = fx.governance.find_user_proposal(proposal_id(&opened.id), T0).await.expect("read").expect("exists");
	assert_eq!(record.state, ProposalState::Rejected, "one AGAINST of two peers already puts two out of reach");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active);
	assert!(fx.audit(target).await.is_empty());
}

// ---------------------------------------------------------------------------------
// The audit log the console never had.
// ---------------------------------------------------------------------------------

/// None of these wrote a row before: a KYC level could move and a session could be
/// revoked with no record of who did it or why.
#[tokio::test]
async fn every_operator_decision_lands_in_the_audit_log() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	let directory = fx.directory();

	directory
		.set_kyc_level(as_user(
			owner,
			SetKycLevelRequest {
				user_id: target.to_string(),
				kyc_level: 2,
				reason: "documents verified by hand".into(),
			},
		))
		.await
		.expect("set the level");

	directory
		.revoke_tokens(as_user(
			owner,
			RevokeTokensRequest {
				user_id: target.to_string(),
				reason: "device reported stolen".into(),
			},
		))
		.await
		.expect("revoke");

	let audit = fx.audit(target).await;
	let actions: Vec<&str> = audit.iter().map(|a| a.0.as_str()).collect();
	assert_eq!(actions, ["kyc_level_set", "tokens_revoked"]);
	assert!(audit.iter().all(|a| a.1 == Some(owner.raw())), "every row names the operator");
	assert_eq!(audit[0].2, "documents verified by hand");
	assert_eq!(audit[1].2, "device reported stolen");

	// The detail column records what the action DID, taken from the aggregate after the
	// command rather than from what the caller asked for.
	let detail: serde_json::Value = sqlx::query_scalar("SELECT detail FROM admin_action WHERE subject_user_id = $1 ORDER BY position LIMIT 1")
		.bind(target.raw())
		.fetch_one(&fx.pool)
		.await
		.expect("read the detail");
	assert_eq!(detail["kyc_level"], 2);
}

/// The audit row and the change it describes commit together or not at all — a log that
/// can be missing the entry for a change that happened is a source of false confidence.
#[tokio::test]
async fn a_refused_command_writes_neither_the_change_nor_its_audit_row() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx
		.directory()
		.set_kyc_level(as_user(
			owner,
			SetKycLevelRequest {
				user_id: target.to_string(),
				kyc_level: 99,
				reason: "a tier the platform does not define".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "{err}");
	assert_eq!(fx.reload(target).await.kyc_level(), 0);
	assert!(fx.audit(target).await.is_empty(), "the rollback took the audit row with it");
}

/// A hold cannot restate the owners' verdict as its own, which would hand one admin the
/// 24h clock that goes with a hold and expire a decision they had no part in.
#[tokio::test]
async fn a_hold_cannot_downgrade_a_governance_suspension() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	fx.stamp_governance_suspension(target).await;

	let err = fx
		.directory()
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "let me put a clock on this".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::AlreadyExists, "{err}");

	let user = fx.reload(target).await;
	assert_eq!(user.suspension(), Some(Suspension::Governance));
	// The sweep selects on `hold_expires_at IS NOT NULL` and nothing else, so a verdict
	// with no deadline is invisible to it. Asserted on the column rather than by running
	// the sweep: `lapse_due_holds` is global, and a far-future sweep here would release
	// every hold the tests beside this one are in the middle of asserting on.
	assert_eq!(user.suspension().unwrap().hold_expires_at(), None, "and no sweep will ever release it");
	let due: bool = sqlx::query_scalar("SELECT hold_expires_at IS NOT NULL FROM users WHERE id = $1")
		.bind(target.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert!(!due);
}
