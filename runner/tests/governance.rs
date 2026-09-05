//! Real-Postgres coverage for the ownership consilium.
//!
//! These hit a **real** Postgres (no mocks, per the project rules). They run when
//! `DATABASE_URL` is set and skip cleanly otherwise, so a DB-less `cargo test` still
//! passes. What only a live server can prove is exactly what matters here: a partial
//! UNIQUE index enforcing one open proposal per target, `FOR UPDATE` on the roster
//! holding a snapshot still, the attempt counter and the code comparison landing in one
//! transaction, and the seat change plus its cross-plane `ROLE_CHANGED` committing with
//! the verdict or not at all.
//!
//! ⚠️ THIS SUITE OWNS THE OWNER ROSTER. The rules are decided against `users.role =
//! 'owner'` globally, so a test cannot scope itself to its own fixtures the way
//! `user_directory.rs` does. Each test therefore takes a session-level advisory lock
//! (serializing against concurrent runs and other processes) and demotes every existing
//! owner before minting its own. Point `DATABASE_URL` at a development database.
//!
//! The clock is an argument to every call, so time is simulated rather than waited on:
//! expiry is reached by passing a later `now`, never by sleeping.

use std::sync::Arc;

mod common;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	governance::Governance,
	infrastructure::{
		db,
		governance::{PgGovernance, SelfDecision},
		users::PgUsers,
	},
	ports::{GovernanceRepository, UserDirectoryRepository},
};
use domain::{
	authz::Role,
	error::DomainError,
	governance::{AdmissionVote as DomainAdmissionVote, MAX_CODE_ATTEMPTS, ProposalState, REMOVAL_TTL_SECS, RemovalId, RemovalState, Vote},
	users::{AuthSubject, Email, UserId},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	CancelOwnerRemovalRequest, ListOwnersRequest, OpenOwnerAdmissionRequest, OpenOwnerRemovalRequest, RemovalVote, ResignOwnershipRequest, SetRoleRequest, SubmitPeerVoteRequest,
	governance_service_server::GovernanceService, user_directory_server::UserDirectory,
};
use sqlx::{Connection, PgConnection, PgPool, Row};
use tonic::{Code, Request};
use uuid::Uuid;

/// Arbitrary, stable key for the session lock this suite serializes on.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
/// A fixed instant, so every assertion about expiry is exact rather than racy.
const T0: i64 = 1_800_000_000;

struct Fixture {
	governance: Arc<PgGovernance>,
	users: Arc<PgUsers>,
	pool: PgPool,
	/// Holding this connection open holds the advisory lock; dropping it releases.
	_roster_lock: PgConnection,
}

async fn setup() -> Option<Fixture> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	// This suite clears the owner registry — a state no API can restore. Never on a
	// database nobody has declared disposable.
	common::assert_disposable_database();
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let mut roster_lock = PgConnection::connect(&url).await.expect("a dedicated connection for the roster lock");
	sqlx::query("SELECT pg_advisory_lock($1)")
		.bind(ROSTER_LOCK)
		.execute(&mut roster_lock)
		.await
		.expect("take the roster lock");

	// A clean roster is a precondition, not a courtesy: the floor and the peer set are
	// both counted from every owner in the database.
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
	/// Mint a fresh owner. Every fixture user carries a unique subject, so runs neither
	/// collide nor need a clean database beyond the roster.
	async fn owner(&self) -> UserId {
		let id = self.user().await;
		// Straight through the repository: `UserDirectory.SetRole` deliberately refuses to
		// mint owners, and a fixture must not be able to do what the RPC cannot.
		self.users.set_role(id, Role::Owner).await.expect("grant the seat");
		id
	}

	/// A provisioned user holding no seat.
	async fn user(&self) -> UserId {
		let subject = AuthSubject::parse(&format!("gov-itest-{}", Uuid::new_v4())).unwrap();
		let email = Email::parse(&format!("gov-{}@example.com", Uuid::new_v4())).unwrap();
		self.users.provision(subject, email, true).await.expect("provision").id()
	}

	/// The directory service over the same adapter, with no emergency allowlist.
	fn directory(&self) -> Directory {
		Directory::new(self.users.clone(), Arc::new(BreakGlass::new(Vec::new())))
	}

	/// The directory service as an `OWNER_SUBJECTS`-listed operator sees it.
	fn directory_with_break_glass(&self, subject: UserId) -> Directory {
		Directory::new(self.users.clone(), Arc::new(BreakGlass::new(vec![subject.to_string()])))
	}

	/// The consilium service as an `OWNER_SUBJECTS`-listed operator sees it.
	fn service_with_break_glass(&self, subject: UserId) -> Governance {
		let (revisions, _) = tokio::sync::broadcast::channel(8);
		Governance::new(self.users.clone(), Arc::new(BreakGlass::new(vec![subject.to_string()])), self.governance.clone(), revisions)
	}

	/// A roster of `n` owners, returned in a stable order.
	async fn roster(&self, n: usize) -> Vec<UserId> {
		let mut owners = Vec::with_capacity(n);
		for _ in 0..n {
			owners.push(self.owner().await);
		}
		owners
	}

	/// The gRPC service over the same adapters, with no emergency allowlist — so the
	/// gate has only the PERSISTED role to decide on.
	fn service(&self) -> Governance {
		let (revisions, _) = tokio::sync::broadcast::channel(8);
		Governance::new(self.users.clone(), Arc::new(BreakGlass::new(Vec::new())), self.governance.clone(), revisions)
	}

	async fn role_of(&self, id: UserId) -> Role {
		self.users.find_by_id(id).await.expect("read").expect("user exists").role()
	}

	async fn demote(&self, id: UserId) {
		self.users.set_role(id, Role::Investor).await.expect("demote");
	}

	/// The token and the code as the TARGET receives them — read out of the queued
	/// delivery, which is the only place their plaintext ever exists.
	async fn invitation_credentials(&self, removal: RemovalId) -> (String, String) {
		let row = sqlx::query("SELECT payload FROM notification_deliveries WHERE kind = 'owner_removal_self_accept' AND dedupe_key LIKE '%' || $1")
			.bind(removal.to_string())
			.fetch_one(&self.pool)
			.await
			.expect("the invitation was queued in the same transaction as the open");
		let payload: serde_json::Value = row.try_get("payload").expect("a typed payload");
		let url = payload["approval_url"].as_str().expect("an approval url").to_owned();
		let token = url.rsplit('/').next().expect("the token is the last path segment").to_owned();
		(token, payload["code"].as_str().expect("a code").to_owned())
	}

	async fn token_attempts(&self, removal: RemovalId) -> i32 {
		sqlx::query_scalar::<_, i32>("SELECT attempts FROM owner_removal_token WHERE removal_id = $1")
			.bind(removal.raw())
			.fetch_one(&self.pool)
			.await
			.expect("read attempts")
	}

	async fn outbox_kinds(&self, user: UserId) -> Vec<String> {
		sqlx::query_scalar::<_, String>("SELECT kind FROM user_outbox WHERE user_id = $1 ORDER BY position")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the outbox")
	}
}

/// Pitfall 18 at the boundary the money plane cares about. With two owners the eligible
/// peer set is empty and unanimity over it is vacuously true; the floor refuses the
/// proposal before that rule is ever consulted, so BOTH guards have to be wrong for a
/// two-owner fund to expel anybody.
#[tokio::test]
async fn a_two_owner_fund_cannot_expel_either_of_them() {
	let Some(fx) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let owners = fx.roster(2).await;
	let err = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.unwrap_err();
	assert!(matches!(err, DomainError::Conflict(_)), "the floor refuses it at open: {err}");
	assert_eq!(fx.role_of(owners[0]).await, Role::Owner, "and nothing was written");
}

/// The floor is "at least TWO must REMAIN", so three owners CAN spare one — and this is
/// the case the floor was lowered FOR. Under the earlier floor of three, a bad actor in
/// a fund of three was unremovable forever: removal was blocked by the floor, and
/// admitting an ally to outvote them needed the bad actor's own agreement. A payout
/// pause at two owners is recoverable; that deadlock was not.
#[tokio::test]
async fn three_owners_can_spare_a_seat_and_land_on_two() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let (target, initiator, peer) = (owners[0], owners[1], owners[2]);
	let record = fx.governance.open_removal(target, initiator, "cause", T0).await.expect("three owners may spare one");
	assert_eq!(record.removal.peers().len(), 1, "the peer set is owners minus the target and the initiator");

	let after = fx
		.governance
		.peer_vote(record.removal.id(), peer, Vote::Remove, T0 + 1, &Default::default())
		.await
		.expect("unanimity of one is still unanimity — the set is not empty");
	assert_eq!(after.state, RemovalState::Executed);
	assert_eq!(fx.role_of(target).await, Role::Investor, "the seat is gone");
	assert_eq!(fx.governance.owners().await.expect("roster").len(), 2, "and the fund is left with two");
}

/// Pitfall 4. The initiator and the target are kept out of the vote by never being put
/// INTO the snapshotted peer set — not by a check at submit time that somebody could
/// later forget or reorder.
#[tokio::test]
async fn neither_the_initiator_nor_the_target_is_a_peer() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let (target, initiator) = (owners[0], owners[1]);
	let record = fx.governance.open_removal(target, initiator, "cause", T0).await.expect("open");

	let peers: Vec<UserId> = record.removal.peers().iter().map(|p| p.user_id).collect();
	assert_eq!(peers.len(), 2, "four owners minus the target and the initiator");
	assert!(!peers.contains(&target), "the target does not vote on their own removal here");
	assert!(!peers.contains(&initiator), "proposing is not agreeing");

	// And the store agrees: the set is frozen in its own table, not recomputed.
	let stored = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM owner_removal_peer WHERE removal_id = $1 AND user_id IN ($2, $3)")
		.bind(record.removal.id().raw())
		.bind(target.raw())
		.bind(initiator.raw())
		.fetch_one(&fx.pool)
		.await
		.expect("count");
	assert_eq!(stored, 0, "neither was written into the snapshot");

	for who in [target, initiator] {
		let err = fx.governance.peer_vote(record.removal.id(), who, Vote::Remove, T0 + 1, &Default::default()).await.unwrap_err();
		assert!(matches!(err, DomainError::Forbidden(_)), "{who} must not be able to vote: {err}");
	}
}

/// Path (b) is unanimity, so a single KEEP ends the whole proposal — the consilium has
/// said no, and a target who wants to go resigns instead.
#[tokio::test]
async fn one_keeping_peer_ends_it_and_the_seat_stays() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let target = owners[0];
	let record = fx.governance.open_removal(target, owners[1], "cause", T0).await.expect("open");

	let after = fx
		.governance
		.peer_vote(record.removal.id(), owners[2], Vote::Keep, T0 + 1, &Default::default())
		.await
		.expect("a peer may refuse");
	assert_eq!(after.state, RemovalState::Rejected, "one refusal is enough, without waiting for the rest");
	assert_eq!(fx.role_of(target).await, Role::Owner, "the seat stays");

	let err = fx
		.governance
		.peer_vote(record.removal.id(), owners[3], Vote::Remove, T0 + 2, &Default::default())
		.await
		.unwrap_err();
	assert!(matches!(err, DomainError::Conflict(_)), "a closed proposal takes no more votes: {err}");
}

/// The happy path of path (b), end to end: every peer agrees, the seat is taken in the
/// SAME transaction as the verdict, and the money plane is told through the outbox the
/// bridge already drains — it never has to trust this plane's verdict, only the fact.
#[tokio::test]
async fn unanimous_peers_take_the_seat_and_tell_the_money_plane() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let target = owners[0];
	let record = fx.governance.open_removal(target, owners[1], "cause", T0).await.expect("open");

	let midway = fx
		.governance
		.peer_vote(record.removal.id(), owners[2], Vote::Remove, T0 + 1, &Default::default())
		.await
		.expect("first peer");
	assert_eq!(midway.state, RemovalState::Open, "one of two is not unanimity");
	assert_eq!(fx.role_of(target).await, Role::Owner);

	let after = fx
		.governance
		.peer_vote(record.removal.id(), owners[3], Vote::Remove, T0 + 2, &Default::default())
		.await
		.expect("second peer");
	assert_eq!(after.state, RemovalState::Executed);
	assert_eq!(fx.role_of(target).await, Role::Investor, "the seat is taken with the verdict, not after it");
	assert!(
		fx.outbox_kinds(target).await.iter().any(|kind| kind == "ROLE_CHANGED"),
		"the money plane learns through the outbox it already drains"
	);
}

/// Pitfall 20. A removal opened by someone who has since lost their own seat cannot be
/// carried, even though the votes themselves were cast legitimately.
#[tokio::test]
async fn a_removal_whose_initiator_lost_their_seat_is_void() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let (target, initiator) = (owners[0], owners[1]);
	let record = fx.governance.open_removal(target, initiator, "cause", T0).await.expect("open");
	fx.governance
		.peer_vote(record.removal.id(), owners[2], Vote::Remove, T0 + 1, &Default::default())
		.await
		.expect("first peer");

	// The initiator is removed by other means before the vote completes.
	fx.demote(initiator).await;

	let after = fx
		.governance
		.peer_vote(record.removal.id(), owners[3], Vote::Remove, T0 + 2, &Default::default())
		.await
		.expect("the last vote still lands");
	assert_eq!(after.state, RemovalState::Void);
	assert!(after.removal.void_reason().contains("initiator"), "{}", after.removal.void_reason());
	assert_eq!(fx.role_of(target).await, Role::Owner, "and the seat stays");
}

/// Pitfall 19 at the second check: the floor holds even when the roster shrank after
/// the proposal was opened against a roster that could afford it.
#[tokio::test]
async fn the_floor_is_re_checked_when_the_seat_is_taken() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(5).await;
	let target = owners[0];
	let record = fx.governance.open_removal(target, owners[1], "cause", T0).await.expect("open at five owners");
	let (token, code) = fx.invitation_credentials(record.removal.id()).await;

	// Three owners leave by other means; two remain, so this seat is no longer sparable
	// — taking it would leave one, below the floor of two.
	fx.demote(owners[2]).await;
	fx.demote(owners[3]).await;
	fx.demote(owners[4]).await;

	fx.governance.self_decision(&token, &code, Vote::Remove, T0 + 1, &Default::default()).await.expect("decide");

	let after = fx.governance.find_removal(record.removal.id(), T0 + 2).await.unwrap().expect("readable");
	assert_eq!(after.state, RemovalState::Void);
	assert!(after.removal.void_reason().contains("floor"), "{}", after.removal.void_reason());
	assert_eq!(fx.role_of(target).await, Role::Owner);
}

/// Pitfall 5. Mail gateways issue automatic requests for every URL in a message, so the
/// read must cost the target nothing: no attempt counted, no token spent.
#[tokio::test]
async fn reading_the_invitation_has_no_side_effects() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let record = fx.governance.open_removal(owners[0], owners[1], "reason given", T0).await.expect("open");
	let (token, _) = fx.invitation_credentials(record.removal.id()).await;

	for _ in 0..3 {
		let invitation = fx.governance.invitation(&token, T0 + 1).await.unwrap().expect("a live token reads");
		assert_eq!(invitation.reason, "reason given");
		assert_eq!(invitation.decision, Vote::Pending);
		assert_eq!(invitation.attempts_remaining, MAX_CODE_ATTEMPTS as u32);
	}
	assert_eq!(fx.token_attempts(record.removal.id()).await, 0, "a scanned link must not burn the target's budget");
	assert!(fx.governance.invitation("not-a-token", T0 + 1).await.unwrap().is_none());
}

/// Pitfalls 7 and 10. The counter moves before the comparison, five failures burn the
/// token for good, and a burned token is indistinguishable from one that never existed.
#[tokio::test]
async fn five_wrong_codes_burn_the_token_into_an_unknown_one() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");
	let (token, code) = fx.invitation_credentials(record.removal.id()).await;

	for attempt in 1..=MAX_CODE_ATTEMPTS {
		match fx
			.governance
			.self_decision(&token, "0000000000", Vote::Remove, T0 + 1, &Default::default())
			.await
			.expect("attempt")
		{
			SelfDecision::WrongCode { attempts_remaining } => assert_eq!(attempts_remaining as i32, MAX_CODE_ATTEMPTS - attempt),
			_ => panic!("a wrong code is a wrong code, not an outcome"),
		}
		assert_eq!(
			fx.token_attempts(record.removal.id()).await,
			attempt,
			"the counter is durable, so concurrent guesses cannot slip past it"
		);
	}

	// Burned. The RIGHT code no longer works, and says exactly what an unknown token says.
	assert!(matches!(
		fx.governance.self_decision(&token, &code, Vote::Remove, T0 + 2, &Default::default()).await.expect("burned"),
		SelfDecision::Unusable
	));
	assert!(matches!(
		fx.governance
			.self_decision("not-a-token", &code, Vote::Remove, T0 + 2, &Default::default())
			.await
			.expect("unknown"),
		SelfDecision::Unusable
	));
	assert!(fx.governance.invitation(&token, T0 + 2).await.unwrap().is_none(), "and it reads as absent too");
	assert_eq!(fx.role_of(owners[0]).await, Role::Owner);
}

/// Pitfall 11. One shot: the same answer again is a no-op, a different one is refused,
/// and a correct code never burns the budget it was proving it did not need.
#[tokio::test]
async fn the_target_answer_is_one_shot_and_idempotent() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(5).await;
	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");
	let id = record.removal.id();
	let (token, code) = fx.invitation_credentials(id).await;

	// Refusing keeps the proposal open — path (b) can still carry it.
	assert!(matches!(
		fx.governance.self_decision(&token, &code, Vote::Keep, T0 + 1, &Default::default()).await.expect("refuse"),
		SelfDecision::Decided(_)
	));
	assert_eq!(fx.governance.find_removal(id, T0 + 2).await.unwrap().unwrap().state, RemovalState::Open);

	// The same answer again changes nothing and is not an error.
	assert!(matches!(
		fx.governance.self_decision(&token, &code, Vote::Keep, T0 + 3, &Default::default()).await.expect("repeat"),
		SelfDecision::Decided(_)
	));
	// The counter is NOT reset by a correct answer — one attempt for each of the two
	// answers above. A token that has been guessed at stays closer to burning: the
	// guesses were still made. Both planes specify this identically; see the
	// "One specification for both planes" table in banking'''s docs/CONSILIUM.md.
	assert_eq!(fx.token_attempts(id).await, 2, "a correct code spends an attempt like any other");

	// A contradicting answer is refused, and answers as an absent invitation does.
	assert!(matches!(
		fx.governance
			.self_decision(&token, &code, Vote::Remove, T0 + 4, &Default::default())
			.await
			.expect("contradiction"),
		SelfDecision::Unusable
	));
	let after = fx.governance.find_removal(id, T0 + 5).await.unwrap().unwrap();
	assert_eq!(after.removal.decision(), Vote::Keep, "the first answer stands");
	assert_eq!(after.state, RemovalState::Open);
}

/// Pitfall 17. A stale approval can never execute, and no sweeper has to have run for
/// that to be true.
#[tokio::test]
async fn an_expired_token_cannot_decide() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");
	let id = record.removal.id();
	let (token, code) = fx.invitation_credentials(id).await;
	let late = T0 + REMOVAL_TTL_SECS + 1;

	assert!(fx.governance.invitation(&token, late).await.unwrap().is_none(), "a due proposal reads as absent");
	assert_eq!(
		fx.governance.find_removal(id, late).await.unwrap().unwrap().state,
		RemovalState::Expired,
		"and the read path projects it as expired without writing"
	);
	assert!(matches!(
		fx.governance.self_decision(&token, &code, Vote::Remove, late, &Default::default()).await.expect("late answer"),
		SelfDecision::Unusable
	));
	assert_eq!(fx.role_of(owners[0]).await, Role::Owner);

	// A due proposal must not hold the one-open-per-target index hostage forever.
	let reopened = fx.governance.open_removal(owners[0], owners[1], "again", late).await.expect("a fresh proposal");
	assert_ne!(reopened.removal.id(), id);
	assert_eq!(fx.governance.find_removal(id, late).await.unwrap().unwrap().state, RemovalState::Expired);
}

/// Pitfall 20's other half: two owners cannot each open a proposal against the same
/// person and race the outcome.
#[tokio::test]
async fn only_one_proposal_may_be_open_against_a_target() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(5).await;
	fx.governance.open_removal(owners[0], owners[1], "first", T0).await.expect("open");
	let err = fx.governance.open_removal(owners[0], owners[2], "second", T0 + 1).await.unwrap_err();
	assert!(matches!(err, DomainError::Repository(_)), "the partial unique index refuses the second: {err}");
}

#[tokio::test]
async fn resignation_respects_the_same_floor_and_moots_an_open_proposal() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");

	fx.governance.resign(owners[0], T0 + 1).await.expect("the fourth seat can be spared");
	assert_eq!(fx.role_of(owners[0]).await, Role::Investor);
	let mooted = fx.governance.find_removal(record.removal.id(), T0 + 2).await.unwrap().unwrap();
	assert_eq!(mooted.state, RemovalState::Void, "a proposal against someone who already left is moot");

	// Three remain, so a third seat can still go — the floor is two, not three.
	fx.governance.resign(owners[1], T0 + 3).await.expect("three may drop to two");
	assert_eq!(fx.role_of(owners[1]).await, Role::Investor);

	// Two remain: now nobody else may go, or the fund would be left with one.
	let err = fx.governance.resign(owners[2], T0 + 4).await.unwrap_err();
	assert!(matches!(err, DomainError::Conflict(_)), "{err}");
	assert!(
		matches!(fx.governance.resign(owners[0], T0 + 4).await.unwrap_err(), DomainError::Forbidden(_)),
		"a non-owner has nothing to resign"
	);
}

#[tokio::test]
async fn the_roster_reports_the_payout_floor() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let listed = fx.governance.owners().await.expect("roster");
	assert_eq!(listed.len(), 4);
	for owner in &owners {
		assert!(listed.iter().any(|row| row.id == owner.raw()), "every seat is listed");
	}
	assert!(listed.iter().all(|row| row.owner_since > 0), "the roster carries when each seat was granted");
}

/// The money plane's relay: idempotent by key, and bypassing every notification
/// preference — a security mail a subscriber can silently switch off is not one.
#[tokio::test]
async fn governance_mail_is_deduped_and_ignores_notification_preferences() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let payload = serde_json::json!({ "consilium_id": "c-1", "outcome": "EXECUTED", "amount": "1 USDT" });
	let key = format!("payout-outcome:{}", Uuid::new_v4());

	assert!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", "payout_outcome", &key, &payload)
			.await
			.expect("first")
	);
	// The subscriber follows nothing and has email switched off; the mail queues anyway.
	sqlx::query("UPDATE notification_subscribers SET email_enabled = FALSE, in_app_enabled = FALSE WHERE user_id = $1")
		.bind(owner.raw())
		.execute(&fx.pool)
		.await
		.expect("switch every channel off");
	let second_key = format!("payout-outcome:{}", Uuid::new_v4());
	assert!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", "payout_outcome", &second_key, &payload)
			.await
			.expect("muted")
	);

	assert!(
		!fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", "payout_outcome", &key, &payload)
			.await
			.expect("retry"),
		"an at-least-once caller may retry the same key without sending twice"
	);
	assert_eq!(
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries WHERE dedupe_key IN ($1, $2)")
			.bind(&key)
			.bind(&second_key)
			.fetch_one(&fx.pool)
			.await
			.unwrap(),
		2
	);
}

/// Pitfall 21/24's server half: the number the live feed emits moves on every write and
/// is read straight from Postgres, so a replica that never saw a broadcast still sees it.
#[tokio::test]
async fn the_governance_revision_moves_on_every_write() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let before = fx.governance.revision().await.expect("read the revision");

	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");
	let after_open = fx.governance.revision().await.unwrap();
	assert!(after_open > before, "opening moved it");

	let peer = record.removal.peers()[0].user_id;
	fx.governance.peer_vote(record.removal.id(), peer, Vote::Keep, T0 + 1, &Default::default()).await.expect("vote");
	assert!(fx.governance.revision().await.unwrap() > after_open, "so did the vote that closed it");
}

// ---------------------------------------------------------------------------------
// Admission — pitfall 21, and the reason every control above is not merely decorative.
// ---------------------------------------------------------------------------------

/// The happy path: every OTHER owner agrees, and the seat is granted in the same
/// transaction as the verdict.
#[tokio::test]
async fn an_admission_needs_every_other_owner_and_then_seats_the_candidate() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let candidate = fx.user().await;
	let record = fx.governance.open_admission(candidate, owners[0], "a new partner", T0).await.expect("open");
	assert_eq!(record.admission.peers().len(), 2, "every owner except the initiator");

	let midway = fx
		.governance
		.admission_vote(record.admission.id(), owners[1], DomainAdmissionVote::Admit, T0 + 1, &Default::default())
		.await
		.expect("first voter");
	assert_eq!(midway.state, ProposalState::Open, "a majority is not enough — a minority must not grow itself");
	assert_eq!(fx.role_of(candidate).await, Role::Investor, "and no seat yet");

	let after = fx
		.governance
		.admission_vote(record.admission.id(), owners[2], DomainAdmissionVote::Admit, T0 + 2, &Default::default())
		.await
		.expect("second voter");
	assert_eq!(after.state, ProposalState::Executed);
	assert_eq!(fx.role_of(candidate).await, Role::Owner, "the seat is granted with the verdict");
	assert!(
		fx.outbox_kinds(candidate).await.iter().any(|kind| kind == "ROLE_CHANGED"),
		"and the money plane learns through the outbox it already drains"
	);
	assert_eq!(fx.governance.owners().await.expect("roster").len(), 4);
}

/// Unanimity, so one refusal ends it and nobody is seated.
#[tokio::test]
async fn one_reject_ends_an_admission_and_grants_nothing() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let candidate = fx.user().await;
	let record = fx.governance.open_admission(candidate, owners[0], "a new partner", T0).await.expect("open");

	let after = fx
		.governance
		.admission_vote(record.admission.id(), owners[1], DomainAdmissionVote::Reject, T0 + 1, &Default::default())
		.await
		.expect("an owner may refuse");
	assert_eq!(after.state, ProposalState::Rejected);
	assert_eq!(fx.role_of(candidate).await, Role::Investor);

	let err = fx
		.governance
		.admission_vote(record.admission.id(), owners[2], DomainAdmissionVote::Admit, T0 + 2, &Default::default())
		.await
		.unwrap_err();
	assert!(matches!(err, DomainError::Conflict(_)), "a closed admission takes no more votes: {err}");
}

/// Vacuous unanimity again, in the direction that matters most: if "everyone agreed"
/// were true of an empty set, a lone owner could mint the majority they wanted.
#[tokio::test]
async fn a_lone_owner_cannot_mint_a_second_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let founder = fx.owner().await;
	let candidate = fx.user().await;
	let err = fx.governance.open_admission(candidate, founder, "my friend", T0).await.unwrap_err();
	assert!(matches!(err, DomainError::Conflict(_)), "{err}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor);
	assert_eq!(
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM owner_admission WHERE candidate_user_id = $1")
			.bind(candidate.raw())
			.fetch_one(&fx.pool)
			.await
			.expect("count"),
		0,
		"and nothing was written"
	);
}

#[tokio::test]
async fn neither_the_initiator_nor_the_candidate_votes_on_an_admission() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let candidate = fx.user().await;
	let record = fx.governance.open_admission(candidate, owners[0], "a new partner", T0).await.expect("open");

	let voters: Vec<UserId> = record.admission.peers().iter().map(|p| p.user_id).collect();
	assert!(!voters.contains(&owners[0]), "proposing is not agreeing");
	assert!(!voters.contains(&candidate), "the candidate has no say in their own admission");

	for who in [owners[0], candidate] {
		let err = fx
			.governance
			.admission_vote(record.admission.id(), who, DomainAdmissionVote::Admit, T0 + 1, &Default::default())
			.await
			.unwrap_err();
		assert!(matches!(err, DomainError::Forbidden(_)), "{who} must not be able to vote: {err}");
	}
}

#[tokio::test]
async fn only_one_admission_may_be_open_per_candidate() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let candidate = fx.user().await;
	fx.governance.open_admission(candidate, owners[0], "first", T0).await.expect("open");
	let err = fx.governance.open_admission(candidate, owners[1], "second", T0 + 1).await.unwrap_err();
	assert!(matches!(err, DomainError::Repository(_)), "the partial unique index refuses the second: {err}");
}

/// An admission that already passed cannot seat anyone if the owner who proposed it has
/// since lost their own seat — the same re-check the removal path makes.
#[tokio::test]
async fn an_admission_whose_initiator_lost_their_seat_is_void() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let candidate = fx.user().await;
	let record = fx.governance.open_admission(candidate, owners[0], "a new partner", T0).await.expect("open");
	fx.governance
		.admission_vote(record.admission.id(), owners[1], DomainAdmissionVote::Admit, T0 + 1, &Default::default())
		.await
		.expect("first voter");
	fx.demote(owners[0]).await;

	let after = fx
		.governance
		.admission_vote(record.admission.id(), owners[2], DomainAdmissionVote::Admit, T0 + 2, &Default::default())
		.await
		.expect("the last vote still lands");
	assert_eq!(after.state, ProposalState::Void);
	assert!(after.admission.void_reason().contains("initiator"), "{}", after.admission.void_reason());
	assert_eq!(fx.role_of(candidate).await, Role::Investor, "and no seat was granted");
}

// ---------------------------------------------------------------------------------
// SetRole is no longer a way in or out of ownership.
// ---------------------------------------------------------------------------------

/// The other half of pitfall 21. The consilium is only a control if the bare role edit
/// it replaces is actually closed off.
#[tokio::test]
async fn set_role_refuses_to_mint_or_to_strip_an_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(2).await;
	let candidate = fx.user().await;
	let directory = fx.directory();

	let minted = directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "owner".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(minted.code(), Code::FailedPrecondition, "{minted}");
	assert!(minted.message().contains("OpenOwnerAdmission"), "the refusal points at the consilium: {minted}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor);

	let stripped = directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: owners[1].to_string(),
				role: "investor".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(stripped.code(), Code::FailedPrecondition, "{stripped}");
	assert_eq!(fx.role_of(owners[1]).await, Role::Owner, "the seat stays");

	// Every OTHER role change is untouched — this closes ownership, not the console.
	directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "admin".into(),
			},
		))
		.await
		.expect("an ordinary role change still works");
	assert_eq!(fx.role_of(candidate).await, Role::Admin);
}

/// The bootstrap carve-out that used to live in `guard_ownership` is GONE, and this is
/// the test that keeps it gone. It seated the second owner directly while the roster was
/// smaller than two — precisely the window in which emergency access is live, so it
/// handed an `OWNER_SUBJECTS`-listed operator a way to build a roster of their own. The
/// first seats now come from the genesis seed, which runs at boot with no request behind
/// it, and `SetRole` refuses `owner` at every roster size including zero.
#[tokio::test]
async fn set_role_refuses_to_seat_an_owner_even_on_an_empty_registry() {
	let Some(fx) = setup().await else {
		return;
	};
	// `setup` leaves the registry empty — the one state the carve-out used to fire in.
	let operator = fx.user().await;
	let candidate = fx.user().await;
	// The caller is authorized by emergency access itself (there is no persisted owner to
	// authorize them), so this is the most permissive caller the plane can ever produce.
	let directory = fx.directory_with_break_glass(operator);

	let err = directory
		.set_role(as_user(
			operator,
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "owner".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("OpenOwnerAdmission"), "the refusal points at the consilium: {err}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor, "an empty registry is not a licence to seat anyone");

	// The rest of the console still works on that same authority — emergency access
	// grants `operator`/`admin`, it just never grants a seat.
	directory
		.set_role(as_user(
			operator,
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "admin".into(),
			},
		))
		.await
		.expect("an ordinary role change is exactly what emergency access is for");
	assert_eq!(fx.role_of(candidate).await, Role::Admin);
}

/// Emergency access is self-extinguishing: the moment the registry holds one owner, an
/// `OWNER_SUBJECTS`-listed subject is nobody again. Before that it authorizes, and this
/// test pins both halves — including the fact that an authorized operator is still not a
/// SEAT, so they hold no vote in any consilium.
#[tokio::test]
async fn break_glass_authorizes_on_an_empty_registry_and_nothing_once_it_fills() {
	let Some(fx) = setup().await else {
		return;
	};
	let operator = fx.user().await;
	let service = fx.service_with_break_glass(operator);

	// Empty registry: the gate lets them in.
	let roster = service
		.list_owners(as_user(operator, ListOwnersRequest {}))
		.await
		.expect("emergency access authorizes while the fund has no owners")
		.into_inner();
	assert!(roster.items.is_empty(), "authorized, but there is no roster to be on");

	// Seat two owners the only way a fixture can, and emergency access is over — for a
	// service that had already observed the empty state, which is what makes the latch
	// worth testing rather than assuming.
	let owners = fx.roster(2).await;
	let err = service.list_owners(as_user(operator, ListOwnersRequest {})).await.unwrap_err();
	assert_eq!(err.code(), Code::PermissionDenied, "the first owner closes emergency access: {err}");

	// And it stays closed: the latch is one-way, so even a fresh service instance — which
	// has to read the registry rather than remember it — refuses.
	let fresh = fx.service_with_break_glass(operator);
	let err = fresh.list_owners(as_user(operator, ListOwnersRequest {})).await.unwrap_err();
	assert_eq!(err.code(), Code::PermissionDenied, "{err}");
	assert_eq!(owners.len(), 2);
}

/// Emergency access never becomes a seat. On a populated fund an `OWNER_SUBJECTS`-listed
/// operator holds nothing at all — but the assertions below go further than the gate and
/// pin the consilium itself: they are not on the roster, they cannot open either
/// proposal, and they are not snapshotted as a voter. That last one is what would
/// otherwise have handed them a vote in every consilium, and on a quiet fund of two, a
/// majority.
#[tokio::test]
async fn a_break_glass_operator_holds_no_seat_in_any_consilium() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(3).await;
	let operator = fx.user().await;
	// A real owner reads the roster, so the assertion below is about who is ON it rather
	// than about who may look.
	let service = fx.service_with_break_glass(operator);

	let roster = service
		.list_owners(as_user(owners[0], ListOwnersRequest {}))
		.await
		.expect("an owner reads the roster")
		.into_inner();
	assert_eq!(roster.items.len(), 3, "the roster counts persisted seats only");
	assert!(!roster.items.iter().any(|o| o.user_id == operator.to_string()), "the env-listed operator is not on it");

	// They cannot be the initiator of either consilium: both read the persisted roster.
	let err = service
		.open_owner_removal(as_user(
			operator,
			OpenOwnerRemovalRequest {
				target_user_id: owners[0].to_string(),
				reason: "cause".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::PermissionDenied, "{err}");

	let err = service
		.open_owner_admission(as_user(
			operator,
			OpenOwnerAdmissionRequest {
				candidate_user_id: fx.user().await.to_string(),
				reason: "a new partner".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::PermissionDenied, "{err}");

	// And they are not snapshotted as a voter, so they cannot answer one either.
	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");
	assert!(
		!record.removal.peers().iter().any(|p| p.user_id == operator),
		"an env-listed operator must not appear in a snapshotted peer set"
	);
	let err = service
		.submit_peer_vote(as_user(
			operator,
			SubmitPeerVoteRequest {
				removal_id: record.removal.id().to_string(),
				vote: RemovalVote::Remove as i32,
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::PermissionDenied, "{err}");
}

/// A mail gateway follows every link in a message, including one on a proposal that
/// has already been decided. That must cost the human nothing: the token is refused
/// BEFORE an attempt is counted, so a scanner cannot quietly spend somebody's budget of
/// five and leave them locked out of their own invitation.
#[tokio::test]
async fn a_token_on_a_closed_proposal_is_refused_before_an_attempt_is_counted() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let record = fx.governance.open_removal(owners[0], owners[1], "cause", T0).await.expect("open");
	let id = record.removal.id();
	let (token, code) = fx.invitation_credentials(id).await;

	// A peer refuses, which closes the proposal outright.
	fx.governance.peer_vote(id, owners[2], Vote::Keep, T0 + 1, &Default::default()).await.expect("vote");
	assert_eq!(fx.governance.find_removal(id, T0 + 2).await.unwrap().unwrap().state, RemovalState::Rejected);

	// Both the RIGHT code and a wrong one answer identically, and neither is counted.
	for attempt in [code.as_str(), "WRONGCODE0"] {
		assert!(matches!(
			fx.governance.self_decision(&token, attempt, Vote::Remove, T0 + 3, &Default::default()).await.expect("answer"),
			SelfDecision::Unusable
		));
		assert_eq!(fx.token_attempts(id).await, 0, "a closed proposal must not spend the target's budget");
	}
}

/// A request carrying the verified claims the auth layer would have injected.
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

/// The TOCTOU window `SetRole` used to leave open, closed and pinned.
///
/// The guard used to read the target's role on its own connection and only then open the
/// write transaction. An admission committing in between was invisible to it, so a
/// demotion aimed at the candidate saw `holds_seat = false`, passed both refusals, and
/// then blocked on the row until the consilium committed — stripping the seat it had just
/// granted, with no consilium, no floor check and no `governance_event` row. This plane's
/// "exactly two writers of `owner`" invariant was false for the width of that window.
///
/// The race is constructed rather than raced for: a transaction that has already seated
/// the candidate holds their row, the demotion is issued while that lock is held, and the
/// seat is committed underneath it. The demotion cannot answer before the commit lands,
/// so a pass here means the decision was taken from the post-commit row.
#[tokio::test]
async fn set_role_cannot_strip_a_seat_granted_while_it_was_deciding() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(2).await;
	let candidate = fx.user().await;
	let directory = fx.directory();

	// Stand in for an admission carrying its verdict: the seat is written and the
	// candidate's row held, exactly as `grant_seat` leaves it mid-transaction.
	let url = std::env::var("DATABASE_URL").expect("setup already required it");
	let mut seating = PgConnection::connect(&url).await.expect("a connection for the seating transaction");
	sqlx::query("BEGIN").execute(&mut seating).await.expect("begin");
	sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1")
		.bind(candidate.raw())
		.execute(&mut seating)
		.await
		.expect("seat the candidate, uncommitted");

	let demotion = directory.set_role(as_user(
		owners[0],
		SetRoleRequest {
			user_id: candidate.to_string(),
			role: "investor".into(),
		},
	));
	let commit = async {
		// Long enough for the demotion to reach the row lock it has to wait on. If it has
		// not got there yet the test still passes — it merely stops being able to catch the
		// old bug — so this can never become a false failure.
		tokio::time::sleep(std::time::Duration::from_millis(250)).await;
		sqlx::query("COMMIT").execute(&mut seating).await.expect("commit the seat");
	};
	let (result, ()) = tokio::join!(demotion, commit);

	let err = result.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "the demotion must see the committed seat: {err}");
	assert!(err.message().contains("OpenOwnerRemoval"), "and be pointed at the consilium: {err}");
	assert_eq!(fx.role_of(candidate).await, Role::Owner, "the seat the consilium granted survives");
}

/// Every RPC on the consilium is Owner-only, through the SHARED RBAC gate. An admin —
/// the most privileged role below owner, and the one that can already perform every
/// other identity mutation — holds nothing here.
#[tokio::test]
async fn the_consilium_is_closed_to_everyone_but_owners() {
	let Some(fx) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let owners = fx.roster(4).await;
	let outsider = fx.owner().await;
	fx.users.set_role(outsider, Role::Admin).await.expect("demote to admin");
	let service = fx.service();

	assert_eq!(service.list_owners(as_user(outsider, ListOwnersRequest {})).await.unwrap_err().code(), Code::PermissionDenied);
	let open = OpenOwnerRemovalRequest {
		target_user_id: owners[0].to_string(),
		reason: "cause".into(),
	};
	assert_eq!(service.open_owner_removal(as_user(outsider, open)).await.unwrap_err().code(), Code::PermissionDenied);
	assert_eq!(
		service
			.resign_ownership(as_user(outsider, ResignOwnershipRequest { confirm_email: String::new() }))
			.await
			.unwrap_err()
			.code(),
		Code::PermissionDenied
	);
	// An owner reaches the same surface.
	assert!(service.list_owners(as_user(owners[0], ListOwnersRequest {})).await.is_ok());
}

/// The target and the initiator are refused at the gRPC edge too — by the peer set,
/// which is the only thing consulted, so no ad-hoc check can be forgotten or bypassed.
#[tokio::test]
async fn the_service_refuses_a_vote_from_the_target_or_the_initiator() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let (target, initiator) = (owners[0], owners[1]);
	let service = fx.service();

	let opened = service
		.open_owner_removal(as_user(
			initiator,
			OpenOwnerRemovalRequest {
				target_user_id: target.to_string(),
				reason: "cause".into(),
			},
		))
		.await
		.expect("open")
		.into_inner();
	assert_eq!(opened.peers.len(), 2);
	assert!(opened.target_notified);

	for barred in [target, initiator] {
		let vote = SubmitPeerVoteRequest {
			removal_id: opened.id.clone(),
			vote: RemovalVote::Remove as i32,
		};
		assert_eq!(service.submit_peer_vote(as_user(barred, vote)).await.unwrap_err().code(), Code::PermissionDenied);
	}

	// Only the initiator may withdraw it.
	let peer = UserId::from_raw(Uuid::parse_str(&opened.peers[0].user_id).unwrap());
	let cancel = |id: String| CancelOwnerRemovalRequest { removal_id: id };
	assert_eq!(
		service.cancel_owner_removal(as_user(peer, cancel(opened.id.clone()))).await.unwrap_err().code(),
		Code::PermissionDenied
	);
	assert!(service.cancel_owner_removal(as_user(initiator, cancel(opened.id))).await.is_ok());
}

/// Resigning is typed confirmation, not a stray click: the address must be the
/// caller's own, and the floor still applies to leaving voluntarily.
#[tokio::test]
async fn resignation_demands_the_callers_own_address() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let service = fx.service();
	let leaving = owners[0];
	let mine = fx.users.find_by_id(leaving).await.unwrap().unwrap().email().as_str().to_owned();
	let theirs = fx.users.find_by_id(owners[1]).await.unwrap().unwrap().email().as_str().to_owned();

	let resign = |email: String| ResignOwnershipRequest { confirm_email: email };
	for wrong in [String::new(), "not-an-address".into(), theirs] {
		assert_eq!(service.resign_ownership(as_user(leaving, resign(wrong))).await.unwrap_err().code(), Code::InvalidArgument);
	}
	assert_eq!(fx.role_of(leaving).await, Role::Owner, "no near-miss gave up the seat");

	// Casing is normalized through the same parser the record was stored with.
	let remaining = service
		.resign_ownership(as_user(leaving, resign(mine.to_uppercase())))
		.await
		.expect("the caller's own address, however they typed it")
		.into_inner();
	assert_eq!(fx.role_of(leaving).await, Role::Investor);
	assert_eq!(remaining.items.len(), 3);
	// Three owners is the LAST roster that can still authorize a payout (threshold
	// floor(3/2)+1 = 2, over two voters), which is exactly why the removal floor keeps
	// three: the flag reports being below it, not at it.
	assert!(!remaining.below_payout_floor);
}
