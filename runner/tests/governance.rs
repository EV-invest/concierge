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

use std::{sync::Arc, time::Duration};

mod common;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	governance::{Governance, MailRelay},
	infrastructure::{
		db,
		governance::{PgGovernance, SelfDecision},
		notifications::PgNotifications,
		users::PgUsers,
	},
	notification::RateLimiter,
	ports::{GovernanceRepository, NotificationDispatchRepository, NotificationRepository, UserDirectoryRepository},
};
use domain::{
	authz::Role,
	error::DomainError,
	governance::{AdmissionVote as DomainAdmissionVote, MAX_CODE_ATTEMPTS, ProposalState, REMOVAL_TTL_SECS, RemovalId, RemovalState, Vote},
	users::{AuthSubject, Email, UserId},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	CancelOwnerRemovalRequest, FeePolicyApprovalMail, FeePolicyNoticeMail, FeeTerms, GovernanceMailKind, ListOwnersRequest, OpenOwnerAdmissionRequest, OpenOwnerRemovalRequest,
	PaymentApprovalMail, PaymentConsentMail, PayoutApprovalMail, PayoutOutcomeMail, RemovalVote, ResignOwnershipRequest, SendGovernanceMailRequest, SetRoleRequest, SubmitPeerVoteRequest,
	governance_service_server::GovernanceService, mail_relay_service_server::MailRelayService, user_directory_server::UserDirectory,
};
use sqlx::{Connection, PgConnection, PgPool, Row};
use tonic::{Code, Request};
use uuid::Uuid;

/// Arbitrary, stable key for the session lock this suite serializes on.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
/// A fixed instant, so every assertion about expiry is exact rather than racy.
const T0: i64 = 1_800_000_000;
/// The shared banking↔concierge service secret, as the relay tests present it. Its value
/// is irrelevant here — what these tests are about is WHO a mail may be addressed to.
const RELAY_TOKEN: &str = "relay-itest-token";
/// The origin every emailed link must sit under, so the link checks are not what fails.
const RELAY_ORIGIN: &str = "https://relay.example.test";

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
		self.provision(true).await
	}

	/// The same, at an address nobody has proved belongs to them.
	async fn unverified_user(&self) -> UserId {
		self.provision(false).await
	}

	/// A seated owner whose address nobody has proved belongs to them.
	async fn unverified_owner(&self) -> UserId {
		let id = self.unverified_user().await;
		self.users.set_role(id, Role::Owner).await.expect("grant the seat");
		id
	}

	async fn provision(&self, email_verified: bool) -> UserId {
		let subject = AuthSubject::parse(&format!("gov-itest-{}", Uuid::new_v4())).unwrap();
		let email = Email::parse(&format!("gov-{}@example.com", Uuid::new_v4())).unwrap();
		self.users.provision(subject, email, email_verified).await.expect("provision").id()
	}

	/// The money plane's push seam over the same adapters, with a ceiling no test here
	/// reaches by accident.
	fn relay(&self) -> MailRelay {
		self.relay_allowing(1_000)
	}

	/// The same, accepting `per_hour` mails per recipient.
	fn relay_allowing(&self, per_hour: u32) -> MailRelay {
		MailRelay::new(
			self.users.clone(),
			self.governance.clone(),
			Arc::new(PgNotifications::new(self.pool.clone())),
			Arc::new(RateLimiter::new(Duration::from_secs(3600), per_hour)),
			Some(RELAY_TOKEN.to_owned()),
			RELAY_ORIGIN.to_owned(),
		)
	}

	/// The inbox entries' own dedupe keys — to see the namespace.
	async fn inbox_keys(&self, id: UserId) -> Vec<String> {
		sqlx::query_scalar("SELECT n.dedupe_key FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the inbox keys")
	}

	async fn email_of(&self, id: UserId) -> String {
		self.users.find_by_id(id).await.expect("read").expect("user exists").email().as_str().to_owned()
	}

	/// The queued delivery a relay call produced, by its idempotency key.
	async fn delivery(&self, dedupe_key: &str) -> Option<(String, String)> {
		sqlx::query("SELECT kind, recipient FROM notification_deliveries WHERE dedupe_key = $1")
			.bind(dedupe_key)
			.fetch_optional(&self.pool)
			.await
			.expect("read the queue")
			.map(|row| (row.get("kind"), row.get("recipient")))
	}

	/// The queued delivery's typed payload, by its idempotency key.
	async fn payload(&self, dedupe_key: &str) -> serde_json::Value {
		sqlx::query_scalar("SELECT payload FROM notification_deliveries WHERE dedupe_key = $1")
			.bind(dedupe_key)
			.fetch_one(&self.pool)
			.await
			.expect("a queued delivery with a payload")
	}

	/// Every inbox entry a user holds, as `(topic, kind, title, body)`.
	async fn inbox(&self, id: UserId) -> Vec<(String, String, String, String)> {
		sqlx::query(
			"SELECT n.topic, n.kind, n.title, n.body FROM notifications n \
			 JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 ORDER BY n.created_at",
		)
		.bind(id.raw())
		.fetch_all(&self.pool)
		.await
		.expect("read the inbox")
		.into_iter()
		.map(|row| (row.get("topic"), row.get("kind"), row.get("title"), row.get("body")))
		.collect()
	}

	/// How many topics a user follows. Zero for anyone who never opened their settings.
	async fn followed_topics(&self, id: UserId) -> i64 {
		sqlx::query_scalar("SELECT count(*) FROM notification_subscriptions t JOIN notification_subscribers s ON s.id = t.subscriber_id WHERE s.user_id = $1")
			.bind(id.raw())
			.fetch_one(&self.pool)
			.await
			.expect("count subscriptions")
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
			.enqueue_mail(owner.raw(), "relay@example.com", true, "payout_outcome", &key, &payload)
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
			.enqueue_mail(owner.raw(), "relay@example.com", true, "payout_outcome", &second_key, &payload)
			.await
			.expect("muted")
	);

	assert!(
		!fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "payout_outcome", &key, &payload)
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

/// Queueing a governance mail refreshes the recipient's subscriber row, and that row's
/// `email_verified` is what `emit` consults before mailing an ordinary notification. It
/// must carry the identity record's flag: hard-coding `true` there made an owner whose
/// address nobody has proved eligible for every email notification they follow (#65).
#[tokio::test]
async fn a_governance_mail_does_not_verify_the_subscriber_by_itself() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.unverified_owner().await;
	let email = fx.email_of(owner).await;
	let payload = serde_json::json!({ "consilium_id": "c-65", "outcome": "EXECUTED", "amount": "1 USDT" });
	assert!(
		fx.governance
			.enqueue_mail(owner.raw(), &email, false, "payout_outcome", &format!("payout-outcome:{}", Uuid::new_v4()), &payload)
			.await
			.expect("queued")
	);
	let (subscriber_id, verified): (Uuid, bool) = sqlx::query_as("SELECT id, email_verified FROM notification_subscribers WHERE user_id = $1")
		.bind(owner.raw())
		.fetch_one(&fx.pool)
		.await
		.expect("the subscriber row the mail refreshed");
	assert!(
		!verified,
		"the subscriber carries the identity record's flag, not the fact that a governance mail was addressed to it"
	);

	// The consequence the flag guards: an ordinary notification on a followed topic
	// reaches the inbox and NOT the mail queue. The row is followed as the mail left
	// it — re-resolving the subscriber here would overwrite the very flag under test.
	let notifications = PgNotifications::new(fx.pool.clone());
	notifications.set_topic_subscription(subscriber_id, "fund:quy-nhon", true, true).await.expect("follow");
	let outcome = notifications
		.emit(owner.raw(), "fund:quy-nhon", "nav", "NAV updated", "", "", &format!("nav:{}", Uuid::new_v4()), T0)
		.await
		.expect("emit");
	assert!(outcome.in_app, "the in-app copy is unaffected");
	assert!(!outcome.email, "no email is queued to an address nobody has proved belongs to the owner");
}

/// A delivery the dispatcher gives up on loses its link and code, exactly as one it
/// sends does; a delivery it will retry keeps them, because the retry renders from them.
/// Anyone holding a dump of the table must not be able to act on a still-pending seat
/// through a mail that was never sent (#66).
#[tokio::test]
async fn a_parked_delivery_is_redacted_but_a_retried_one_is_not() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let key = format!("payout-approval:{}", Uuid::new_v4());
	let payload = serde_json::json!({
		"consilium_id": "c-66", "initiator_email": "init@example.com", "amount": "1 USDT",
		"approval_url": "https://example.test/governance/consilium/c-66", "code": "ABCDEFGH",
	});
	assert!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "payout_approval", &key, &payload)
			.await
			.expect("queued")
	);
	let delivery_id: i64 = sqlx::query_scalar("SELECT id FROM notification_deliveries WHERE dedupe_key = $1")
		.bind(&key)
		.fetch_one(&fx.pool)
		.await
		.expect("the queued row");
	let dispatch = PgNotifications::new(fx.pool.clone());

	// Attempts left ⇒ rescheduled, and the payload is what the next attempt sends.
	dispatch.mark_failed(delivery_id, "smtp down", 60, 6).await.expect("reschedule");
	let (status, payload_after): (String, serde_json::Value) = sqlx::query_as("SELECT status, payload FROM notification_deliveries WHERE id = $1")
		.bind(delivery_id)
		.fetch_one(&fx.pool)
		.await
		.expect("the row");
	assert_eq!(status, "pending");
	assert_eq!(payload_after, payload, "a retry keeps everything, secrets included");

	// Out of attempts ⇒ parked. The secrets go; what an operator reads stays.
	dispatch.mark_failed(delivery_id, "smtp down", 60, 0).await.expect("park");
	let (status, payload_after): (String, serde_json::Value) = sqlx::query_as("SELECT status, payload FROM notification_deliveries WHERE id = $1")
		.bind(delivery_id)
		.fetch_one(&fx.pool)
		.await
		.expect("the row");
	assert_eq!(status, "failed");
	assert!(payload_after.get("approval_url").is_none(), "the link is gone");
	assert!(payload_after.get("code").is_none(), "and the code that arms it");
	assert_eq!(payload_after["consilium_id"], "c-66", "the rest is kept for the operator who looks at the parked row");
	assert_eq!(payload_after["amount"], "1 USDT");
	let dumped = payload_after.to_string();
	assert!(!dumped.contains("ABCDEFGH") && !dumped.contains("consilium/c-66"), "nothing secret survives in any form");
}

/// A relay call as banking makes it: the shared service token in `authorization`.
fn relayed(body: SendGovernanceMailRequest) -> Request<SendGovernanceMailRequest> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("authorization", format!("Bearer {RELAY_TOKEN}").parse().unwrap());
	request
}

/// A well-formed consent request. `addressee` is who the mail is sent TO; `subject` is
/// who the payload claims the money belongs to. They are separate arguments precisely
/// because the rule under test is that they must be the same person.
fn consent(addressee: UserId, subject: UserId) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: GovernanceMailKind::PaymentConsent as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("payment-consent:{}", Uuid::new_v4()),
		payout_approval: None,
		payout_outcome: None,
		payment_consent: Some(PaymentConsentMail {
			payment_id: "pay-7".into(),
			subject_user_id: subject.to_string(),
			initiator_email: "ops@evinvest.ltd".into(),
			tier: "external".into(),
			source: "Quy Nhon Fund — distributions".into(),
			destination: "Your bank account ••4417".into(),
			amount: "1 200.00 USDT".into(),
			reason: "Scheduled quarterly distribution".into(),
			payload_hash: "9f2c1ab4de5607891122334455667788".into(),
			expires_at: T0 + 86_400,
			approval_url: format!("{RELAY_ORIGIN}/cabinet/payment-consent/tok"),
			code: "483012".into(),
		}),
		payment_approval: None,
		fee_policy_approval: None,
		fee_policy_notice: None,
	}
}

/// A well-formed payout approval — the consilium's question about a withdrawal to a rail.
fn payout(addressee: UserId) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: GovernanceMailKind::PayoutApproval as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("payout-approval:{}", Uuid::new_v4()),
		payout_approval: Some(PayoutApprovalMail {
			consilium_id: "c-1".into(),
			initiator_email: "ops@evinvest.ltd".into(),
			network: "TRON".into(),
			address: "TJRabc".into(),
			amount: "10 000 USDT".into(),
			memo: String::new(),
			payload_hash: "ab".into(),
			threshold: 2,
			owner_count: 3,
			expires_at: T0 + 86_400,
			approval_url: format!("{RELAY_ORIGIN}/cabinet/payout-approval/tok"),
			code: "483012".into(),
		}),
		payout_outcome: None,
		payment_consent: None,
		payment_approval: None,
		fee_policy_approval: None,
		fee_policy_notice: None,
	}
}

/// The rule that makes this kind possible at all: a consent mail is addressed by
/// IDENTITY, not by role, so an ordinary investor can be asked about their own money —
/// and it reaches that one person and nobody else.
///
/// The address still comes from the identity record. Neither field of the request can
/// choose where the mail lands.
#[tokio::test]
async fn a_payment_consent_reaches_its_subject_and_nobody_else() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	assert_eq!(fx.role_of(investor).await, Role::Investor, "the whole point: no seat is involved");

	let request = consent(investor, investor);
	let key = request.dedupe_key.clone();
	assert!(fx.relay().send_governance_mail(relayed(request)).await.expect("the subject may be asked").into_inner().enqueued);
	assert_eq!(
		fx.delivery(&key).await.expect("queued"),
		("payment_consent".to_owned(), fx.email_of(investor).await),
		"the address is resolved from the identity record, never from the request"
	);

	// Fanning one payment's consent out to a second mailbox means contradicting the
	// payload in the same message, and that is refused from either side.
	let stranger = fx.user().await;
	for (addressee, subject, why) in [
		(stranger, investor, "a consent addressed to somebody other than the subject"),
		(investor, stranger, "a consent claiming a subject the addressee is not"),
	] {
		let err = fx.relay().send_governance_mail(relayed(consent(addressee, subject))).await.unwrap_err();
		assert_eq!(err.code(), Code::FailedPrecondition, "{why}: {err}");
	}
}

/// Widening the relay for consent must not have widened it for the payout kinds. Those
/// still speak to the consilium, and the owner rule is what stops a compromised money
/// plane aiming a branded security mail at any address on the platform.
#[tokio::test]
async fn a_payout_mail_still_reaches_only_a_fund_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let err = fx.relay().send_governance_mail(relayed(payout(investor))).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "a non-owner has no standing in a payout consilium: {err}");

	let owner = fx.owner().await;
	assert!(
		fx.relay()
			.send_governance_mail(relayed(payout(owner)))
			.await
			.expect("a seated owner may be asked")
			.into_inner()
			.enqueued
	);
}

/// An unverified address is one nobody has proved belongs to this person. A consent mail
/// carries both the link and the code that arms it, so sending it there hands the
/// decision to whoever holds the mailbox — the one thing consent exists to rule out.
#[tokio::test]
async fn a_payment_consent_refuses_an_unverified_address() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.unverified_user().await;
	let request = consent(investor, investor);
	let key = request.dedupe_key.clone();
	let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(fx.delivery(&key).await.is_none(), "a refused call queues nothing");
}

/// The money plane is an untrusted caller and `reason` is free text an operator typed.
/// It reaches the subject verbatim in a text part that is NOT escaped, so a newline in it
/// would forge the `Amount:`/`To:` lines the mail exists to state. Refused at the seam,
/// before a row exists.
#[tokio::test]
async fn a_payment_consent_refuses_a_reason_it_cannot_show_safely() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let with_reason = |reason: String| {
		let mut request = consent(investor, investor);
		request.payment_consent.as_mut().unwrap().reason = reason;
		request
	};

	for (reason, why) in [
		("fine\nAmount: 0.01 USDT".to_owned(), "a newline forges a line of the text part"),
		("fine\r\nTo: attacker".to_owned(), "so does a carriage return"),
		("fine\u{7}".to_owned(), "and so does any other control character"),
		(String::new(), "a consent request nobody explained is one nobody can judge"),
		("   ".to_owned(), "nor does whitespace count as an explanation"),
		("a".repeat(501), "over the byte limit"),
		// 200 four-byte code points: well under 500 CHARACTERS, four times over the bytes
		// the row and the transport actually carry.
		("🙂".repeat(200), "the limit is bytes, not characters"),
	] {
		let request = with_reason(reason);
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}
}

/// The remaining fields the money plane supplies are held to the same rule, and `tier` is
/// a closed set: a word neither plane recognises means they disagree about what the
/// payment IS, which is a call to reject rather than a string to print at someone
/// deciding whether to release their money.
#[tokio::test]
async fn a_payment_consent_refuses_an_unrenderable_payload() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let mutate = |edit: &dyn Fn(&mut PaymentConsentMail)| {
		let mut request = consent(investor, investor);
		edit(request.payment_consent.as_mut().unwrap());
		request
	};

	for (request, why) in [
		(mutate(&|m| m.tier = "gold".into()), "an unrecognised tier"),
		(mutate(&|m| m.tier = String::new()), "no tier at all"),
		(mutate(&|m| m.amount = "1\n2".into()), "a forged amount"),
		(mutate(&|m| m.destination = "bank\nTo: attacker".into()), "a forged destination"),
		(mutate(&|m| m.subject_user_id = "not-a-uuid".into()), "a subject that is not an id"),
		(mutate(&|m| m.approval_url = "https://attacker.example/consent/tok".into()), "an off-origin link"),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}
}

/// A well-formed payment approval — the consilium's question about fund-owned money.
fn payment_approval(addressee: UserId) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: GovernanceMailKind::PaymentApproval as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("payment-approval:{}", Uuid::new_v4()),
		payout_approval: None,
		payout_outcome: None,
		payment_consent: None,
		payment_approval: Some(PaymentApprovalMail {
			consilium_id: "c-9".into(),
			payment_id: "pay-9".into(),
			initiator_email: "ops@evinvest.ltd".into(),
			tier: "service".into(),
			source: "Piggybank — fund treasury".into(),
			destination: "Quy Nhon Fund — pooled funds".into(),
			amount: "25 000.00 USDT".into(),
			reason: "Seed the pooled balance for Q3".into(),
			payload_hash: "9f2c1ab4de5607891122334455667788".into(),
			threshold: 2,
			owner_count: 3,
			expires_at: T0 + 86_400,
			approval_url: format!("{RELAY_ORIGIN}/cabinet/payment-approval/tok"),
			code: "483012".into(),
		}),
		fee_policy_approval: None,
		fee_policy_notice: None,
	}
}

/// The outcome of a PAYMENT consilium, riding the payout outcome payload with the payment
/// tuple filled and the rail pair empty.
fn payment_outcome(addressee: UserId, kind: GovernanceMailKind) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: kind as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("payment-outcome:{}", Uuid::new_v4()),
		payout_approval: None,
		payout_outcome: Some(PayoutOutcomeMail {
			consilium_id: "c-9".into(),
			outcome: "EXECUTED".into(),
			network: String::new(),
			address: String::new(),
			amount: "25 000.00 USDT".into(),
			detail: "Settled as one ledger transfer.".into(),
			tier: "service".into(),
			source: "Piggybank — fund treasury".into(),
			destination: "Quy Nhon Fund — pooled funds".into(),
			reason: "Seed the pooled balance for Q3".into(),
			fund: String::new(),
			current: None,
			proposed: None,
		}),
		payment_consent: None,
		payment_approval: None,
		fee_policy_approval: None,
		fee_policy_notice: None,
	}
}

/// The outcome of a FEE POLICY consilium, riding the outcome payload with the fee terms
/// description filled and both the rail pair and the payment tuple empty.
fn fee_policy_outcome(addressee: UserId, kind: GovernanceMailKind) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: kind as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("fee-policy-outcome:{}", Uuid::new_v4()),
		payout_approval: None,
		payout_outcome: Some(PayoutOutcomeMail {
			consilium_id: "c-12".into(),
			outcome: "EXECUTED".into(),
			network: String::new(),
			address: String::new(),
			amount: String::new(),
			detail: "The new terms apply from the next crystallization.".into(),
			tier: String::new(),
			source: String::new(),
			destination: String::new(),
			reason: "Align with the revised prospectus".into(),
			fund: "Quy Nhon Fund".into(),
			current: Some(house_terms()),
			proposed: Some(proposed_terms()),
		}),
		payment_consent: None,
		payment_approval: None,
		fee_policy_approval: None,
		fee_policy_notice: None,
	}
}

/// The new consilium kind is addressed under the payout rule, not the consent one: a
/// seated owner, and nobody else. What changed is only what the mail describes.
#[tokio::test]
async fn a_payment_approval_reaches_only_a_fund_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let err = fx.relay().send_governance_mail(relayed(payment_approval(investor))).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "a non-owner has no standing in a payment consilium: {err}");

	let owner = fx.owner().await;
	let request = payment_approval(owner);
	let key = request.dedupe_key.clone();
	assert!(
		fx.relay()
			.send_governance_mail(relayed(request))
			.await
			.expect("a seated owner may be asked")
			.into_inner()
			.enqueued
	);
	assert_eq!(fx.delivery(&key).await.expect("queued"), ("payment_approval".to_owned(), fx.email_of(owner).await));
	let payload = fx.payload(&key).await;
	assert_eq!(payload["source"], "Piggybank — fund treasury");
	assert_eq!(payload["destination"], "Quy Nhon Fund — pooled funds");
	assert_eq!(payload["threshold"], 2, "the bar the owner is measured against travels with the mail");
	assert!(
		fx.inbox(owner).await.is_empty(),
		"an owner's approval leaves no inbox trace — the consilium surface is where they find it"
	);
}

/// The consent's second rule applies to the consilium kinds too: an approval mail
/// carries the link and the code that arms it, so an address nobody has proved belongs
/// to the owner would hand their vote to whoever holds the mailbox.
#[tokio::test]
async fn a_payment_approval_refuses_an_unverified_address() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.unverified_owner().await;
	let request = payment_approval(owner);
	let key = request.dedupe_key.clone();
	let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(fx.delivery(&key).await.is_none(), "a refused call queues nothing");
}

/// The payout kinds shipped without that rule (#64), so a seated owner at an address
/// nobody had verified was still handed a payout vote. One rule for every consilium
/// kind now: the approval, and both outcome kinds riding the same payload.
#[tokio::test]
async fn a_payout_mail_refuses_an_unverified_address() {
	let Some(fx) = setup().await else {
		return;
	};
	let unverified = fx.unverified_owner().await;
	for (request, why) in [
		(payout(unverified), "a payout approval"),
		(payment_outcome(unverified, GovernanceMailKind::PayoutOutcome), "a consilium outcome"),
		(payment_outcome(unverified, GovernanceMailKind::ApprovalTokenBurned), "a burned-token notice"),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::FailedPrecondition, "{why} to an unverified address: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: a refused call queues nothing");
	}

	// The control: the rule narrows on verification, not on the kind.
	let owner = fx.owner().await;
	for (request, why) in [
		(payout(owner), "a payout approval"),
		(payment_outcome(owner, GovernanceMailKind::PayoutOutcome), "a consilium outcome"),
		(payment_outcome(owner, GovernanceMailKind::ApprovalTokenBurned), "a burned-token notice"),
	] {
		let key = request.dedupe_key.clone();
		assert!(
			fx.relay()
				.send_governance_mail(relayed(request))
				.await
				.expect("a verified owner may be asked")
				.into_inner()
				.enqueued,
			"{why} to a verified owner is queued"
		);
		assert!(fx.delivery(&key).await.is_some(), "{why}: queued for the verified owner");
	}
}

/// The same field rules as the consent mail: bounded in bytes, no control characters, a
/// closed tier set, a required reason, a link on our own origin.
#[tokio::test]
async fn a_payment_approval_refuses_an_unrenderable_payload() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let mutate = |edit: &dyn Fn(&mut PaymentApprovalMail)| {
		let mut request = payment_approval(owner);
		edit(request.payment_approval.as_mut().unwrap());
		request
	};

	for (request, why) in [
		(mutate(&|m| m.tier = "gold".into()), "an unrecognised tier"),
		(mutate(&|m| m.amount = "1\n2".into()), "a forged amount"),
		(mutate(&|m| m.reason = "fine\r\nTo: attacker".into()), "a forged line in the reason"),
		(mutate(&|m| m.reason = "   ".into()), "no reason at all"),
		(mutate(&|m| m.reason = "🙂".repeat(200)), "a reason over the byte limit"),
		(mutate(&|m| m.approval_url = "https://attacker.example/approve/tok".into()), "an off-origin link"),
		(
			mutate(&|m| m.approval_url = format!("{RELAY_ORIGIN}/approve/tok\nhttps://attacker.example/")),
			"a link that breaks the line",
		),
		(
			mutate(&|m| m.approval_url = format!("{RELAY_ORIGIN}/approve/tok https://attacker.example/")),
			"a link with a space after the origin",
		),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}

	let mut without_body = payment_approval(owner);
	without_body.payment_approval = None;
	let err = fx.relay().send_governance_mail(relayed(without_body)).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "the kind names a payload it did not carry: {err}");
}

/// A payment consilium's outcome — and its burn notice — ride the outcome payload with
/// the payment tuple filled, under the owner rule and the payment field rules.
#[tokio::test]
async fn a_payment_outcome_rides_the_outcome_payload() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	for kind in [GovernanceMailKind::PayoutOutcome, GovernanceMailKind::ApprovalTokenBurned] {
		let request = payment_outcome(owner, kind);
		let key = request.dedupe_key.clone();
		assert!(
			fx.relay()
				.send_governance_mail(relayed(request))
				.await
				.expect("an owner is told how it ended")
				.into_inner()
				.enqueued
		);
		let payload = fx.payload(&key).await;
		assert_eq!(payload["tier"], "service");
		assert_eq!(payload["destination"], "Quy Nhon Fund — pooled funds");
		assert_eq!(payload["network"], "", "the rail pair stays empty, which is how the renderer tells the two apart");
	}

	let investor = fx.user().await;
	let err = fx
		.relay()
		.send_governance_mail(relayed(payment_outcome(investor, GovernanceMailKind::PayoutOutcome)))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "still a consilium mail: {err}");

	let mut bad_tier = payment_outcome(owner, GovernanceMailKind::PayoutOutcome);
	bad_tier.payout_outcome.as_mut().unwrap().tier = "gold".into();
	let err = fx.relay().send_governance_mail(relayed(bad_tier)).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "the tier set is closed here too: {err}");

	let mut forged = payment_outcome(owner, GovernanceMailKind::PayoutOutcome);
	forged.payout_outcome.as_mut().unwrap().reason = "ok\nAmount: 0".into();
	let err = fx.relay().send_governance_mail(relayed(forged)).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "the payment tuple is held to `line`: {err}");
}

/// An outcome names ONE subject, whole, and ends one of the ways a consilium can end:
/// the renderer switches on which pair is filled and puts the outcome in the headline,
/// so a payload naming both, or half of one, or a word of its own, is refused.
#[tokio::test]
async fn an_outcome_names_one_whole_subject_and_a_known_ending() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let mutate = |edit: &dyn Fn(&mut PayoutOutcomeMail)| {
		let mut request = payment_outcome(owner, GovernanceMailKind::PayoutOutcome);
		edit(request.payout_outcome.as_mut().unwrap());
		request
	};
	for (request, why) in [
		(mutate(&|m| m.network = "TRON".into()), "a rail on a payment"),
		(mutate(&|m| m.address = "TJRabc".into()), "an address on a payment"),
		(mutate(&|m| m.source = String::new()), "a payment with no source"),
		(mutate(&|m| m.destination = String::new()), "a payment with no destination"),
		(mutate(&|m| m.tier = String::new()), "a payment with no tier"),
		(mutate(&|m| m.outcome = "WHATEVER".into()), "an ending the consilium cannot reach"),
		(mutate(&|m| m.outcome = "executed".into()), "the money plane's own casing is upper"),
		(mutate(&|m| m.outcome = String::new()), "no ending at all"),
		(mutate(&|m| m.fund = "Quy Nhon Fund".into()), "a fund on a payment"),
		(mutate(&|m| m.proposed = Some(proposed_terms())), "terms on a payment"),
		(
			mutate(&|m| {
				m.tier = String::new();
				m.source = String::new();
				m.destination = String::new();
				m.network = "TRON".into();
				m.address = "TJRabc".into();
				m.fund = "Quy Nhon Fund".into();
				m.proposed = Some(proposed_terms());
			}),
			"a rail on fee terms",
		),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}

	// Every ending the money plane actually announces still passes, on a payout too.
	for outcome in ["APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "EXECUTED", "EXECUTION_FAILED", "TOKEN_BURNED"] {
		let request = mutate(&|m| {
			m.outcome = outcome.into();
			m.tier = String::new();
			m.source = String::new();
			m.destination = String::new();
			m.reason = String::new();
			m.network = "TRON".into();
			m.address = "TJRabc".into();
		});
		assert!(
			fx.relay()
				.send_governance_mail(relayed(request))
				.await
				.unwrap_or_else(|e| panic!("{outcome}: {e}"))
				.into_inner()
				.enqueued
		);
	}
}

/// A fee-policy consilium's outcome — and its burn notice — ride the outcome payload with
/// the fee terms description filled, under the owner rule and the fee approval's field
/// rules: one rule per field across every kind that carries it.
#[tokio::test]
async fn a_fee_policy_outcome_rides_the_outcome_payload() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	for kind in [GovernanceMailKind::PayoutOutcome, GovernanceMailKind::ApprovalTokenBurned] {
		let request = fee_policy_outcome(owner, kind);
		let key = request.dedupe_key.clone();
		assert!(
			fx.relay()
				.send_governance_mail(relayed(request))
				.await
				.expect("an owner is told how it ended")
				.into_inner()
				.enqueued
		);
		assert_eq!(fx.delivery(&key).await.expect("queued"), ("payout_outcome".to_owned(), fx.email_of(owner).await));
		let payload = fx.payload(&key).await;
		assert_eq!(payload["fund"], "Quy Nhon Fund", "the fund travels verbatim");
		assert_eq!(payload["proposed"]["management_bps"], 250, "numbers travel as numbers; the percentage is made at render");
		assert_eq!(payload["current"]["management_bps"], 200);
		assert_eq!(payload["network"], "", "the rail pair stays empty");
		assert_eq!(payload["tier"], "", "and so does the payment tuple, which is how the dispatcher tells the three apart");
	}

	// A fund that charged nothing yet is a real current state, not a missing field.
	let mut first_terms = fee_policy_outcome(owner, GovernanceMailKind::PayoutOutcome);
	first_terms.payout_outcome.as_mut().unwrap().current = None;
	let key = first_terms.dedupe_key.clone();
	assert!(
		fx.relay()
			.send_governance_mail(relayed(first_terms))
			.await
			.expect("no current terms is allowed")
			.into_inner()
			.enqueued
	);
	assert!(fx.payload(&key).await["current"].is_null());

	// A bare `http` is a word, not a link, in a fund's name — the rule the fee mails share.
	let mut slug = fee_policy_outcome(owner, GovernanceMailKind::PayoutOutcome);
	slug.payout_outcome.as_mut().unwrap().fund = "httpfund".into();
	let key = slug.dedupe_key.clone();
	assert!(fx.relay().send_governance_mail(relayed(slug)).await.expect("a slug with http in it").into_inner().enqueued);
	assert_eq!(fx.payload(&key).await["fund"], "httpfund");

	let investor = fx.user().await;
	let err = fx
		.relay()
		.send_governance_mail(relayed(fee_policy_outcome(investor, GovernanceMailKind::PayoutOutcome)))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "still a consilium mail: {err}");

	let mutate = |edit: &dyn Fn(&mut PayoutOutcomeMail)| {
		let mut request = fee_policy_outcome(owner, GovernanceMailKind::PayoutOutcome);
		edit(request.payout_outcome.as_mut().unwrap());
		request
	};
	for (request, why) in [
		(mutate(&|m| m.network = "TRON".into()), "a rail on fee terms"),
		(mutate(&|m| m.address = "TJRabc".into()), "an address on fee terms"),
		(mutate(&|m| m.source = "treasury".into()), "a payment source on fee terms"),
		(mutate(&|m| m.destination = "pool".into()), "a payment destination on fee terms"),
		(mutate(&|m| m.tier = "service".into()), "a payment tier on fee terms"),
		(mutate(&|m| m.proposed = None), "a fund with no proposed terms"),
		(mutate(&|m| m.fund = String::new()), "proposed terms for no fund"),
		(
			mutate(&|m| {
				m.fund = String::new();
				m.proposed = None;
			}),
			"current terms alone name no subject whole",
		),
		(mutate(&|m| m.fund = "   ".into()), "a fund that says nothing"),
		(mutate(&|m| m.fund = "http://x".into()), "a linkable fund"),
		(mutate(&|m| m.fund = "www.x".into()), "a host for a fund"),
		(mutate(&|m| m.fund = "QN\nAmount: 0".into()), "a forged line in the fund"),
		(mutate(&|m| m.proposed.as_mut().unwrap().basis = "aum".into()), "an unknown basis"),
		(mutate(&|m| m.proposed.as_mut().unwrap().management_bps = 10_001), "a management fee over 100%"),
		(
			mutate(&|m| m.current.as_mut().unwrap().performance_bps = 10_001),
			"an impossible CURRENT fee is a lie about today",
		),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}
}

/// The consent's in-app trace. Written for a subject who follows NOTHING — there is no
/// topic every user follows by default, so an opt-in emit would reach almost nobody — and
/// it carries neither the link nor the code, which exist in the mail and nowhere else.
#[tokio::test]
async fn a_payment_consent_leaves_a_trace_in_the_subjects_inbox() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let request = consent(investor, investor);
	let key = request.dedupe_key.clone();
	assert!(fx.relay().send_governance_mail(relayed(request.clone())).await.expect("first").into_inner().enqueued);
	assert_eq!(fx.followed_topics(investor).await, 0, "the subject never opened their notification settings");

	let inbox = fx.inbox(investor).await;
	assert_eq!(inbox.len(), 1, "one entry, regardless of subscriptions: {inbox:?}");
	let (topic, kind, title, body) = &inbox[0];
	assert_eq!((topic.as_str(), kind.as_str()), ("account:money-movement", "payment_consent"));
	assert_eq!(title, "A payment needs your consent");
	for fact in ["ops@evinvest.ltd", "1 200.00 USDT"] {
		assert!(body.contains(fact), "the entry states who is asking and how much: {fact}");
	}
	assert!(!body.contains("483012") && !body.contains("/cabinet/payment-consent/"), "no secret and no link in the inbox");
	for foreign in ["Scheduled quarterly distribution", "Quy Nhon Fund — distributions", "Your bank account ••4417"] {
		assert!(!body.contains(foreign), "the money plane's free text is not shown where it cannot be attributed: {foreign}");
	}
	assert_eq!(
		fx.inbox_keys(investor).await,
		vec![format!("governance:{key}")],
		"the inbox key is namespaced away from this plane's own emitters"
	);

	// The money plane retries. The mail is deduped, and so is the trace.
	assert!(!fx.relay().send_governance_mail(relayed(request)).await.expect("retry").into_inner().enqueued);
	assert_eq!(fx.inbox(investor).await.len(), 1, "a retry adds nothing");
	assert_eq!(fx.delivery(&key).await.map(|(kind, _)| kind).as_deref(), Some("payment_consent"));

	// A refused consent — addressed to somebody other than the subject — leaves no trace
	// on either side.
	let stranger = fx.user().await;
	fx.relay().send_governance_mail(relayed(consent(stranger, investor))).await.unwrap_err();
	assert!(fx.inbox(stranger).await.is_empty(), "a refused mail must not leave an inbox entry either");
}

/// One trusted caller, many possible recipients: what the ceiling bounds is how much
/// branded security mail a compromised money plane can aim at ONE person.
#[tokio::test]
async fn a_recipient_is_rate_limited_across_kinds() {
	let Some(fx) = setup().await else {
		return;
	};
	let relay = fx.relay_allowing(2);
	let owner = fx.owner().await;
	let first = payout(owner);
	assert!(relay.send_governance_mail(relayed(first.clone())).await.expect("within budget").into_inner().enqueued);

	// Neither a retry the dedupe key turns into a no-op nor a refused call spends the
	// budget: the money plane's worker retries every 30s and gives a mail up after ten
	// attempts, so a budget drained by retries would lose an approval mail for good.
	for _ in 0..5 {
		assert!(!relay.send_governance_mail(relayed(first.clone())).await.expect("a retry").into_inner().enqueued);
	}
	let mut refused = payout(owner);
	refused.payout_approval.as_mut().unwrap().approval_url = "https://attacker.example/".into();
	assert_eq!(relay.send_governance_mail(relayed(refused)).await.unwrap_err().code(), Code::InvalidArgument);

	assert!(
		relay
			.send_governance_mail(relayed(payout(owner)))
			.await
			.expect("the second NEW mail still fits")
			.into_inner()
			.enqueued
	);
	let err = relay.send_governance_mail(relayed(payment_approval(owner))).await.unwrap_err();
	assert_eq!(err.code(), Code::ResourceExhausted, "the third new mail to the same person in the window: {err}");
	// Over budget, even a retry of a mail already queued is refused — the budget is
	// peeked before the queue is consulted. Transient: the worker retries, the window
	// turns, and the retry is then answered `enqueued: false` without spending anything.
	assert_eq!(relay.send_governance_mail(relayed(first)).await.unwrap_err().code(), Code::ResourceExhausted);

	// Another recipient has their own bucket.
	let other = fx.owner().await;
	assert!(relay.send_governance_mail(relayed(payout(other))).await.expect("a different person").into_inner().enqueued);
}

/// `initiator_email` is rendered as "Requested by" and woven into our sentences, so it
/// must be one address and nothing that reads as a sentence of ours.
#[tokio::test]
async fn the_initiator_must_be_an_address() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let investor = fx.user().await;
	let mut sentence = payout(owner);
	sentence.payout_approval.as_mut().unwrap().initiator_email = "EV Investment security team".into();
	let mut trailing = payment_approval(owner);
	trailing.payment_approval.as_mut().unwrap().initiator_email = "ops@evinvest.ltd please approve".into();
	let mut no_at = consent(investor, investor);
	no_at.payment_consent.as_mut().unwrap().initiator_email = "no-at-sign".into();
	for (request, why) in [
		(sentence, "a payout approval with a sentence for an initiator"),
		(trailing, "a payment approval with words after the address"),
		(no_at, "a consent with no `@` at all"),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}
}

/// The inbox repeats the amount in the platform's own sentence, where nothing marks it
/// as the money plane's text; and its key has to leave room for the namespace prefix.
#[tokio::test]
async fn a_consent_inbox_entry_cannot_carry_a_link_or_squat_a_key() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	for (amount, why) in [
		("see http://evil.example", "a link"),
		("1 USDT (www.evil.example)", "a bare host"),
		("1 USDT HTTPS://x", "case does not help"),
		// The amount keeps the coarse rule the fund line does not: an amount has no
		// business saying `http` at all, scheme or no scheme.
		("1 USDT http evil.example", "the bare word with no scheme"),
	] {
		let mut request = consent(investor, investor);
		request.payment_consent.as_mut().unwrap().amount = amount.into();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
	}
	let mut long_key = consent(investor, investor);
	long_key.dedupe_key = "k".repeat(128);
	let err = fx.relay().send_governance_mail(relayed(long_key)).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "a key the prefix would push past the column limit: {err}");
	assert!(fx.inbox(investor).await.is_empty(), "nothing was queued, so nothing was traced");
}

/// The house terms, as the money plane would state them.
fn house_terms() -> FeeTerms {
	FeeTerms {
		management_bps: 200,
		performance_bps: 2_000,
		hurdle_bps: 0,
		basis: "invested_capital".into(),
		crystallization: "annual".into(),
	}
}

/// A dearer set: quarterly crystallization on a market-value basis with a hurdle.
fn proposed_terms() -> FeeTerms {
	FeeTerms {
		management_bps: 250,
		performance_bps: 2_000,
		hurdle_bps: 800,
		basis: "market_value".into(),
		crystallization: "quarterly".into(),
	}
}

/// A well-formed fee policy approval — the consilium's question about a fund's price.
fn fee_policy_approval(addressee: UserId) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: GovernanceMailKind::FeePolicyApproval as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("fee-policy-approval:{}", Uuid::new_v4()),
		payout_approval: None,
		payout_outcome: None,
		payment_consent: None,
		payment_approval: None,
		fee_policy_approval: Some(FeePolicyApprovalMail {
			consilium_id: "c-12".into(),
			initiator_email: "ops@evinvest.ltd".into(),
			fund: "Quy Nhon Fund".into(),
			current: Some(house_terms()),
			proposed: Some(proposed_terms()),
			reason: "Align with the revised prospectus".into(),
			payload_hash: "9f2c1ab4de5607891122334455667788".into(),
			threshold: 2,
			owner_count: 3,
			expires_at: T0 + 86_400,
			approval_url: format!("{RELAY_ORIGIN}/cabinet/fee-policy-approval/tok"),
			code: "483012".into(),
		}),
		fee_policy_notice: None,
	}
}

/// A well-formed notice. `addressee` and `subject` are separate for the reason
/// `consent`'s are: the rule under test is that they must be one person.
fn fee_policy_notice(addressee: UserId, subject: UserId) -> SendGovernanceMailRequest {
	SendGovernanceMailRequest {
		kind: GovernanceMailKind::FeePolicyNotice as i32,
		user_id: addressee.to_string(),
		dedupe_key: format!("fee-policy-notice:{}", Uuid::new_v4()),
		payout_approval: None,
		payout_outcome: None,
		payment_consent: None,
		payment_approval: None,
		fee_policy_approval: None,
		fee_policy_notice: Some(FeePolicyNoticeMail {
			subject_user_id: subject.to_string(),
			fund: "Quy Nhon Fund".into(),
			current: Some(house_terms()),
			proposed: Some(proposed_terms()),
			effective_at: T0 + 30 * 86_400,
			link: "/funds/quy-nhon/fees".into(),
		}),
	}
}

/// A fee change is a consilium question, so it is addressed under the payment approval's
/// rule: a seated owner at a verified address, and nobody else. The code rides the
/// payload like a payment approval's, to be cleared once the mail is sent.
#[tokio::test]
async fn a_fee_policy_approval_reaches_only_a_verified_fund_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let err = fx.relay().send_governance_mail(relayed(fee_policy_approval(investor))).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "a non-owner has no standing in a fee consilium: {err}");

	let unverified = fx.unverified_owner().await;
	let err = fx.relay().send_governance_mail(relayed(fee_policy_approval(unverified))).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "an address nobody proved holds the code that arms the vote: {err}");

	let owner = fx.owner().await;
	let request = fee_policy_approval(owner);
	let key = request.dedupe_key.clone();
	assert!(
		fx.relay()
			.send_governance_mail(relayed(request))
			.await
			.expect("a seated owner may be asked")
			.into_inner()
			.enqueued
	);
	assert_eq!(fx.delivery(&key).await.expect("queued"), ("fee_policy_approval".to_owned(), fx.email_of(owner).await));
	let payload = fx.payload(&key).await;
	assert_eq!(payload["fund"], "Quy Nhon Fund");
	assert_eq!(payload["current"]["management_bps"], 200);
	assert_eq!(payload["proposed"]["management_bps"], 250);
	assert_eq!(payload["proposed"]["crystallization"], "quarterly");
	assert_eq!(payload["code"], "483012", "the code travels with the row until the mail is sent");
	assert_eq!(payload["threshold"], 2, "the bar the owner is measured against travels with the mail");
	assert!(
		fx.inbox(owner).await.is_empty(),
		"an owner's approval leaves no inbox trace — the consilium surface is where they find it"
	);

	// A fund that charged nothing yet is a real current state, not a missing field.
	let mut first_terms = fee_policy_approval(owner);
	first_terms.fee_policy_approval.as_mut().unwrap().current = None;
	let key = first_terms.dedupe_key.clone();
	assert!(
		fx.relay()
			.send_governance_mail(relayed(first_terms))
			.await
			.expect("no current terms is allowed")
			.into_inner()
			.enqueued
	);
	assert!(fx.payload(&key).await["current"].is_null());
}

/// The terms are closed vocabularies and bounded numbers, because every one of them is
/// rendered at an owner deciding a price; the rest are the payment approval's rules.
#[tokio::test]
async fn a_fee_policy_approval_refuses_terms_it_cannot_render() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let mutate = |edit: &dyn Fn(&mut FeePolicyApprovalMail)| {
		let mut request = fee_policy_approval(owner);
		edit(request.fee_policy_approval.as_mut().unwrap());
		request
	};
	for (request, why) in [
		(mutate(&|m| m.proposed = None), "no proposed terms"),
		(mutate(&|m| m.proposed.as_mut().unwrap().management_bps = 10_001), "a management fee over 100%"),
		(mutate(&|m| m.proposed.as_mut().unwrap().hurdle_bps = 20_000), "a hurdle over 100%"),
		(
			mutate(&|m| m.current.as_mut().unwrap().performance_bps = 10_001),
			"an impossible CURRENT fee is a lie about today",
		),
		(mutate(&|m| m.proposed.as_mut().unwrap().basis = "aum".into()), "an unknown basis"),
		(mutate(&|m| m.proposed.as_mut().unwrap().crystallization = "weekly".into()), "an unknown crystallization"),
		(mutate(&|m| m.proposed.as_mut().unwrap().basis = "Market_Value".into()), "the money plane's own casing is lower"),
		(mutate(&|m| m.fund = "   ".into()), "no fund at all"),
		(mutate(&|m| m.fund = "QN\nAmount: 0".into()), "a forged line in the fund"),
		(mutate(&|m| m.reason = String::new()), "no reason"),
		(mutate(&|m| m.approval_url = "https://attacker.example/approve/tok".into()), "an off-origin link"),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}

	let mut without_body = fee_policy_approval(owner);
	without_body.fee_policy_approval = None;
	let err = fx.relay().send_governance_mail(relayed(without_body)).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "the kind names a payload it did not carry: {err}");
}

/// A notice is addressed by identity, like a consent: it reaches the one investor the
/// payload names, at an address they have proved, and nobody else — an owner seat buys
/// nothing here.
#[tokio::test]
async fn a_fee_policy_notice_reaches_its_subject_and_nobody_else() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let stranger = fx.user().await;
	let owner = fx.owner().await;
	for (request, why) in [
		(fee_policy_notice(stranger, investor), "another user"),
		(fee_policy_notice(owner, investor), "a seated owner who is not the subject"),
		(fee_policy_notice(fx.unverified_user().await, investor), "an unverified stranger"),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::FailedPrecondition, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}
	let unverified = fx.unverified_user().await;
	let err = fx.relay().send_governance_mail(relayed(fee_policy_notice(unverified, unverified))).await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "the subject themselves, at an address nobody proved: {err}");

	let request = fee_policy_notice(investor, investor);
	let key = request.dedupe_key.clone();
	assert!(fx.relay().send_governance_mail(relayed(request)).await.expect("the subject").into_inner().enqueued);
	assert_eq!(fx.delivery(&key).await.expect("queued"), ("fee_policy_notice".to_owned(), fx.email_of(investor).await));
	let payload = fx.payload(&key).await;
	assert_eq!(payload["link"], "/funds/quy-nhon/fees", "the path is stored relative; the dispatcher hangs it off the cabinet");
	assert!(payload.get("code").is_none(), "a notice carries no secret");
	assert_eq!(payload["proposed"]["hurdle_bps"], 800);
}

/// The notice's in-app trace, under the consent's rules: written whether or not the
/// investor follows anything, deduped with the mail, namespaced, and carrying the fund
/// and the two headline percentages in the platform's own words — no link.
#[tokio::test]
async fn a_fee_policy_notice_leaves_a_trace_in_the_investors_inbox() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let request = fee_policy_notice(investor, investor);
	let key = request.dedupe_key.clone();
	assert!(fx.relay().send_governance_mail(relayed(request.clone())).await.expect("first").into_inner().enqueued);
	assert_eq!(fx.followed_topics(investor).await, 0, "the investor never opened their notification settings");

	let inbox = fx.inbox(investor).await;
	assert_eq!(inbox.len(), 1, "one entry, regardless of subscriptions: {inbox:?}");
	let (topic, kind, title, body) = &inbox[0];
	assert_eq!((topic.as_str(), kind.as_str()), ("account:money-movement", "fee_policy_notice"));
	assert!(title.contains("Quy Nhon Fund"), "the title names the fund: {title}");
	for fact in ["2% → 2.5%", "20%"] {
		assert!(body.contains(fact), "the entry states the headline change: {fact} in {body}");
	}
	assert!(!body.contains("/funds/quy-nhon/fees"), "no link in the inbox");
	assert_eq!(fx.inbox_keys(investor).await, vec![format!("governance:{key}")]);

	assert!(!fx.relay().send_governance_mail(relayed(request)).await.expect("retry").into_inner().enqueued);
	assert_eq!(fx.inbox(investor).await.len(), 1, "a retry adds nothing");

	// A refused notice leaves no trace on either side.
	let stranger = fx.user().await;
	fx.relay().send_governance_mail(relayed(fee_policy_notice(stranger, investor))).await.unwrap_err();
	assert!(fx.inbox(stranger).await.is_empty());
}

/// The one emailed link the money plane spells no host for: a path under the cabinet,
/// and nothing a browser would read as leaving it.
#[tokio::test]
async fn a_fee_policy_notice_link_is_a_cabinet_path_and_nothing_else() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let mutate = |edit: &dyn Fn(&mut FeePolicyNoticeMail)| {
		let mut request = fee_policy_notice(investor, investor);
		edit(request.fee_policy_notice.as_mut().unwrap());
		request
	};
	for (request, why) in [
		(mutate(&|m| m.link = "https://attacker.example/".into()), "an absolute URL"),
		(mutate(&|m| m.link = "//attacker.example/".into()), "a protocol-relative URL"),
		(mutate(&|m| m.link = "/\\attacker.example/".into()), "what a browser turns into one"),
		(mutate(&|m| m.link = "funds/fees".into()), "a path with no leading slash"),
		(mutate(&|m| m.link = "/funds/fees https://attacker.example/".into()), "a path that breaks the line"),
		(mutate(&|m| m.link = "/funds/fées".into()), "non-ASCII"),
		(
			mutate(&|m| m.fund = "Quy Nhon Fund — see http://evil.example".into()),
			"a link smuggled into the one field the inbox repeats",
		),
		(mutate(&|m| m.fund = "http://x".into()), "a fund that is nothing but a link"),
		(mutate(&|m| m.fund = "www.x".into()), "a fund that is a bare host"),
		(mutate(&|m| m.fund = "WWW.X".into()), "case does not help"),
		(mutate(&|m| m.proposed = None), "no proposed terms"),
		(mutate(&|m| m.proposed.as_mut().unwrap().basis = "aum".into()), "an unknown basis"),
	] {
		let key = request.dedupe_key.clone();
		let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "{why}: {err}");
		assert!(fx.delivery(&key).await.is_none(), "{why}: nothing may be queued");
	}
	assert!(fx.inbox(investor).await.is_empty(), "nothing was queued, so nothing was traced");

	let front_page = mutate(&|m| m.link = String::new());
	assert!(
		fx.relay()
			.send_governance_mail(relayed(front_page))
			.await
			.expect("an empty path means the cabinet itself")
			.into_inner()
			.enqueued
	);
}

/// The fund line is a product slug, and `httpfund` is a legal one (banking#265): the
/// coarse "no `http` anywhere" rule that fits an amount made every fee mail about such a
/// fund undeliverable, so a tightening on it could never promote. What a client actually
/// linkifies — a scheme or a `www.` host — is refused, in the notice and the approval
/// alike, so the money plane learns one rule for the field.
#[tokio::test]
async fn a_fund_named_with_a_bare_http_still_gets_its_fee_mail() {
	let Some(fx) = setup().await else {
		return;
	};
	let investor = fx.user().await;
	let owner = fx.owner().await;
	let notice = |fund: &str| {
		let mut request = fee_policy_notice(investor, investor);
		request.fee_policy_notice.as_mut().unwrap().fund = fund.into();
		request
	};
	let approval = |fund: &str| {
		let mut request = fee_policy_approval(owner);
		request.fee_policy_approval.as_mut().unwrap().fund = fund.into();
		request
	};

	for fund in ["httpfund", "lighthttp-arb"] {
		for (request, kind) in [(notice(fund), "fee_policy_notice"), (approval(fund), "fee_policy_approval")] {
			let key = request.dedupe_key.clone();
			assert!(
				fx.relay()
					.send_governance_mail(relayed(request))
					.await
					.unwrap_or_else(|err| panic!("{kind} about {fund}: {err}"))
					.into_inner()
					.enqueued,
				"{kind} about {fund} is queued"
			);
			assert_eq!(fx.delivery(&key).await.map(|(k, _)| k).as_deref(), Some(kind));
			assert_eq!(fx.payload(&key).await["fund"], fund, "the slug travels verbatim");
		}
	}
	let traced = fx.inbox(investor).await;
	assert_eq!(traced.len(), 2, "each notice is traced in the inbox");
	assert!(traced.iter().any(|(_, _, title, _)| title.contains("httpfund")), "and names the fund: {traced:?}");

	for fund in ["http://x", "www.x", "WWW.X"] {
		for (request, kind) in [(notice(fund), "fee_policy_notice"), (approval(fund), "fee_policy_approval")] {
			let key = request.dedupe_key.clone();
			let err = fx.relay().send_governance_mail(relayed(request)).await.unwrap_err();
			assert_eq!(err.code(), Code::InvalidArgument, "{kind} with a fund of {fund:?}: {err}");
			assert!(fx.delivery(&key).await.is_none(), "{kind} with a fund of {fund:?}: nothing may be queued");
		}
	}
	assert_eq!(fx.inbox(investor).await.len(), 2, "a refused notice leaves no trace");
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
				reason: String::new(),
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
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(stripped.code(), Code::FailedPrecondition, "{stripped}");
	assert_eq!(fx.role_of(owners[1]).await, Role::Owner, "the seat stays");

	// `admin` joined the refusal list, in the GRANTING direction only: the seat carries
	// every identity mutation except role granting, so an operator who can appoint
	// operators can appoint accomplices.
	let appointed = directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "admin".into(),
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(appointed.code(), Code::FailedPrecondition, "{appointed}");
	assert!(appointed.message().contains("OpenAdminAdmission"), "the refusal points at the consilium: {appointed}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor);

	// Every OTHER role change is untouched — this closes ownership and appointment, not
	// the console.
	directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "operator".into(),
				reason: String::new(),
			},
		))
		.await
		.expect("an ordinary role change still works");
	assert_eq!(fx.role_of(candidate).await, Role::Operator);
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
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("OpenOwnerAdmission"), "the refusal points at the consilium: {err}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor, "an empty registry is not a licence to seat anyone");

	// The rest of the console still works on that same authority — emergency access
	// grants `operator`, it just never grants a seat. It does not grant `admin` either
	// any more: appointing one is a proposal, and on an empty registry there is nobody to
	// propose to, which is the correct answer rather than a gap.
	directory
		.set_role(as_user(
			operator,
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "operator".into(),
				reason: String::new(),
			},
		))
		.await
		.expect("an ordinary role change is exactly what emergency access is for");
	assert_eq!(fx.role_of(candidate).await, Role::Operator);
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
			reason: String::new(),
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
