//! Real-Postgres coverage for the genesis seeding of the owner registry.
//!
//! Every branch of `concierge::genesis` is asserted here, because each one is a decision
//! about who owns the fund and none of them is reachable again once the first one lands.
//! What only a live server can prove is what matters: the roster check and the seats
//! commit in ONE transaction, a refusal writes nothing at all, and a successful seed
//! leaves a `ROLE_CHANGED` row in `user_outbox` for every founder — the row that mirrors
//! the seat into the money plane.
//!
//! ⚠️ LIKE THE CONSILIUM SUITE, THIS ONE OWNS THE OWNER ROSTER. Genesis is decided
//! against `users.role = 'owner'` globally, so each test takes the SAME session advisory
//! lock `governance.rs` and `authz_gate.rs` use and clears the roster first.

use std::sync::Arc;

use concierge::{
	genesis::{self, GenesisOutcome},
	infrastructure::{db, governance::PgGovernance, users::PgUsers},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::Role,
	users::{AuthSubject, Email, UserId},
};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

/// The key the roster-owning suites serialize on.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"

struct Fixture {
	seeder: Arc<PgGovernance>,
	users: Arc<PgUsers>,
	pool: PgPool,
	/// Holding this connection open holds the advisory lock; dropping it releases.
	_roster_lock: PgConnection,
}

async fn setup() -> Option<Fixture> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
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
		seeder: Arc::new(PgGovernance::new(pool.clone(), "https://example.test/governance/removal".into())),
		users: Arc::new(PgUsers::new(pool.clone())),
		pool,
		_roster_lock: roster_lock,
	})
}

impl Fixture {
	/// A provisioned user holding no seat, with a unique address so the mailbox lookups
	/// below are unambiguous by construction.
	async fn user(&self) -> (UserId, String) {
		let subject = AuthSubject::parse(&format!("genesis-{}", Uuid::new_v4())).unwrap();
		let address = format!("genesis-{}@example.com", Uuid::new_v4());
		let id = self.users.provision(subject, Email::parse(&address).unwrap(), true).await.expect("provision").id();
		(id, address)
	}

	async fn seed(&self, subjects: &[String]) -> GenesisOutcome {
		genesis::seed(self.seeder.as_ref(), subjects).await.expect("the control plane is up")
	}

	async fn role_of(&self, id: UserId) -> Role {
		self.users.find_by_id(id).await.expect("read").expect("user exists").role()
	}

	async fn role_changed_events(&self, id: UserId) -> Vec<String> {
		sqlx::query_scalar::<_, String>("SELECT role FROM user_outbox WHERE user_id = $1 AND kind = 'ROLE_CHANGED' ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the outbox")
	}
}

/// The happy path, and the only one that ever writes. Both entry forms are exercised at
/// once — an operator who already knows one founder's id and only the other two's
/// mailboxes should not have to choose.
#[tokio::test]
async fn a_mixed_roster_is_seated_in_full_and_mirrored_to_the_money_plane() {
	let Some(fx) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let (first, _) = fx.user().await;
	let (second, second_mail) = fx.user().await;
	let (third, third_mail) = fx.user().await;

	// Upper-cased on purpose: the address is normalized by the same parser the directory
	// stores through, so what the operator typed does not have to match byte for byte.
	let outcome = fx.seed(&[first.to_string(), second_mail.to_uppercase(), third_mail.clone()]).await;

	let GenesisOutcome::Seated(resolution) = outcome else {
		panic!("expected a seeded roster, got {outcome:?}");
	};
	assert_eq!(resolution.found.len(), 3, "every entry resolved");
	for id in [first, second, third] {
		assert_eq!(fx.role_of(id).await, Role::Owner, "the seat is persisted");
		assert_eq!(
			fx.role_changed_events(id).await.last().map(String::as_str),
			Some("owner"),
			"the seat must leave the ROLE_CHANGED row the money plane pulls"
		);
	}
}

/// The same person named twice — once by id, once by mailbox — is one seat, and the pair
/// does not fake up the second owner genesis requires.
#[tokio::test]
async fn naming_one_person_twice_counts_once_and_does_not_reach_the_floor() {
	let Some(fx) = setup().await else {
		return;
	};
	let (only, mail) = fx.user().await;

	let outcome = fx.seed(&[only.to_string(), mail]).await;

	let GenesisOutcome::TooFew(resolution) = outcome else {
		panic!("expected a refusal, got {outcome:?}");
	};
	assert_eq!(resolution.found, vec![only], "deduplicated by user id, not by the string that named them");
	assert_eq!(fx.role_of(only).await, Role::Investor, "a refusal writes nothing");
}

/// The intended workflow: the operator fills the list in before anyone has signed in, and
/// genesis simply waits. A mailbox with no row yet is not a misconfiguration.
#[tokio::test]
async fn genesis_waits_for_founders_who_have_not_signed_in_yet() {
	let Some(fx) = setup().await else {
		return;
	};
	let (present, present_mail) = fx.user().await;
	let absent_mail = format!("not-yet-{}@example.com", Uuid::new_v4());

	let outcome = fx.seed(&[present_mail, absent_mail.clone()]).await;

	let GenesisOutcome::TooFew(resolution) = outcome else {
		panic!("expected a refusal, got {outcome:?}");
	};
	assert_eq!(resolution.found, vec![present]);
	assert_eq!(resolution.missing_mailboxes.len(), 1, "the address nobody has signed in with is named, not swallowed");
	assert_eq!(resolution.missing_mailboxes[0].as_str(), absent_mail);
	assert_eq!(fx.role_of(present).await, Role::Investor, "one owner is a dead end, so nobody is seated");
}

/// A user id with no row is a different animal: an id can only have been copied from a
/// row that exists, so this is a typo and it is reported as one.
#[tokio::test]
async fn an_unknown_user_id_is_reported_separately_from_a_waiting_mailbox() {
	let Some(fx) = setup().await else {
		return;
	};
	let (present, _) = fx.user().await;
	let ghost = Uuid::new_v4();

	let outcome = fx.seed(&[present.to_string(), ghost.to_string()]).await;

	let GenesisOutcome::TooFew(resolution) = outcome else {
		panic!("expected a refusal, got {outcome:?}");
	};
	assert_eq!(resolution.missing_ids, vec![UserId::from_raw(ghost)]);
	assert!(resolution.missing_mailboxes.is_empty());
}

/// `users.email` is deliberately not unique, so an address CAN name two people. Seating
/// the wrong one is not a mistake the owner floor lets anyone undo, so the whole roster
/// is refused rather than guessed at.
#[tokio::test]
async fn an_ambiguous_mailbox_seats_nobody() {
	let Some(fx) = setup().await else {
		return;
	};
	let (first, shared) = fx.user().await;
	let (second, _) = fx.user().await;
	let (third, _) = fx.user().await;
	// Only Postgres can produce the collision; the directory always writes a fresh row per
	// auth subject and never checks addresses against each other.
	sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
		.bind(&shared)
		.bind(second.raw())
		.execute(&fx.pool)
		.await
		.expect("collide the two addresses");

	let outcome = fx.seed(&[shared.clone(), third.to_string()]).await;

	let GenesisOutcome::Ambiguous { mailbox, matches } = outcome else {
		panic!("expected an ambiguity refusal, got {outcome:?}");
	};
	assert_eq!(mailbox.as_str(), shared);
	assert_eq!(matches, 2);
	for id in [first, second, third] {
		assert_eq!(fx.role_of(id).await, Role::Investor, "an ambiguous roster seats nobody at all");
	}
}

/// An entry that is neither a UUID nor an address is a typo, and a partially understood
/// roster is not the roster the operator meant. Nothing is looked up and nothing is
/// written.
#[tokio::test]
async fn a_malformed_entry_refuses_the_whole_roster() {
	let Some(fx) = setup().await else {
		return;
	};
	let (first, first_mail) = fx.user().await;
	let (second, second_mail) = fx.user().await;

	let outcome = fx.seed(&[first_mail, second_mail, "oops-no-at-sign".into()]).await;

	assert_eq!(outcome, GenesisOutcome::Malformed { entry: "oops-no-at-sign".into() });
	assert_eq!(fx.role_of(first).await, Role::Investor);
	assert_eq!(fx.role_of(second).await, Role::Investor);
}

/// The permanent end state, and the reason `OWNER_SUBJECTS` is inert after the first
/// success: a populated registry is not re-seeded, and a fourth name appended later buys
/// nothing.
#[tokio::test]
async fn a_populated_registry_is_never_re_seeded() {
	let Some(fx) = setup().await else {
		return;
	};
	let (first, first_mail) = fx.user().await;
	let (second, second_mail) = fx.user().await;
	let (latecomer, latecomer_mail) = fx.user().await;

	let seeded = fx.seed(&[first_mail.clone(), second_mail.clone()]).await;
	assert!(matches!(seeded, GenesisOutcome::Seated(_)), "{seeded:?}");

	// Re-running the SAME list is a no-op, which is what makes the boot-time call safe to
	// repeat on every restart and on every replica.
	let again = fx.seed(&[first_mail.clone(), second_mail.clone()]).await;
	assert_eq!(again, GenesisOutcome::Closed { owners: 2 });

	// And appending a name after the fact grants nothing.
	let extended = fx.seed(&[first_mail, second_mail, latecomer_mail]).await;
	assert_eq!(extended, GenesisOutcome::Closed { owners: 2 });
	assert_eq!(fx.role_of(latecomer).await, Role::Investor, "the list is inert once the fund exists");
	assert_eq!(fx.role_of(first).await, Role::Owner);
	assert_eq!(fx.role_of(second).await, Role::Owner);
}

#[tokio::test]
async fn an_empty_list_does_nothing() {
	let Some(fx) = setup().await else {
		return;
	};
	assert_eq!(fx.seed(&[]).await, GenesisOutcome::Unconfigured);
}
