//! The one rule every non-password sign-in lands in (`UserDirectoryRepository::resolve`),
//! and the column invariants that back it: one verified mailbox per account, no KYC level
//! on an unverified one, and the rollout bridge for the binary that still provisions by
//! Google `sub`.

mod common;

use concierge::{
	infrastructure::{
		db,
		users::{AdminAction, PgUsers},
	},
	ports::UserDirectoryRepository,
};
use domain::{
	auth::{ProvenIdentity, Provider},
	error::DomainError,
	users::{Email, UserId},
};
use sqlx::PgPool;
use uuid::Uuid;

struct Fx {
	users: PgUsers,
	pool: PgPool,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some(Fx {
		users: PgUsers::new(pool.clone()),
		pool,
	})
}

macro_rules! fixture {
	() => {
		match setup().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

fn address(tag: &str) -> String {
	format!("{tag}-{}@example.com", Uuid::new_v4().simple())
}

fn subject() -> String {
	format!("sub-{}", Uuid::new_v4())
}

fn code_login(email: &str) -> ProvenIdentity {
	ProvenIdentity {
		provider: None,
		email: Email::parse(email).unwrap(),
		email_proven: true,
	}
}

fn github(subject: &str, email: &str) -> ProvenIdentity {
	ProvenIdentity {
		provider: Some((Provider::Github, subject.to_owned())),
		email: Email::parse(email).unwrap(),
		email_proven: true,
	}
}

impl Fx {
	/// An account registered by email + password and never verified — the squatter's shape.
	async fn password_account(&self, email: &str) -> UserId {
		let id = UserId::new();
		sqlx::query("INSERT INTO users (id, auth_subject, email, email_verified) VALUES ($1, $1::text, $2, FALSE)")
			.bind(id.raw())
			.bind(email)
			.execute(&self.pool)
			.await
			.unwrap();
		sqlx::query("INSERT INTO password_credentials (user_id, phc, updated_at) VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', 0)")
			.bind(id.raw())
			.execute(&self.pool)
			.await
			.unwrap();
		id
	}

	async fn has_password(&self, id: UserId) -> bool {
		sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM password_credentials WHERE user_id = $1)")
			.bind(id.raw())
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	async fn identities(&self, id: UserId) -> Vec<(String, String)> {
		sqlx::query_as("SELECT provider, subject FROM user_identities WHERE user_id = $1 ORDER BY provider")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.unwrap()
	}
}

#[tokio::test]
async fn a_linked_subject_opens_its_account_whatever_the_address_says() {
	let fx = fixture!();
	let sub = subject();
	let first = fx.users.resolve(common::google_as(&sub, &address("one"), true), 1).await.unwrap();
	let moved = address("moved");
	let again = fx.users.resolve(common::google_as(&sub, &moved, true), 2).await.unwrap();
	assert_eq!(first.id(), again.id());
	assert_eq!(again.email().as_str(), moved, "the provider's current address follows");
}

#[tokio::test]
async fn a_provider_address_never_moves_onto_a_mailbox_another_account_proved() {
	let fx = fixture!();
	let taken = address("taken");
	let holder = fx.users.resolve(code_login(&taken), 1).await.unwrap();
	let sub = subject();
	let mine = fx.users.resolve(common::google_as(&sub, &address("mine"), true), 1).await.unwrap();

	let again = fx.users.resolve(common::google_as(&sub, &taken, true), 2).await.unwrap();
	assert_eq!(again.id(), mine.id(), "the subject still opens its own account");
	assert_ne!(again.email().as_str(), taken, "and keeps the address it had");
	assert_ne!(holder.id(), mine.id());
}

#[tokio::test]
async fn a_proven_mailbox_links_a_new_provider_to_the_account_it_is_verified_on() {
	let fx = fixture!();
	let email = address("link");
	let by_code = fx.users.resolve(code_login(&email), 1).await.unwrap();
	assert!(by_code.email_verified(), "a code proves the mailbox it was sent to");

	let sub = subject();
	let by_github = fx.users.resolve(github(&sub, &email), 2).await.unwrap();
	assert_eq!(by_github.id(), by_code.id());
	assert_eq!(fx.identities(by_code.id()).await, vec![("github".to_owned(), sub)]);
}

#[tokio::test]
async fn an_unproven_mailbox_links_to_nothing() {
	let fx = fixture!();
	let email = address("unproven");
	let owner = fx.users.resolve(code_login(&email), 1).await.unwrap();
	let stranger = fx.users.resolve(common::google_as(&subject(), &email, false), 2).await.unwrap();
	assert_ne!(stranger.id(), owner.id(), "an address the provider did not verify proves nothing");
	assert!(!stranger.email_verified());
}

/// The pre-hijack attack: somebody registers the victim's address with a password and
/// waits. Proving the mailbox takes the account back from them.
#[tokio::test]
async fn proving_a_mailbox_takes_over_an_unverified_password_registration() {
	let fx = fixture!();
	let email = address("squat");
	let squatted = fx.password_account(&email).await;
	let before = fx.users.find_by_id(squatted).await.unwrap().unwrap();

	let sub = subject();
	let owner = fx.users.resolve(common::google_as(&sub, &email, true), 1).await.unwrap();
	assert_eq!(owner.id(), squatted, "the mailbox's owner gets the account");
	assert!(owner.email_verified());
	assert_eq!(owner.token_version(), before.token_version() + 1, "every session the squatter held ends");
	assert!(!fx.has_password(squatted).await, "and the squatter's password goes with them");
	assert_eq!(fx.identities(squatted).await, vec![("google".to_owned(), sub)]);

	let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_action WHERE subject_user_id = $1 AND action = 'taken_over_by_mailbox'")
		.bind(squatted.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(audited, 1);
}

#[tokio::test]
async fn nothing_known_makes_a_new_account_with_its_own_subject_and_a_handle() {
	let fx = fixture!();
	let local = format!("fresh{}", Uuid::new_v4().simple());
	let email = format!("{local}@example.com");
	let user = fx.users.resolve(code_login(&email), 1).await.unwrap();
	assert_eq!(user.auth_subject().as_str(), user.id().to_string());
	assert_eq!(user.username().map(|u| u.as_str()), Some(local.as_str()), "the local part, nobody holding it");
	assert!(fx.identities(user.id()).await.is_empty(), "a code links no provider");

	let twin = fx.users.resolve(common::google_as(&subject(), &format!("{local}@elsewhere.example"), false), 2).await.unwrap();
	assert_eq!(twin.username().map(|u| u.as_str()), Some(format!("{local}@elsewhere.example").as_str()), "then the whole address");
}

#[tokio::test]
async fn one_verified_mailbox_names_one_account_at_the_column() {
	let fx = fixture!();
	let email = address("unique");
	fx.users.resolve(code_login(&email), 1).await.unwrap();
	let other = fx.users.resolve(common::google_as(&subject(), &email, false), 2).await.unwrap();
	let err = sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
		.bind(other.id().raw())
		.execute(&fx.pool)
		.await
		.unwrap_err();
	assert!(err.to_string().contains("users_verified_email_idx"), "{err}");
}

#[tokio::test]
async fn an_unverified_mailbox_holds_no_kyc_level() {
	let fx = fixture!();
	let user = fx.users.resolve(common::google("kyc-unverified", false), 1).await.unwrap();

	let err = fx.users.set_kyc_level(user.id(), 1, &AdminAction::system("kyc_level_set"), 1).await.unwrap_err();
	assert!(matches!(err, DomainError::Precondition(_)), "the aggregate refuses: {err}");

	let err = sqlx::query("UPDATE users SET kyc_level = 1 WHERE id = $1")
		.bind(user.id().raw())
		.execute(&fx.pool)
		.await
		.unwrap_err();
	assert!(err.to_string().contains("users_kyc_needs_verified_email"), "and so does the column: {err}");
}

/// The binary before this one provisions by `users.auth_subject = <google sub>`. While
/// both run, a sub this one already linked must not become a second account.
#[tokio::test]
async fn the_previous_binary_cannot_duplicate_a_linked_google_account() {
	let fx = fixture!();
	let sub = subject();
	fx.users.resolve(common::google_as(&sub, &address("linked"), true), 1).await.unwrap();

	let old_insert = sqlx::query("INSERT INTO users (id, auth_subject, email, email_verified) VALUES ($1, $2, $3, FALSE) ON CONFLICT (auth_subject) DO NOTHING")
		.bind(Uuid::new_v4())
		.bind(&sub)
		.bind(address("dup"))
		.execute(&fx.pool)
		.await;
	assert!(old_insert.is_err(), "the mirror trigger refuses a sub that is already linked");

	let fresh = subject();
	let id = Uuid::new_v4();
	sqlx::query("INSERT INTO users (id, auth_subject, email, email_verified) VALUES ($1, $2, $3, FALSE)")
		.bind(id)
		.bind(&fresh)
		.bind(address("old"))
		.execute(&fx.pool)
		.await
		.expect("an unlinked sub provisions as before");
	let reopened = fx.users.resolve(common::google_as(&fresh, &address("old-again"), false), 2).await.unwrap();
	assert_eq!(reopened.id().raw(), id, "and this binary finds it by the mirrored identity");
}
