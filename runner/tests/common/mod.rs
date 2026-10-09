//! Shared preconditions for the integration suites: the disposable-database marker the
//! roster-clearing suites need, and the one decision about a missing database — skip
//! locally, fail under CI.
//!
//! Each integration test is its own crate, so a suite that uses one half of this module
//! compiles the other half unused — hence the blanket allowance.
#![allow(dead_code)]

/// The environment marker that says "this database is disposable".
pub const TEST_DB_MARKER: &str = "CONCIERGE_TEST_DB";

/// True under CI: `CI` is set, non-empty and not `"0"`/`"false"`. GitHub Actions and every
/// other runner this repo could land on export `CI=true`.
fn under_ci() -> bool {
	std::env::var("CI").is_ok_and(|value| !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false"))
}

/// The URL a DB-backed suite should connect to, or `None` when the caller must skip.
///
/// Locally a missing `DATABASE_URL` is a skip — a DB-less `cargo test` still passes, which
/// is what keeps `cargo check` independent of a live database. Under CI it is a panic,
/// because the skip is otherwise INVISIBLE: libtest swallows a passing test's output unless
/// `--nocapture` is given, so a fully skipped suite prints exactly the "N passed" a real run
/// prints and the only tell is the wall time. A green CI job that asserted nothing is the
/// single outcome CI exists to catch, so it is the one place this stops being a courtesy.
///
/// The printed marker stays for the local case: `cargo test -- --nocapture` is how a reader
/// tells a real run from a skipped one without counting milliseconds.
pub fn database_url() -> Option<String> {
	match std::env::var("DATABASE_URL").ok().filter(|value| !value.is_empty()) {
		Some(url) => Some(url),
		None if under_ci() => panic!("CI=true and DATABASE_URL unset: this suite would assert nothing. Point it at a real Postgres, or unset CI to skip locally."),
		None => {
			eprintln!("SKIPPED: DATABASE_URL unset — this test asserted nothing (only visible under --nocapture)");
			None
		}
	}
}

/// Refuse to run a roster-clearing fixture unless the operator has said, separately from
/// `DATABASE_URL`, that the database is throwaway.
///
/// Three suites here run `UPDATE users SET role = 'investor' WHERE role = 'owner'`. They
/// have to: ownership is decided globally from `users.role`, so a test cannot scope
/// itself to its own fixtures the way the profile suites do. Pointed at production, that
/// one statement empties the owner registry — the single state this whole design calls
/// unreachable. It re-opens `OWNER_SUBJECTS` emergency access, it un-latches every
/// running replica's `BreakGlass` on its next restart, and nothing in the plane can put
/// it back: the owner floor forbids dropping below `MIN_OWNERS`, so there is no API that
/// re-seats anyone.
///
/// A `DATABASE_URL` inherited from whatever shell `cargo test` was typed into is not
/// consent. The dev shell sets this marker; a production shell has no reason to.
pub fn assert_disposable_database() {
	assert!(
		std::env::var(TEST_DB_MARKER).is_ok_and(|value| !value.is_empty()),
		"refusing to run: this suite CLEARS the owner registry of whatever DATABASE_URL points at, \
		 and no API can restore it (the owner floor forbids dropping below MIN_OWNERS). \
		 Set {TEST_DB_MARKER}=1 to confirm the database is disposable — the nix dev shell already does."
	);
}

/// A migrated database of its own, for a suite that rewrites state every writer reads
/// (`seat_meanings`). Left behind if the test panics before [`Scratch::drop_database`].
pub struct Scratch {
	pub pool: sqlx::PgPool,
	admin: sqlx::PgPool,
	name: String,
}
impl Scratch {
	pub async fn create(url: &str) -> Self {
		let admin = sqlx::PgPool::connect(url).await.expect("connect to Postgres");
		let name = format!("concierge_scratch_{}", uuid::Uuid::new_v4().simple());
		sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
			.execute(&admin)
			.await
			.expect("create the scratch database");
		let options: sqlx::postgres::PgConnectOptions = url.parse().expect("DATABASE_URL parses");
		let pool = sqlx::PgPool::connect_with(options.database(&name)).await.expect("connect to the scratch database");
		concierge::infrastructure::db::migrate(&pool).await.expect("apply migrations");
		Self { pool, admin, name }
	}

	pub async fn drop_database(self) {
		self.pool.close().await;
		sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {} WITH (FORCE)", self.name)))
			.execute(&self.admin)
			.await
			.expect("drop the scratch database");
	}
}

/// A Google sign-in as `UserDirectoryRepository::resolve` receives it, with a fresh
/// subject and a fresh address: one verified mailbox opens one account, so two fixtures
/// sharing an address would silently be one person. `tag` keeps the address readable.
pub fn google(tag: &str, verified: bool) -> domain::auth::ProvenIdentity {
	google_as(
		&format!("{tag}-{}", uuid::Uuid::new_v4()),
		&format!("{tag}-{}@example.com", uuid::Uuid::new_v4().simple()),
		verified,
	)
}

/// A Google sign-in by a named subject and address — for the tests about what those do.
pub fn google_as(subject: &str, email: &str, verified: bool) -> domain::auth::ProvenIdentity {
	domain::auth::ProvenIdentity {
		provider: Some((domain::auth::Provider::Google, subject.to_owned())),
		email: domain::users::Email::parse(email).expect("a test address parses"),
		email_proven: verified,
	}
}
