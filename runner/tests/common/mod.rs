//! Shared preconditions for the suites that own the owner roster.

/// The environment marker that says "this database is disposable".
pub const TEST_DB_MARKER: &str = "CONCIERGE_TEST_DB";

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
