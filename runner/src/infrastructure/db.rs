use color_eyre::eyre::{Result, ensure};
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Open a Postgres pool with an explicit `max_connections`, sourced from config so a
/// burst of read traffic and the bridge's outbox reads can't exhaust each other. The
/// pool is `Clone` and shared by the directory repository and the bridge outbox.
/// sqlx already applies sane `acquire_timeout`/`idle_timeout`/`max_lifetime` defaults,
/// so size is the only knob.
pub async fn connect_sized(database_url: &str, max_connections: u32) -> Result<PgPool> {
	// sqlx 0.9 eagerly builds an ArrayQueue of this capacity, and crossbeam-queue
	// panics on 0 — fail as a clean config error instead.
	ensure!(
		max_connections >= 1,
		"database pool max_connections must be at least 1 (db_max_connections / DB_MAX_CONNECTIONS set to 0?)"
	);
	let pool = PgPoolOptions::new().max_connections(max_connections).connect(database_url).await?;
	Ok(pool)
}

/// Apply pending control-plane migrations (embedded from `runner/migrations` at build
/// time) on startup. Idempotent. Author new migration FILES with the sqlx CLI
/// (`sqlx migrate add --source runner/migrations --sequential <name>`), never by hand;
/// the embedded runner here is interoperable with the CLI (same `_sqlx_migrations` table).
pub async fn migrate(pool: &PgPool) -> Result<()> {
	sqlx::migrate!().run(pool).await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	// Bogus URLs keep both tests I/O-free: the guard fires before any connection
	// attempt, and an unparseable URL fails before dialing.
	#[tokio::test]
	async fn zero_max_connections_is_a_clean_error() {
		let err = connect_sized("postgres://invalid", 0).await.expect_err("0 connections must be rejected");
		assert!(err.to_string().contains("max_connections"), "unexpected error: {err}");
	}

	#[tokio::test]
	async fn one_max_connection_passes_the_guard() {
		let err = connect_sized("not-a-url", 1).await.expect_err("bogus URL must fail past the guard");
		assert!(!err.to_string().contains("max_connections"), "guard must not reject 1: {err}");
	}
}
