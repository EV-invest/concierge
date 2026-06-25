use sqlx::postgres::{PgPool, PgPoolOptions};

/// Open a Postgres pool with an explicit `max_connections`, sourced from config so a
/// burst of read traffic and the bridge's outbox reads can't exhaust each other. The
/// pool is `Clone` and shared by the directory repository and the bridge outbox.
/// sqlx already applies sane `acquire_timeout`/`idle_timeout`/`max_lifetime` defaults,
/// so size is the only knob.
pub async fn connect_sized(database_url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
	let pool = PgPoolOptions::new().max_connections(max_connections).connect(database_url).await?;
	Ok(pool)
}

/// Apply pending control-plane migrations (embedded from `runner/migrations` at build
/// time) on startup. Idempotent. Author new migration FILES with the sqlx CLI
/// (`sqlx migrate add --source runner/migrations --sequential <name>`), never by hand;
/// the embedded runner here is interoperable with the CLI (same `_sqlx_migrations` table).
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
	sqlx::migrate!().run(pool).await?;
	Ok(())
}
