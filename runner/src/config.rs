use std::{env, net::SocketAddr};

use anyhow::Context;

/// Runner configuration, sourced from environment variables (and `.env` in
/// development via `dotenvy`).
#[derive(Clone, Debug)]
pub struct Config {
	pub database_url: String,
	/// gRPC listener address for the modular-monolith surface (auth + directory +
	/// notification + log + health, all mounted on one server).
	pub bind_addr: SocketAddr,
	/// Max connections for the request-serving Postgres pool (the directory handlers
	/// and the bridge outbox reads). `DB_MAX_CONNECTIONS`; defaults to the sqlx
	/// default (10) — raise it for production.
	pub db_max_connections: u32,
	pub sentry_dsn: Option<String>,
	/// PostHog project key for native product-analytics capture. `None` disables
	/// capture (a silent no-op), so the same code runs unconfigured (local, CI).
	pub posthog_key: Option<String>,
	/// PostHog ingestion host; `None` falls back to the library default.
	pub posthog_host: Option<String>,
	pub app_env: String,
}

impl Config {
	pub fn from_env() -> anyhow::Result<Self> {
		let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
		let bind_addr = env::var("CONCIERGE_BIND")
			.unwrap_or_else(|_| "127.0.0.1:50061".to_string())
			.parse()
			.context("CONCIERGE_BIND must be a valid socket address, e.g. 127.0.0.1:50061")?;
		let db_max_connections = env::var("DB_MAX_CONNECTIONS")
			.ok()
			.map(|v| v.parse().context("DB_MAX_CONNECTIONS must be a positive integer"))
			.transpose()?
			.unwrap_or(10);
		let sentry_dsn = env::var("SENTRY_DSN").ok().filter(|s| !s.is_empty());
		let posthog_key = env::var("POSTHOG_KEY").ok().filter(|s| !s.is_empty());
		let posthog_host = env::var("POSTHOG_HOST").ok().filter(|s| !s.is_empty());
		let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
		Ok(Self {
			database_url,
			bind_addr,
			db_max_connections,
			sentry_dsn,
			posthog_key,
			posthog_host,
			app_env,
		})
	}
}
