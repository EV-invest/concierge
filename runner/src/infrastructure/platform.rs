//! Postgres adapter for the platform/cabinet control config.
//!
//! Plain config state (maintenance mode, announcement banner, feature flags) — not a
//! domain aggregate with invariants, so it lives in the adapter + service layers
//! rather than `domain`. Runtime queries (not the compile-time macros) keep
//! `cargo build` independent of a live database, mirroring the users adapter.

use domain::error::DomainError;
use sqlx::PgPool;

pub struct PgPlatform {
	pool: PgPool,
}

/// The singleton platform config (maintenance + announcement).
#[derive(sqlx::FromRow)]
pub struct PlatformConfigRow {
	pub maintenance_mode: bool,
	pub announcement_title: String,
	pub announcement_body: String,
	pub announcement_active: bool,
}

/// One feature flag row.
#[derive(sqlx::FromRow)]
pub struct FeatureFlagRow {
	pub key: String,
	pub description: String,
	pub enabled: bool,
	pub rollout: i32,
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

impl PgPlatform {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}

	pub async fn config(&self) -> Result<PlatformConfigRow, DomainError> {
		sqlx::query_as::<_, PlatformConfigRow>("SELECT maintenance_mode, announcement_title, announcement_body, announcement_active FROM platform_config WHERE id = TRUE")
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)
	}

	pub async fn flags(&self) -> Result<Vec<FeatureFlagRow>, DomainError> {
		sqlx::query_as::<_, FeatureFlagRow>("SELECT key, description, enabled, rollout FROM feature_flags ORDER BY key ASC")
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)
	}

	pub async fn set_maintenance(&self, enabled: bool) -> Result<(), DomainError> {
		sqlx::query("UPDATE platform_config SET maintenance_mode = $1, updated_at = now() WHERE id = TRUE")
			.bind(enabled)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	pub async fn set_announcement(&self, title: &str, body: &str, active: bool) -> Result<(), DomainError> {
		sqlx::query("UPDATE platform_config SET announcement_title = $1, announcement_body = $2, announcement_active = $3, updated_at = now() WHERE id = TRUE")
			.bind(title)
			.bind(body)
			.bind(active)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	pub async fn upsert_flag(&self, key: &str, description: &str, enabled: bool, rollout: i32) -> Result<(), DomainError> {
		sqlx::query(
			"INSERT INTO feature_flags (key, description, enabled, rollout) VALUES ($1, $2, $3, $4) \
			 ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description, enabled = EXCLUDED.enabled, rollout = EXCLUDED.rollout, updated_at = now()",
		)
		.bind(key)
		.bind(description)
		.bind(enabled)
		.bind(rollout.clamp(0, 100))
		.execute(&self.pool)
		.await
		.map_err(repo_err)?;
		Ok(())
	}
}
