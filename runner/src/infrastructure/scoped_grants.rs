//! Postgres adapter for scoped grants (`scoped_grants`, migration 0023).
//!
//! Every write decides WHO may make it inside the transaction that makes it, from rows
//! it holds locked: the target's `users` row (`FOR UPDATE`, so two grants to one person
//! serialize instead of racing the partial unique index) and the actor's own grant on
//! the scope (`FOR SHARE`, so the admin whose authority is being exercised cannot be
//! revoked between the check and the write). The target row is always locked FIRST —
//! a scope admin acting on their own grant then waits behind a concurrent revocation of
//! it instead of deadlocking with it.
//!
//! The audit row goes to `admin_action` in the same transaction, like every other
//! operator decision about a person.

use async_trait::async_trait;
use domain::{
	error::DomainError,
	scopes::{Scope, ScopeAuthority, ScopeRole},
	users::UserId,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::users::{AdminAction, record_action};
use crate::ports::{ScopeActor, ScopeGrantOutcome, ScopeRevokeOutcome, ScopedGrantRepository};

/// One active grant, parsed back into domain types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedGrantRecord {
	pub user_id: UserId,
	pub scope: Scope,
	pub role: ScopeRole,
	pub granted_by: UserId,
	pub granted_at: i64,
}

/// An active grant with the holder's identity beside it, so a console can draw the
/// roster without a lookup per row.
pub struct ScopeHolderRecord {
	pub grant: ScopedGrantRecord,
	pub email: Option<String>,
	pub legal_name: Option<String>,
	pub preferred_name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct GrantRow {
	user_id: Uuid,
	scope: String,
	role: String,
	granted_by: Uuid,
	granted_at: i64,
}

impl GrantRow {
	fn into_record(self) -> Result<ScopedGrantRecord, DomainError> {
		Ok(ScopedGrantRecord {
			user_id: UserId::from_raw(self.user_id),
			scope: Scope::parse(&self.scope)?,
			role: ScopeRole::parse(&self.role)?,
			granted_by: UserId::from_raw(self.granted_by),
			granted_at: self.granted_at,
		})
	}
}

#[derive(sqlx::FromRow)]
struct HolderRow {
	#[sqlx(flatten)]
	grant: GrantRow,
	email: Option<String>,
	legal_name: Option<String>,
	preferred_name: Option<String>,
}

pub struct PgScopedGrants {
	pool: PgPool,
}

impl PgScopedGrants {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

#[derive(Clone, Copy)]
enum RowLock {
	/// The actor's own grant: read to authorize, must not change under the write.
	Share,
	/// The target's grant: about to be revoked or replaced.
	Update,
}

async fn active_grant(conn: &mut PgConnection, user: UserId, scope: &Scope, lock: RowLock) -> Result<Option<GrantRow>, DomainError> {
	// sqlx needs a `&'static str`, so the two lock modes are two whole statements.
	let sql = match lock {
		RowLock::Update => "SELECT user_id, scope, role, granted_by, granted_at FROM scoped_grants WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL FOR UPDATE",
		RowLock::Share => "SELECT user_id, scope, role, granted_by, granted_at FROM scoped_grants WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL FOR SHARE",
	};
	sqlx::query_as::<_, GrantRow>(sql)
		.bind(user.raw())
		.bind(scope.to_string())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)
}

/// Lock the target's `users` row, answering whether it exists.
async fn lock_user(conn: &mut PgConnection, user: UserId) -> Result<bool, DomainError> {
	let found: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1 FOR UPDATE")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(found.is_some())
}

/// The actor's authority over `scope`, read on the open transaction with their own grant
/// held `FOR SHARE`. A global manager never needs the read.
async fn authority_of(conn: &mut PgConnection, actor: &ScopeActor, scope: &Scope) -> Result<ScopeAuthority, DomainError> {
	let global = ScopeAuthority::resolve(actor.role, None);
	if global == ScopeAuthority::Global {
		return Ok(global);
	}
	let held = active_grant(conn, actor.id, scope, RowLock::Share).await?.map(|row| ScopeRole::parse(&row.role)).transpose()?;
	Ok(ScopeAuthority::resolve(actor.role, held))
}

async fn revoke_row(conn: &mut PgConnection, user: UserId, scope: &Scope, by: UserId, now: i64) -> Result<(), DomainError> {
	sqlx::query("UPDATE scoped_grants SET revoked_at = $3, revoked_by = $4 WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL")
		.bind(user.raw())
		.bind(scope.to_string())
		.bind(now)
		.bind(by.raw())
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

#[async_trait]
impl ScopedGrantRepository for PgScopedGrants {
	async fn authority(&self, actor: &ScopeActor, scope: &Scope) -> Result<ScopeAuthority, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		authority_of(&mut conn, actor, scope).await
	}

	async fn grant(&self, target: UserId, scope: &Scope, role: ScopeRole, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeGrantOutcome, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let exists = lock_user(&mut tx, target).await?;
		let authority = authority_of(&mut tx, actor, scope).await?;
		// Authority before existence: a caller with no say over this scope must not learn
		// which user ids exist by watching NOT_FOUND come back.
		if authority == ScopeAuthority::None {
			return Ok(ScopeGrantOutcome::Denied);
		}
		if !exists {
			return Err(DomainError::NotFound {
				entity: "user",
				id: target.to_string(),
			});
		}
		let current = active_grant(&mut tx, target, scope, RowLock::Update).await?;
		let current_role = current.as_ref().map(|row| ScopeRole::parse(&row.role)).transpose()?;
		if !authority.may_grant(role, current_role) {
			return Ok(ScopeGrantOutcome::Denied);
		}
		if let Some(row) = current
			&& current_role == Some(role)
		{
			// Re-granting what is held writes nothing: no history row that says nothing
			// changed, and a console re-submitting a form is not an event.
			return Ok(ScopeGrantOutcome::Granted(row.into_record()?));
		}
		if current_role.is_some() {
			revoke_row(&mut tx, target, scope, actor.id, now).await?;
		}
		let row = sqlx::query_as::<_, GrantRow>(
			"INSERT INTO scoped_grants (user_id, scope, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, $5) \
			 RETURNING user_id, scope, role, granted_by, granted_at",
		)
		.bind(target.raw())
		.bind(scope.to_string())
		.bind(role.as_str())
		.bind(actor.id.raw())
		.bind(now)
		.fetch_one(&mut *tx)
		.await
		.map_err(repo_err)?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({
			"scope": scope.to_string(),
			"role": role.as_str(),
			"previous_role": current_role.map(ScopeRole::as_str),
		}));
		record_action(&mut tx, target, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(ScopeGrantOutcome::Granted(row.into_record()?))
	}

	async fn revoke(&self, target: UserId, scope: &Scope, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeRevokeOutcome, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_user(&mut tx, target).await?;
		let authority = authority_of(&mut tx, actor, scope).await?;
		if authority == ScopeAuthority::None {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		let Some(current) = active_grant(&mut tx, target, scope, RowLock::Update).await? else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		let current_role = ScopeRole::parse(&current.role)?;
		if !authority.may_revoke(current_role) {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		revoke_row(&mut tx, target, scope, actor.id, now).await?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "scope": scope.to_string(), "role": current_role.as_str() }));
		record_action(&mut tx, target, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(ScopeRevokeOutcome::Revoked)
	}

	async fn active_for_user(&self, user: UserId) -> Result<Vec<ScopedGrantRecord>, DomainError> {
		sqlx::query_as::<_, GrantRow>("SELECT user_id, scope, role, granted_by, granted_at FROM scoped_grants WHERE user_id = $1 AND revoked_at IS NULL ORDER BY scope")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?
			.into_iter()
			.map(GrantRow::into_record)
			.collect()
	}

	async fn holders(&self, scope: &Scope) -> Result<Vec<ScopeHolderRecord>, DomainError> {
		let rows = sqlx::query_as::<_, HolderRow>(
			"SELECT g.user_id, g.scope, g.role, g.granted_by, g.granted_at, u.email, u.legal_name, u.preferred_name \
			 FROM scoped_grants g JOIN users u ON u.id = g.user_id \
			 WHERE g.scope = $1 AND g.revoked_at IS NULL \
			 ORDER BY g.granted_at, g.id",
		)
		.bind(scope.to_string())
		.fetch_all(&self.pool)
		.await
		.map_err(repo_err)?;
		rows.into_iter()
			.map(|row| {
				Ok(ScopeHolderRecord {
					grant: row.grant.into_record()?,
					email: row.email,
					legal_name: row.legal_name,
					preferred_name: row.preferred_name,
				})
			})
			.collect()
	}
}
