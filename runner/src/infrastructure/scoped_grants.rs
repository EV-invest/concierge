//! Postgres adapter for scoped grants (`scoped_grants`, migration 0023).
//!
//! Every write decides WHO may make it inside the transaction that makes it, from rows
//! it holds locked:
//!
//! - the `users` rows of the target AND the actor, `FOR UPDATE`, in ONE statement ordered
//!   by id. Two grants to one person serialize instead of racing the partial unique
//!   index; a `SetRole`/hold on the actor committed after the RPC gate is SEEN, because
//!   the actor's role and status are re-read from the locked row (the gate's copy only
//!   feeds the lock-free precheck); and a fixed lock order means two actors granting to
//!   each other wait instead of deadlocking.
//! - the actor's own grant on the scope, `FOR SHARE`, so the scope admin whose
//!   authority is being exercised cannot be revoked between the check and the write.
//!
//! A cheap unlocked precheck runs before `BEGIN` so a caller with no authority at all
//! never takes a row lock; the transaction's decision is the one that counts.
//!
//! The audit row goes to `admin_action` in the same transaction, like every other
//! operator decision about a person.

use async_trait::async_trait;
use domain::{
	authz::Role,
	error::DomainError,
	scopes::{Scope, ScopeAuthority, ScopeRole},
	users::{UserId, UserStatus},
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::users::{AdminAction, record_action};
use crate::ports::{ScopeActor, ScopeGrantOutcome, ScopeRevokeOutcome, ScopeTarget, ScopedGrantRepository};

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
	/// A read that decides nothing on its own (precheck, roster).
	None,
	/// The actor's own grant: read to authorize, must not change under the write.
	Share,
	/// The target's grant: about to be revoked or replaced.
	Update,
}

async fn active_grant(conn: &mut PgConnection, user: UserId, scope: &Scope, lock: RowLock) -> Result<Option<GrantRow>, DomainError> {
	// sqlx needs a `&'static str`, so each lock mode is a whole statement.
	let sql = match lock {
		RowLock::None => "SELECT user_id, scope, role, granted_by, granted_at FROM scoped_grants WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL",
		RowLock::Share => "SELECT user_id, scope, role, granted_by, granted_at FROM scoped_grants WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL FOR SHARE",
		RowLock::Update => "SELECT user_id, scope, role, granted_by, granted_at FROM scoped_grants WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL FOR UPDATE",
	};
	sqlx::query_as::<_, GrantRow>(sql)
		.bind(user.raw())
		.bind(scope.to_string())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)
}

async fn held_role(conn: &mut PgConnection, user: UserId, scope: &Scope, lock: RowLock) -> Result<Option<ScopeRole>, DomainError> {
	active_grant(conn, user, scope, lock).await?.map(|row| ScopeRole::parse(&row.role)).transpose()
}

/// The persisted facts about one user the decision is taken from.
#[derive(Clone, Copy)]
struct Standing {
	role: Role,
	status: UserStatus,
}

/// Lock the `users` rows of `ids` (deduplicated) `FOR UPDATE` in id order and return
/// what they say. Missing ids are simply absent from the answer.
async fn lock_users(conn: &mut PgConnection, ids: &[UserId]) -> Result<Vec<(UserId, Standing)>, DomainError> {
	let raw: Vec<Uuid> = ids.iter().map(|id| id.raw()).collect();
	let rows: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT id, role, status FROM users WHERE id = ANY($1) ORDER BY id FOR UPDATE")
		.bind(&raw)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	rows.into_iter()
		.map(|(id, role, status)| {
			Ok((
				UserId::from_raw(id),
				Standing {
					role: Role::parse(&role)?,
					status: UserStatus::parse(&status)?,
				},
			))
		})
		.collect()
}

async fn standing_of(conn: &mut PgConnection, user: UserId) -> Result<Option<Standing>, DomainError> {
	let row: Option<(String, String)> = sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	row.map(|(role, status)| {
		Ok(Standing {
			role: Role::parse(&role)?,
			status: UserStatus::parse(&status)?,
		})
	})
	.transpose()
}

/// The global role the actor acts with, from their PERSISTED record: emergency access
/// still elevates (it is decided per request and needs no row to say so), a disabled
/// account acts with nothing, and an actor with no row acts with nothing either — a
/// grant must name a real `granted_by`.
fn acting_role(actor: &ScopeActor, standing: Option<&Standing>) -> Option<Role> {
	let standing = standing?;
	if standing.status != UserStatus::Active {
		return None;
	}
	Some(if actor.elevated { Role::Owner } else { standing.role })
}

/// The actor's authority over `scope` from their persisted standing plus their grant.
async fn authority_of(conn: &mut PgConnection, actor: &ScopeActor, standing: Option<&Standing>, scope: &Scope, lock: RowLock) -> Result<ScopeAuthority, DomainError> {
	let Some(role) = acting_role(actor, standing) else {
		return Ok(ScopeAuthority::None);
	};
	if ScopeAuthority::resolve(role, None) == ScopeAuthority::Global {
		return Ok(ScopeAuthority::Global);
	}
	Ok(ScopeAuthority::resolve(role, held_role(conn, actor.id, scope, lock).await?))
}

/// The lock-free precheck from the gate's view of the actor. It can only REFUSE early:
/// a stale gate role that says yes is overruled inside the transaction.
async fn precheck(pool: &PgPool, actor: &ScopeActor, scope: &Scope) -> Result<bool, DomainError> {
	if ScopeAuthority::resolve(actor.role, None) == ScopeAuthority::Global {
		return Ok(true);
	}
	let mut conn = pool.acquire().await.map_err(repo_err)?;
	Ok(held_role(&mut conn, actor.id, scope, RowLock::None).await? == Some(ScopeRole::Admin))
}

/// The id a target names, if any account holds it. An email may belong to several
/// accounts (`users.email` is deliberately not unique), and picking one of them would
/// grant access to whichever sorted first.
enum Resolved {
	One(UserId),
	None,
	Ambiguous,
}

async fn resolve_target(conn: &mut PgConnection, target: &ScopeTarget) -> Result<Resolved, DomainError> {
	match target {
		ScopeTarget::Id(id) => Ok(Resolved::One(*id)),
		ScopeTarget::Email(email) => {
			// Stored normalized by `Email::parse`, so an equality is the case-insensitive match.
			let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1 LIMIT 2")
				.bind(email.as_str())
				.fetch_all(&mut *conn)
				.await
				.map_err(repo_err)?;
			Ok(match ids.as_slice() {
				[] => Resolved::None,
				[id] => Resolved::One(UserId::from_raw(*id)),
				_ => Resolved::Ambiguous,
			})
		}
	}
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

fn standing_in(locked: &[(UserId, Standing)], id: UserId) -> Option<Standing> {
	locked.iter().find(|(held, _)| *held == id).map(|(_, standing)| *standing)
}

/// Lock the target and the actor together and settle the actor's authority.
async fn lock_and_authorize(conn: &mut PgConnection, target: Option<UserId>, actor: &ScopeActor, scope: &Scope) -> Result<(ScopeAuthority, Option<Standing>), DomainError> {
	let ids: Vec<UserId> = target.into_iter().chain([actor.id]).collect();
	let locked = lock_users(conn, &ids).await?;
	let actor_standing = standing_in(&locked, actor.id);
	let target_standing = target.and_then(|id| standing_in(&locked, id));
	let authority = authority_of(conn, actor, actor_standing.as_ref(), scope, RowLock::Share).await?;
	Ok((authority, target_standing))
}

#[async_trait]
impl ScopedGrantRepository for PgScopedGrants {
	async fn authority(&self, actor: &ScopeActor, scope: &Scope) -> Result<ScopeAuthority, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let standing = standing_of(&mut conn, actor.id).await?;
		authority_of(&mut conn, actor, standing.as_ref(), scope, RowLock::None).await
	}

	async fn grant(&self, target: &ScopeTarget, scope: &Scope, role: ScopeRole, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeGrantOutcome, DomainError> {
		if !precheck(&self.pool, actor, scope).await? {
			return Ok(ScopeGrantOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let resolved = resolve_target(&mut tx, target).await?;
		let target_id = match resolved {
			Resolved::One(id) => Some(id),
			Resolved::None | Resolved::Ambiguous => None,
		};
		let (authority, target_standing) = lock_and_authorize(&mut tx, target_id, actor, scope).await?;
		// Authority before existence: a caller with no say over this scope must not learn
		// which ids or addresses exist by watching NOT_FOUND come back.
		if authority == ScopeAuthority::None {
			return Ok(ScopeGrantOutcome::Denied);
		}
		if matches!(target, ScopeTarget::Id(_)) && !authority.may_address_by_id() {
			return Ok(ScopeGrantOutcome::Denied);
		}
		let (target_id, target_standing) = match (resolved, target_id, target_standing) {
			(Resolved::Ambiguous, ..) => return Ok(ScopeGrantOutcome::AmbiguousEmail),
			(_, Some(id), Some(standing)) => (id, standing),
			_ =>
				return Err(DomainError::NotFound {
					entity: "user",
					id: target.describe(),
				}),
		};
		if target_standing.status != UserStatus::Active {
			return Ok(ScopeGrantOutcome::TargetDisabled);
		}
		let current = active_grant(&mut tx, target_id, scope, RowLock::Update).await?;
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
			revoke_row(&mut tx, target_id, scope, actor.id, now).await?;
		}
		let row = sqlx::query_as::<_, GrantRow>(
			"INSERT INTO scoped_grants (user_id, scope, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, $5) \
			 RETURNING user_id, scope, role, granted_by, granted_at",
		)
		.bind(target_id.raw())
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
		record_action(&mut tx, target_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(ScopeGrantOutcome::Granted(row.into_record()?))
	}

	async fn revoke(&self, target: &ScopeTarget, scope: &Scope, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeRevokeOutcome, DomainError> {
		if !precheck(&self.pool, actor, scope).await? {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// An ambiguous email names nobody in particular; revoking "whichever of them holds
		// a grant" would still be well defined, but a refusal is simpler to reason about
		// and a global admin can revoke by id.
		let target_id = match resolve_target(&mut tx, target).await? {
			Resolved::One(id) => Some(id),
			Resolved::None | Resolved::Ambiguous => None,
		};
		let (authority, _) = lock_and_authorize(&mut tx, target_id, actor, scope).await?;
		if authority == ScopeAuthority::None {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		// Either addressing form is fine for a scope admin here: the outcome depends only
		// on a grant in their own scope, which they can already list.
		let Some(target_id) = target_id else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		let Some(current_role) = held_role(&mut tx, target_id, scope, RowLock::Update).await? else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		if !authority.may_revoke(current_role) {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		revoke_row(&mut tx, target_id, scope, actor.id, now).await?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "scope": scope.to_string(), "role": current_role.as_str() }));
		record_action(&mut tx, target_id, &action, now).await?;
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
