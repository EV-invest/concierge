//! Postgres adapter for grants over tenant namespaces (`grants`, `tenants`, `catalogs`,
//! migration 0026), and the `allocation:<service_id>` scope view of the same rows that
//! GrantScope/RevokeScope still speak until they are deleted.
//!
//! Every write decides WHO may make it inside the transaction that makes it, from rows
//! it holds locked:
//!
//! - the `users` rows of the target AND the actor, `FOR UPDATE`, in ONE statement ordered
//!   by id. Two grants to one person serialize instead of racing the partial unique
//!   index; a `SetRole`/hold on the actor committed after the RPC gate is SEEN, because
//!   the actor's seat and status are re-read from the locked row (the gate's copy only
//!   feeds the lock-free precheck); and a fixed lock order means two actors granting to
//!   each other wait instead of deadlocking.
//! - on the scope view, the actor's own scope grant, `FOR SHARE`, so the scope admin whose
//!   authority is being exercised cannot be revoked between the check and the write.
//!
//! A cheap unlocked precheck runs before `BEGIN` so a caller with no authority at all
//! never takes a row lock; the transaction's decision is the one that counts.
//!
//! The audit row goes to `admin_action` in the same transaction, like every other
//! operator decision about a person.
//!
//! A scope `allocation:<service>` is the tenant whose `legacy_scope` it is, and its two
//! roles are that tenant's `<namespace>:operator` and `<namespace>:admin` aliases. A user
//! granted both through GrantPermission reads as the admin.

use async_trait::async_trait;
use domain::{
	authz::{Iam, Role},
	error::DomainError,
	iam::{Catalog, Target},
	scopes::{Scope, ScopeAuthority, ScopeRole},
	users::{UserId, UserStatus},
};
use sqlx::{AssertSqlSafe, PgConnection, PgPool};
use uuid::Uuid;

use super::users::{AdminAction, record_action};
use crate::ports::{
	GrantHolderRecord, GrantOutcome, GrantRecord, GrantRepository, PublishOutcome, ScopeActor, ScopeGrantOutcome, ScopeRevokeOutcome, ScopeTarget, ScopedGrantRepository, UngrantableAddress,
};

/// One active scope grant, parsed back into domain types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedGrantRecord {
	pub user_id: UserId,
	pub scope: Scope,
	pub role: ScopeRole,
	pub granted_by: UserId,
	pub granted_at: i64,
}

/// An active scope grant with the holder's identity beside it, so a console can draw the
/// roster without a lookup per row.
pub struct ScopeHolderRecord {
	pub grant: ScopedGrantRecord,
	pub email: Option<String>,
	pub legal_name: Option<String>,
	pub preferred_name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct GrantRow {
	id: i64,
	user_id: Uuid,
	target: String,
	granted_by: Uuid,
	granted_at: i64,
	reason: Option<String>,
}

impl From<GrantRow> for GrantRecord {
	fn from(row: GrantRow) -> Self {
		Self {
			id: row.id,
			user_id: UserId::from_raw(row.user_id),
			target: row.target,
			granted_by: UserId::from_raw(row.granted_by),
			granted_at: row.granted_at,
			reason: row.reason,
		}
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

const GRANT_COLUMNS: &str = "id, user_id, target, granted_by, granted_at, reason";

pub struct PgGrants {
	pool: PgPool,
}

impl PgGrants {
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

impl RowLock {
	fn suffix(self) -> &'static str {
		match self {
			Self::None => "",
			Self::Share => " FOR SHARE",
			Self::Update => " FOR UPDATE",
		}
	}
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

fn standing_in(locked: &[(UserId, Standing)], id: UserId) -> Option<Standing> {
	locked.iter().find(|(held, _)| *held == id).map(|(_, standing)| *standing)
}

/// The seat the actor acts with, from their PERSISTED record: emergency access still
/// elevates (it is decided per request and needs no row to say so), a disabled account
/// acts with nothing, and an actor with no row acts with nothing either — a grant must
/// name a real `granted_by`.
fn acting_role(actor: &ScopeActor, standing: Option<&Standing>) -> Option<Role> {
	let standing = standing?;
	if standing.status != UserStatus::Active {
		return None;
	}
	Some(if actor.elevated { Role::Owner } else { standing.role })
}

/// The id a target names, if any account holds it. An email may belong to several
/// accounts (`users.email` is deliberately not unique), and picking one of them would
/// grant access to whichever sorted first.
enum Resolved {
	One(UserId),
	None,
	Ambiguous,
}

impl Resolved {
	fn id(&self) -> Option<UserId> {
		match self {
			Self::One(id) => Some(*id),
			Self::None | Self::Ambiguous => None,
		}
	}
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

async fn insert_grant(conn: &mut PgConnection, user: UserId, target: &str, namespace: &str, by: UserId, now: i64, reason: &str) -> Result<GrantRow, DomainError> {
	sqlx::query_as::<_, GrantRow>(AssertSqlSafe(format!(
		"INSERT INTO grants (user_id, namespace, target, granted_by, granted_at, reason) VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')) RETURNING {GRANT_COLUMNS}"
	)))
	.bind(user.raw())
	.bind(namespace)
	.bind(target)
	.bind(by.raw())
	.bind(now)
	.bind(reason)
	.fetch_one(&mut *conn)
	.await
	.map_err(repo_err)
}

async fn revoke_targets(conn: &mut PgConnection, user: UserId, targets: &[String], by: UserId, now: i64) -> Result<(), DomainError> {
	sqlx::query("UPDATE grants SET revoked_at = $3, revoked_by = $4 WHERE user_id = $1 AND target = ANY($2) AND revoked_at IS NULL")
		.bind(user.raw())
		.bind(targets)
		.bind(now)
		.bind(by.raw())
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

async fn catalog_of(conn: &mut PgConnection, namespace: &str) -> Result<Option<Option<Catalog>>, DomainError> {
	let row: Option<(Option<serde_json::Value>,)> = sqlx::query_as("SELECT c.catalog FROM tenants t LEFT JOIN catalogs c ON c.tenant_id = t.id WHERE t.namespace = $1")
		.bind(namespace)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	row.map(|(json,)| json.map(parse_catalog).transpose()).transpose()
}

fn parse_catalog(json: serde_json::Value) -> Result<Catalog, DomainError> {
	serde_json::from_value(json).map_err(|e| DomainError::Repository(format!("stored catalog is unreadable: {e}")))
}

// ---- the scope view -------------------------------------------------------------------

/// The tenant a scope names and the two targets its roles are.
struct ScopeTenant {
	namespace: String,
}

impl ScopeTenant {
	fn target(&self, role: ScopeRole) -> String {
		format!("{}:{}", self.namespace, role.as_str())
	}

	fn targets(&self) -> Vec<String> {
		[ScopeRole::Operator, ScopeRole::Admin].map(|role| self.target(role)).into()
	}

	fn role_of(&self, target: &str) -> Result<ScopeRole, DomainError> {
		let name = target
			.strip_prefix(&self.namespace)
			.and_then(|rest| rest.strip_prefix(':'))
			.ok_or_else(|| DomainError::Repository(format!("{target} is not a role of {}", self.namespace)))?;
		ScopeRole::parse(name)
	}
}

async fn scope_tenant(conn: &mut PgConnection, scope: &Scope) -> Result<ScopeTenant, DomainError> {
	let namespace: Option<String> = sqlx::query_scalar("SELECT namespace FROM tenants WHERE legacy_scope = $1")
		.bind(scope.to_string())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	namespace
		.map(|namespace| ScopeTenant { namespace })
		.ok_or_else(|| DomainError::Validation(format!("no tenant serves the scope {scope}")))
}

/// The role `user` holds on the scope: the higher of its two aliases they hold.
async fn active_scope_grant(conn: &mut PgConnection, user: UserId, tenant: &ScopeTenant, scope: &Scope, lock: RowLock) -> Result<Option<ScopedGrantRecord>, DomainError> {
	let rows = sqlx::query_as::<_, GrantRow>(AssertSqlSafe(format!(
		"SELECT {GRANT_COLUMNS} FROM grants WHERE user_id = $1 AND target = ANY($2) AND revoked_at IS NULL ORDER BY id{}",
		lock.suffix()
	)))
	.bind(user.raw())
	.bind(tenant.targets())
	.fetch_all(&mut *conn)
	.await
	.map_err(repo_err)?;
	let mut best: Option<ScopedGrantRecord> = None;
	for row in rows {
		let role = tenant.role_of(&row.target)?;
		if best.as_ref().is_none_or(|held| held.role < role) {
			best = Some(ScopedGrantRecord {
				user_id: UserId::from_raw(row.user_id),
				scope: scope.clone(),
				role,
				granted_by: UserId::from_raw(row.granted_by),
				granted_at: row.granted_at,
			});
		}
	}
	Ok(best)
}

async fn held_role(conn: &mut PgConnection, user: UserId, tenant: &ScopeTenant, scope: &Scope, lock: RowLock) -> Result<Option<ScopeRole>, DomainError> {
	Ok(active_scope_grant(conn, user, tenant, scope, lock).await?.map(|grant| grant.role))
}

/// The actor's authority over `scope` from their persisted standing plus their grant.
async fn authority_of(conn: &mut PgConnection, actor: &ScopeActor, standing: Option<&Standing>, tenant: &ScopeTenant, scope: &Scope, lock: RowLock) -> Result<ScopeAuthority, DomainError> {
	let Some(role) = acting_role(actor, standing) else {
		return Ok(ScopeAuthority::None);
	};
	if ScopeAuthority::resolve(role, None) == ScopeAuthority::Global {
		return Ok(ScopeAuthority::Global);
	}
	Ok(ScopeAuthority::resolve(role, held_role(conn, actor.id, tenant, scope, lock).await?))
}

/// The lock-free precheck from the gate's view of the actor. It can only REFUSE early:
/// a stale gate role that says yes is overruled inside the transaction.
async fn scope_precheck(pool: &PgPool, actor: &ScopeActor, scope: &Scope) -> Result<bool, DomainError> {
	if ScopeAuthority::resolve(actor.role, None) == ScopeAuthority::Global {
		return Ok(true);
	}
	let mut conn = pool.acquire().await.map_err(repo_err)?;
	let tenant = scope_tenant(&mut conn, scope).await?;
	Ok(held_role(&mut conn, actor.id, &tenant, scope, RowLock::None).await? == Some(ScopeRole::Admin))
}

/// Lock the target and the actor together and settle the actor's authority over a scope.
async fn lock_and_authorize(
	conn: &mut PgConnection,
	target: Option<UserId>,
	actor: &ScopeActor,
	tenant: &ScopeTenant,
	scope: &Scope,
) -> Result<(ScopeAuthority, Option<Standing>), DomainError> {
	let ids: Vec<UserId> = target.into_iter().chain([actor.id]).collect();
	let locked = lock_users(conn, &ids).await?;
	let actor_standing = standing_in(&locked, actor.id);
	let target_standing = target.and_then(|id| standing_in(&locked, id));
	let authority = authority_of(conn, actor, actor_standing.as_ref(), tenant, scope, RowLock::Share).await?;
	Ok((authority, target_standing))
}

#[async_trait]
impl ScopedGrantRepository for PgGrants {
	async fn scope_authority(&self, actor: &ScopeActor, scope: &Scope) -> Result<ScopeAuthority, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let tenant = scope_tenant(&mut conn, scope).await?;
		let standing = standing_of(&mut conn, actor.id).await?;
		authority_of(&mut conn, actor, standing.as_ref(), &tenant, scope, RowLock::None).await
	}

	async fn grant_scope(&self, target: &ScopeTarget, scope: &Scope, role: ScopeRole, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeGrantOutcome, DomainError> {
		if !scope_precheck(&self.pool, actor, scope).await? {
			return Ok(ScopeGrantOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let tenant = scope_tenant(&mut tx, scope).await?;
		let resolved = resolve_target(&mut tx, target).await?;
		let target_id = resolved.id();
		let (authority, target_standing) = lock_and_authorize(&mut tx, target_id, actor, &tenant, scope).await?;
		// Authority before existence: a caller with no say over this scope must not learn
		// which ids or addresses exist by watching NOT_FOUND come back.
		if authority == ScopeAuthority::None {
			return Ok(ScopeGrantOutcome::Denied);
		}
		if matches!(target, ScopeTarget::Id(_)) && !authority.may_address_by_id() {
			return Ok(ScopeGrantOutcome::Denied);
		}
		// A role the actor may not hand out to ANYONE is refused before the address is
		// looked at: refused for a real account and answered "cannot be granted" for a
		// missing one would be the oracle below by another door.
		if !authority.may_grant(role, None) {
			return Ok(ScopeGrantOutcome::Denied);
		}
		// Only staff learn why an address cannot be granted. A scope admin hears one answer
		// for all three, or GrantScope becomes a lookup of whether an address has an
		// account, how many, and whether it is in good standing (banking#447).
		let told_why = authority == ScopeAuthority::Global;
		let (target_id, target_standing) = match (resolved, target_id, target_standing) {
			(Resolved::Ambiguous, ..) if told_why => return Ok(ScopeGrantOutcome::AmbiguousEmail),
			(Resolved::Ambiguous, ..) => return Ok(ScopeGrantOutcome::Ungrantable(UngrantableAddress::SharedByAccounts)),
			(_, Some(id), Some(standing)) => (id, standing),
			_ if told_why =>
				return Err(DomainError::NotFound {
					entity: "user",
					id: target.describe(),
				}),
			_ => return Ok(ScopeGrantOutcome::Ungrantable(UngrantableAddress::NoAccount)),
		};
		if target_standing.status != UserStatus::Active {
			return Ok(if told_why {
				ScopeGrantOutcome::TargetDisabled
			} else {
				ScopeGrantOutcome::Ungrantable(UngrantableAddress::AccountNotActive)
			});
		}
		let current = active_scope_grant(&mut tx, target_id, &tenant, scope, RowLock::Update).await?;
		let current_role = current.as_ref().map(|grant| grant.role);
		if !authority.may_grant(role, current_role) {
			return Ok(ScopeGrantOutcome::Denied);
		}
		if let Some(grant) = current
			&& grant.role == role
		{
			// Re-granting what is held writes nothing: no history row that says nothing
			// changed, and a console re-submitting a form is not an event.
			return Ok(ScopeGrantOutcome::Granted(grant));
		}
		revoke_targets(&mut tx, target_id, &tenant.targets(), actor.id, now).await?;
		let row = insert_grant(&mut tx, target_id, &tenant.target(role), &tenant.namespace, actor.id, now, &action.reason).await?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({
			"scope": scope.to_string(),
			"role": role.as_str(),
			"previous_role": current_role.map(ScopeRole::as_str),
		}));
		record_action(&mut tx, target_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(ScopeGrantOutcome::Granted(ScopedGrantRecord {
			user_id: target_id,
			scope: scope.clone(),
			role,
			granted_by: UserId::from_raw(row.granted_by),
			granted_at: row.granted_at,
		}))
	}

	async fn revoke_scope(&self, target: &ScopeTarget, scope: &Scope, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeRevokeOutcome, DomainError> {
		if !scope_precheck(&self.pool, actor, scope).await? {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let tenant = scope_tenant(&mut tx, scope).await?;
		// An ambiguous email names nobody in particular; revoking "whichever of them holds
		// a grant" would still be well defined, but a refusal is simpler to reason about
		// and a global admin can revoke by id.
		let target_id = resolve_target(&mut tx, target).await?.id();
		let (authority, _) = lock_and_authorize(&mut tx, target_id, actor, &tenant, scope).await?;
		if authority == ScopeAuthority::None {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		// Either addressing form is fine for a scope admin here: the outcome depends only
		// on a grant in their own scope, which they can already list. That is also why an
		// unknown, shared or disabled address needs no collapsing like `grant`'s: all of
		// them are the one `NotHeld`.
		let Some(target_id) = target_id else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		let Some(current_role) = held_role(&mut tx, target_id, &tenant, scope, RowLock::Update).await? else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		if !authority.may_revoke(current_role) {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		revoke_targets(&mut tx, target_id, &tenant.targets(), actor.id, now).await?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "scope": scope.to_string(), "role": current_role.as_str() }));
		record_action(&mut tx, target_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(ScopeRevokeOutcome::Revoked)
	}

	async fn active_for_user(&self, user: UserId) -> Result<Vec<ScopedGrantRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let scopes: Vec<String> = sqlx::query_scalar(
			"SELECT DISTINCT t.legacy_scope FROM grants g JOIN tenants t ON t.namespace = g.namespace \
			 WHERE g.user_id = $1 AND g.revoked_at IS NULL AND t.legacy_scope IS NOT NULL \
			 AND g.target IN (t.namespace || ':operator', t.namespace || ':admin') ORDER BY t.legacy_scope",
		)
		.bind(user.raw())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		let mut out = Vec::with_capacity(scopes.len());
		for raw in scopes {
			let scope = Scope::parse(&raw)?;
			let tenant = scope_tenant(&mut conn, &scope).await?;
			out.extend(active_scope_grant(&mut conn, user, &tenant, &scope, RowLock::None).await?);
		}
		Ok(out)
	}

	async fn scope_holders(&self, scope: &Scope) -> Result<Vec<ScopeHolderRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let tenant = scope_tenant(&mut conn, scope).await?;
		let rows = sqlx::query_as::<_, HolderRow>(
			"SELECT g.id, g.user_id, g.target, g.granted_by, g.granted_at, g.reason, u.email, u.legal_name, u.preferred_name \
			 FROM grants g JOIN users u ON u.id = g.user_id \
			 WHERE g.target = ANY($1) AND g.revoked_at IS NULL \
			 ORDER BY g.granted_at, g.id",
		)
		.bind(tenant.targets())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		let mut holders: Vec<ScopeHolderRecord> = Vec::with_capacity(rows.len());
		for row in rows {
			let record = ScopeHolderRecord {
				grant: ScopedGrantRecord {
					user_id: UserId::from_raw(row.grant.user_id),
					scope: scope.clone(),
					role: tenant.role_of(&row.grant.target)?,
					granted_by: UserId::from_raw(row.grant.granted_by),
					granted_at: row.grant.granted_at,
				},
				email: row.email,
				legal_name: row.legal_name,
				preferred_name: row.preferred_name,
			};
			match holders.iter_mut().find(|held| held.grant.user_id == record.grant.user_id) {
				Some(held) if held.grant.role < record.grant.role => *held = record,
				Some(_) => {}
				None => holders.push(record),
			}
		}
		Ok(holders)
	}
}

// ---- grants over tenant namespaces ----------------------------------------------------

#[async_trait]
impl GrantRepository for PgGrants {
	async fn grant(&self, user: &ScopeTarget, target: &Target, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<GrantOutcome, DomainError> {
		if !actor.role.may(Iam::Grant) {
			return Ok(GrantOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let resolved = resolve_target(&mut tx, user).await?;
		let locked = lock_users(&mut tx, &resolved.id().into_iter().chain([actor.id]).collect::<Vec<_>>()).await?;
		if !acting_role(actor, standing_in(&locked, actor.id).as_ref()).is_some_and(|seat| seat.may(Iam::Grant)) {
			return Ok(GrantOutcome::Denied);
		}
		let Some(catalog) = catalog_of(&mut tx, target.namespace()).await? else {
			return Ok(GrantOutcome::UnknownTenant);
		};
		if catalog.as_ref().is_none_or(|catalog| target.grants(catalog).is_empty()) {
			return Ok(GrantOutcome::UndefinedTarget);
		}
		let user_id = match resolved {
			Resolved::Ambiguous => return Ok(GrantOutcome::AmbiguousEmail),
			Resolved::One(id) => id,
			Resolved::None =>
				return Err(DomainError::NotFound {
					entity: "user",
					id: user.describe(),
				}),
		};
		let Some(standing) = standing_in(&locked, user_id) else {
			return Err(DomainError::NotFound {
				entity: "user",
				id: user.describe(),
			});
		};
		if standing.status != UserStatus::Active {
			return Ok(GrantOutcome::TargetDisabled);
		}
		let held = sqlx::query_as::<_, GrantRow>(AssertSqlSafe(format!(
			"SELECT {GRANT_COLUMNS} FROM grants WHERE user_id = $1 AND target = $2 AND revoked_at IS NULL FOR UPDATE"
		)))
		.bind(user_id.raw())
		.bind(target.as_str())
		.fetch_optional(&mut *tx)
		.await
		.map_err(repo_err)?;
		if let Some(row) = held {
			return Ok(GrantOutcome::Granted(row.into()));
		}
		let row = insert_grant(&mut tx, user_id, target.as_str(), target.namespace(), actor.id, now, &action.reason).await?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "target": target.as_str(), "grant_id": row.id }));
		record_action(&mut tx, user_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(GrantOutcome::Granted(row.into()))
	}

	async fn revoke(&self, user: &ScopeTarget, target: &Target, actor: &ScopeActor, action: &AdminAction, now: i64) -> Result<ScopeRevokeOutcome, DomainError> {
		if !actor.role.may(Iam::Grant) {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let user_id = resolve_target(&mut tx, user).await?.id();
		let locked = lock_users(&mut tx, &user_id.into_iter().chain([actor.id]).collect::<Vec<_>>()).await?;
		if !acting_role(actor, standing_in(&locked, actor.id).as_ref()).is_some_and(|seat| seat.may(Iam::Grant)) {
			return Ok(ScopeRevokeOutcome::Denied);
		}
		let Some(user_id) = user_id else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		let revoked: Option<i64> = sqlx::query_scalar("UPDATE grants SET revoked_at = $3, revoked_by = $4 WHERE user_id = $1 AND target = $2 AND revoked_at IS NULL RETURNING id")
			.bind(user_id.raw())
			.bind(target.as_str())
			.bind(now)
			.bind(actor.id.raw())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		let Some(grant_id) = revoked else {
			return Ok(ScopeRevokeOutcome::NotHeld);
		};
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "target": target.as_str(), "grant_id": grant_id }));
		record_action(&mut tx, user_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(ScopeRevokeOutcome::Revoked)
	}

	async fn holders(&self, namespace: &str) -> Result<Option<Vec<GrantHolderRecord>>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let tenant: Option<String> = sqlx::query_scalar("SELECT id FROM tenants WHERE namespace = $1")
			.bind(namespace)
			.fetch_optional(&mut *conn)
			.await
			.map_err(repo_err)?;
		if tenant.is_none() {
			return Ok(None);
		}
		let rows = sqlx::query_as::<_, HolderRow>(
			"SELECT g.id, g.user_id, g.target, g.granted_by, g.granted_at, g.reason, u.email, u.legal_name, u.preferred_name \
			 FROM grants g JOIN users u ON u.id = g.user_id \
			 WHERE g.namespace = $1 AND g.revoked_at IS NULL \
			 ORDER BY g.granted_at, g.id",
		)
		.bind(namespace)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		Ok(Some(
			rows.into_iter()
				.map(|row| GrantHolderRecord {
					grant: row.grant.into(),
					email: row.email,
					legal_name: row.legal_name,
					preferred_name: row.preferred_name,
				})
				.collect(),
		))
	}

	async fn targets_of(&self, user: UserId) -> Result<Vec<Target>, DomainError> {
		let raw: Vec<String> = sqlx::query_scalar("SELECT target FROM grants WHERE user_id = $1 AND revoked_at IS NULL ORDER BY target")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?;
		raw.iter().map(|t| Target::parse(t)).collect()
	}

	async fn catalogs(&self) -> Result<Vec<(String, Catalog)>, DomainError> {
		let rows: Vec<(String, serde_json::Value)> = sqlx::query_as("SELECT t.namespace, c.catalog FROM catalogs c JOIN tenants t ON t.id = c.tenant_id ORDER BY t.namespace")
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?;
		rows.into_iter().map(|(namespace, json)| Ok((namespace, parse_catalog(json)?))).collect()
	}

	async fn audience_namespace(&self, audience: &str) -> Result<Option<String>, DomainError> {
		sqlx::query_scalar("SELECT t.namespace FROM rp_clients c JOIN tenants t ON t.id = c.tenant_id WHERE c.audience = $1")
			.bind(audience)
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)
	}

	async fn publish(&self, namespace: &str, catalog: &Catalog, now: i64) -> Result<PublishOutcome, DomainError> {
		let version = i64::try_from(catalog.version).map_err(|_| DomainError::Validation("a catalog version is at most 2^63-1".into()))?;
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let tenant: String = sqlx::query_scalar("SELECT id FROM tenants WHERE namespace = $1 FOR UPDATE")
			.bind(namespace)
			.fetch_one(&mut *tx)
			.await
			.map_err(repo_err)?;
		let stored: Option<serde_json::Value> = sqlx::query_scalar("SELECT catalog FROM catalogs WHERE tenant_id = $1")
			.bind(&tenant)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(stored) = stored.map(parse_catalog).transpose()? {
			if stored == *catalog {
				return Ok(PublishOutcome::Unchanged);
			}
			if stored.version >= catalog.version {
				return Ok(PublishOutcome::Stale { stored: stored.version });
			}
		}
		let json = serde_json::to_value(catalog).expect("a catalog serializes");
		sqlx::query(
			"INSERT INTO catalogs (tenant_id, version, catalog, published_at) VALUES ($1, $2, $3, $4) \
			 ON CONFLICT (tenant_id) DO UPDATE SET version = EXCLUDED.version, catalog = EXCLUDED.catalog, published_at = EXCLUDED.published_at",
		)
		.bind(&tenant)
		.bind(version)
		.bind(json)
		.bind(now)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;
		Ok(PublishOutcome::Published)
	}
}
