//! Postgres adapter for grants over tenant namespaces (`grants`, `tenants`, `catalogs`,
//! migration 0026).
//!
//! Every write decides WHO may make it inside the transaction that makes it, from rows
//! it holds locked:
//!
//! - the `users` rows of the subject AND the actor, `FOR UPDATE`, in ONE statement ordered
//!   by id. Two grants to one person serialize instead of racing the partial unique
//!   index; a `SetRole`/hold on the actor committed after the RPC gate is SEEN, because
//!   the actor's seat and status are re-read from the locked row (the gate's copy only
//!   feeds the lock-free precheck); and a fixed lock order means two actors granting to
//!   each other wait instead of deadlocking.
//! - a delegate's own grants in the namespace, `FOR SHARE`, so the alias whose authority
//!   is being exercised cannot be revoked between the check and the write.
//!
//! A cheap unlocked precheck runs before `BEGIN` so a caller with no authority at all
//! never takes a row lock; the transaction's decision is the one that counts.
//!
//! The audit row goes to `admin_action` in the same transaction, like every other
//! operator decision about a person.

use async_trait::async_trait;
use domain::{
	authz::{Iam, Role},
	error::DomainError,
	iam::{self, Catalog, Target},
	users::{UserId, UserStatus},
};
use sqlx::{AssertSqlSafe, PgConnection, PgPool};
use uuid::Uuid;

use super::users::{AdminAction, record_action};
use crate::ports::{
	GrantActor, GrantAuthority, GrantHolderRecord, GrantOutcome, GrantRecord, GrantRepository, GrantSubject, PublishOutcome, RevokeOutcome, TenantCatalog, UngrantableAddress,
};

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

#[derive(sqlx::FromRow)]
struct CatalogRow {
	namespace: String,
	granting_seats_hold_all: bool,
	catalog: serde_json::Value,
}

impl TryFrom<CatalogRow> for TenantCatalog {
	type Error = DomainError;

	fn try_from(row: CatalogRow) -> Result<Self, DomainError> {
		Ok(Self {
			namespace: row.namespace,
			granting_seats_hold_all: row.granting_seats_hold_all,
			catalog: parse_catalog(row.catalog)?,
		})
	}
}

const GRANT_COLUMNS: &str = "id, user_id, target, granted_by, granted_at, reason";

/// Each tenant's highest version.
const CURRENT_CATALOGS: &str = "SELECT DISTINCT ON (c.tenant_id) t.namespace, t.granting_seats_hold_all, c.catalog \
	 FROM catalogs c JOIN tenants t ON t.id = c.tenant_id";

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

fn parse_catalog(json: serde_json::Value) -> Result<Catalog, DomainError> {
	serde_json::from_value(json).map_err(|e| DomainError::Repository(format!("stored catalog is unreadable: {e}")))
}

/// The persisted facts about one user the decision is taken from.
#[derive(Clone, Copy)]
struct Standing {
	role: Role,
	status: UserStatus,
}

fn standing(role: &str, status: &str) -> Result<Standing, DomainError> {
	Ok(Standing {
		role: Role::parse(role)?,
		status: UserStatus::parse(status)?,
	})
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
	rows.into_iter().map(|(id, role, status)| Ok((UserId::from_raw(id), standing(&role, &status)?))).collect()
}

async fn standing_of(conn: &mut PgConnection, user: UserId) -> Result<Option<Standing>, DomainError> {
	let row: Option<(String, String)> = sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	row.map(|(role, status)| standing(&role, &status)).transpose()
}

fn standing_in(locked: &[(UserId, Standing)], id: UserId) -> Option<Standing> {
	locked.iter().find(|(held, _)| *held == id).map(|(_, standing)| *standing)
}

/// The seat the actor acts with, from their PERSISTED record: emergency access still
/// elevates (it is decided per request and needs no row to say so), a disabled account
/// acts with nothing, and an actor with no row acts with nothing either — a grant must
/// name a real `granted_by`.
fn acting_role(actor: &GrantActor, standing: Option<Standing>) -> Option<Role> {
	let standing = standing?;
	if standing.status != UserStatus::Active {
		return None;
	}
	Some(if actor.elevated { Role::Owner } else { standing.role })
}

/// The id a subject names, if any account holds it. An email may belong to several
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

async fn resolve_subject(conn: &mut PgConnection, subject: &GrantSubject) -> Result<Resolved, DomainError> {
	match subject {
		GrantSubject::Id(id) => Ok(Resolved::One(*id)),
		GrantSubject::Email(email) => {
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

async fn current_catalog(conn: &mut PgConnection, namespace: &str) -> Result<Option<TenantCatalog>, DomainError> {
	sqlx::query_as::<_, CatalogRow>(AssertSqlSafe(format!("{CURRENT_CATALOGS} WHERE t.namespace = $1 ORDER BY c.tenant_id, c.version DESC")))
		.bind(namespace)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.map(TenantCatalog::try_from)
		.transpose()
}

/// The aliases `user` may grant in `catalog`'s namespace, from their active grants there.
/// `share` holds those grants for the rest of the transaction.
async fn delegable_by(conn: &mut PgConnection, user: UserId, tenant: &TenantCatalog, share: bool) -> Result<Vec<String>, DomainError> {
	let held: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
		"SELECT target FROM grants WHERE user_id = $1 AND namespace = $2 AND revoked_at IS NULL ORDER BY id{}",
		if share { " FOR SHARE" } else { "" }
	)))
	.bind(user.raw())
	.bind(&tenant.namespace)
	.fetch_all(&mut *conn)
	.await
	.map_err(repo_err)?;
	let held = held.iter().map(|t| Target::parse(t)).collect::<Result<Vec<_>, _>>()?;
	Ok(iam::delegable(&held, &tenant.catalog).into_iter().map(str::to_owned).collect())
}

/// The actor's authority over `target`, inside the transaction holding their row.
async fn authority_over(conn: &mut PgConnection, actor: &GrantActor, standing: Option<Standing>, tenant: Option<&TenantCatalog>, target: &Target) -> Result<GrantAuthority, DomainError> {
	let Some(role) = acting_role(actor, standing) else {
		return Ok(GrantAuthority::None);
	};
	if role.may(Iam::Grant) {
		return Ok(GrantAuthority::Seat);
	}
	let Some(tenant) = tenant else {
		return Ok(GrantAuthority::None);
	};
	Ok(match delegable_by(conn, actor.id, tenant, true).await?.iter().any(|alias| alias == target.as_str()) {
		true => GrantAuthority::Delegate,
		false => GrantAuthority::None,
	})
}

/// The lock-free precheck from the gate's view of the actor. It can only REFUSE early:
/// a stale gate role that says yes is overruled inside the transaction.
async fn precheck(pool: &PgPool, actor: &GrantActor, target: &Target) -> Result<bool, DomainError> {
	if actor.role.may(Iam::Grant) {
		return Ok(true);
	}
	let mut conn = pool.acquire().await.map_err(repo_err)?;
	let Some(tenant) = current_catalog(&mut conn, target.namespace()).await? else {
		return Ok(false);
	};
	Ok(delegable_by(&mut conn, actor.id, &tenant, false).await?.iter().any(|alias| alias == target.as_str()))
}

#[async_trait]
impl GrantRepository for PgGrants {
	async fn authority(&self, actor: &GrantActor, namespace: &str) -> Result<GrantAuthority, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let standing = standing_of(&mut conn, actor.id).await?;
		let Some(role) = acting_role(actor, standing) else {
			return Ok(GrantAuthority::None);
		};
		if role.may(Iam::Grant) {
			return Ok(GrantAuthority::Seat);
		}
		let Some(tenant) = current_catalog(&mut conn, namespace).await? else {
			return Ok(GrantAuthority::None);
		};
		Ok(match delegable_by(&mut conn, actor.id, &tenant, false).await?.is_empty() {
			true => GrantAuthority::None,
			false => GrantAuthority::Delegate,
		})
	}

	async fn grant(&self, subject: &GrantSubject, target: &Target, actor: &GrantActor, action: &AdminAction, now: i64) -> Result<GrantOutcome, DomainError> {
		if !precheck(&self.pool, actor, target).await? {
			return Ok(GrantOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let resolved = resolve_subject(&mut tx, subject).await?;
		let locked = lock_users(&mut tx, &resolved.id().into_iter().chain([actor.id]).collect::<Vec<_>>()).await?;
		let tenant = current_catalog(&mut tx, target.namespace()).await?;
		// Authority before existence: a caller with no say over this target must not learn
		// which ids, addresses or tenants exist by watching the answer change.
		let authority = authority_over(&mut tx, actor, standing_in(&locked, actor.id), tenant.as_ref(), target).await?;
		match authority {
			GrantAuthority::None => return Ok(GrantOutcome::Denied),
			GrantAuthority::Delegate if matches!(subject, GrantSubject::Id(_)) => return Ok(GrantOutcome::Denied),
			GrantAuthority::Delegate | GrantAuthority::Seat => {}
		}
		let Some(tenant) = tenant else {
			return Ok(GrantOutcome::UnknownTenant);
		};
		if target.grants(&tenant.catalog).is_empty() {
			return Ok(GrantOutcome::UndefinedTarget);
		}
		// Only a seat learns why an address cannot be granted. A delegate hears one answer
		// for all three, or a grant becomes a lookup of whether an address has an account,
		// how many, and whether it is in good standing (banking#447).
		let told_why = authority == GrantAuthority::Seat;
		let subject_standing = resolved.id().and_then(|id| standing_in(&locked, id));
		let (user_id, standing) = match (resolved, subject_standing) {
			(Resolved::Ambiguous, _) if told_why => return Ok(GrantOutcome::AmbiguousEmail),
			(Resolved::Ambiguous, _) => return Ok(GrantOutcome::Ungrantable(UngrantableAddress::SharedByAccounts)),
			(Resolved::One(id), Some(standing)) => (id, standing),
			_ if told_why =>
				return Err(DomainError::NotFound {
					entity: "user",
					id: subject.describe(),
				}),
			_ => return Ok(GrantOutcome::Ungrantable(UngrantableAddress::NoAccount)),
		};
		if user_id == actor.id {
			return Ok(GrantOutcome::ToSelf);
		}
		if standing.status != UserStatus::Active {
			return Ok(if told_why {
				GrantOutcome::TargetDisabled
			} else {
				GrantOutcome::Ungrantable(UngrantableAddress::AccountNotActive)
			});
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
			// Re-granting what is held writes nothing: a console re-submitting a form is not
			// an event.
			return Ok(GrantOutcome::Granted(row.into()));
		}
		let row = sqlx::query_as::<_, GrantRow>(AssertSqlSafe(format!(
			"INSERT INTO grants (user_id, namespace, target, granted_by, granted_at, reason) VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')) RETURNING {GRANT_COLUMNS}"
		)))
		.bind(user_id.raw())
		.bind(target.namespace())
		.bind(target.as_str())
		.bind(actor.id.raw())
		.bind(now)
		.bind(&action.reason)
		.fetch_one(&mut *tx)
		.await
		.map_err(repo_err)?;
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "target": target.as_str(), "grant_id": row.id }));
		record_action(&mut tx, user_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(GrantOutcome::Granted(row.into()))
	}

	async fn revoke(&self, subject: &GrantSubject, target: &Target, actor: &GrantActor, action: &AdminAction, now: i64) -> Result<RevokeOutcome, DomainError> {
		if !precheck(&self.pool, actor, target).await? {
			return Ok(RevokeOutcome::Denied);
		}
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// An ambiguous email names nobody in particular, and either addressing form is fine
		// for a delegate: the answer depends only on a grant they can already list, so an
		// unknown, shared or disabled address is the one `NotHeld`.
		let user_id = resolve_subject(&mut tx, subject).await?.id();
		let locked = lock_users(&mut tx, &user_id.into_iter().chain([actor.id]).collect::<Vec<_>>()).await?;
		let tenant = current_catalog(&mut tx, target.namespace()).await?;
		if authority_over(&mut tx, actor, standing_in(&locked, actor.id), tenant.as_ref(), target).await? == GrantAuthority::None {
			return Ok(RevokeOutcome::Denied);
		}
		let Some(user_id) = user_id else {
			return Ok(RevokeOutcome::NotHeld);
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
			return Ok(RevokeOutcome::NotHeld);
		};
		let mut action = action.clone();
		action.detail = Some(serde_json::json!({ "target": target.as_str(), "grant_id": grant_id }));
		record_action(&mut tx, user_id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(RevokeOutcome::Revoked)
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

	async fn catalogs(&self) -> Result<Vec<TenantCatalog>, DomainError> {
		sqlx::query_as::<_, CatalogRow>(AssertSqlSafe(format!("{CURRENT_CATALOGS} ORDER BY c.tenant_id, c.version DESC")))
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?
			.into_iter()
			.map(TenantCatalog::try_from)
			.collect()
	}

	async fn catalog(&self, namespace: &str) -> Result<Option<TenantCatalog>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		current_catalog(&mut conn, namespace).await
	}

	async fn audience_namespace(&self, audience: &str) -> Result<Option<String>, DomainError> {
		sqlx::query_scalar("SELECT t.namespace FROM rp_clients c JOIN tenants t ON t.id = c.tenant_id WHERE c.audience = $1")
			.bind(audience)
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)
	}

	async fn publish(&self, namespace: &str, client_id: &str, catalog: &Catalog, now: i64) -> Result<PublishOutcome, DomainError> {
		let version = i64::try_from(catalog.version).map_err(|_| DomainError::Validation("a catalog version is at most 2^63-1".into()))?;
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// Serializes publishers of one tenant, so two replicas booting together cannot both
		// pass the version check.
		let tenant: String = sqlx::query_scalar("SELECT id FROM tenants WHERE namespace = $1 FOR UPDATE")
			.bind(namespace)
			.fetch_one(&mut *tx)
			.await
			.map_err(repo_err)?;
		let stored: Option<serde_json::Value> = sqlx::query_scalar("SELECT catalog FROM catalogs WHERE tenant_id = $1 ORDER BY version DESC LIMIT 1")
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
		sqlx::query("INSERT INTO catalogs (tenant_id, version, catalog, published_at, published_by) VALUES ($1, $2, $3, $4, $5)")
			.bind(&tenant)
			.bind(version)
			.bind(serde_json::to_value(catalog).expect("a catalog is maps and sets of strings"))
			.bind(now)
			.bind(client_id)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;
		Ok(PublishOutcome::Published)
	}
}
