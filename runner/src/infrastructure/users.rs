//! Postgres adapter for the user directory (the identity control plane).
//!
//! Each mutating method opens one transaction, writes the user row, and appends the
//! aggregate's drained lifecycle events to `user_outbox` in that same transaction —
//! the single ACID point that keeps the cross-plane bridge consistent with the
//! identity record. Each outbox row is stamped with the `row_version` at which its
//! event was emitted as the bridge `sequence`, plus a snapshot of the identity
//! payload the banking consumer needs.
//! Runtime queries (`sqlx::query*`, not the compile-time macros) keep `cargo build`
//! independent of a live database, mirroring banking.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use domain::{
	architecture::{EmitsEvents, Reader, Repository},
	authz::Role,
	error::DomainError,
	users::{AuthSubject, Email, ProfileFields, Suspension, User, UserId, UserStatus},
};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::ports::{KycLevelChange, RoleChange, UserDirectoryRepository};

/// The full column projection for the [`UserRow`] reads. sqlx 0.9 requires a
/// `&'static str` query, so each `SELECT` splices this literal in via `concat!` rather
/// than a runtime `format!` — keep this list in sync with [`UserRow`].
macro_rules! user_columns {
	() => {
		"id, auth_subject, email, email_verified, status, suspended_by, hold_expires_at, hold_ended_at, token_version, kyc_level, role, \
		legal_name, preferred_name, phone, date_of_birth, nationality, tax_residence, \
		residential_address, language, base_currency, timezone, row_version"
	};
}

/// Stable, arbitrary key for the transaction-scoped advisory lock that serializes
/// `user_outbox` appends (`pg_advisory_xact_lock`). Every path that appends an outbox
/// row MUST take this lock, so `position` (BIGSERIAL) order equals commit order — see
/// [`drain_outbox`]. Exported so integration tests can assert the contention.
pub const USER_OUTBOX_ADVISORY_LOCK: i64 = 0x4f55_5442_4f58; // "OUTBOX"

pub struct PgUsers {
	pool: PgPool,
}

impl PgUsers {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}

	/// Load-mutate-persist in one transaction: read the row `FOR UPDATE`, run the
	/// aggregate command, write the row back, and drain its events to the outbox.
	/// A command error (e.g. profile validation) rolls the transaction back.
	async fn mutate(&self, id: UserId, command: impl FnOnce(&mut User) -> Result<(), DomainError>) -> Result<User, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut user = load_for_update(&mut tx, id).await?;
		command(&mut user)?;
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(user)
	}

	/// [`Self::mutate`] with the operator's decision appended to `admin_action` on the
	/// SAME transaction. A command error rolls back the audit row with the change, which
	/// is the only ordering that keeps the log honest in both directions: no row without
	/// a change, and no change without a row.
	///
	/// `detail` is computed from the aggregate AFTER the command, so it records what the
	/// action actually did rather than what the caller asked for, and it is handed the
	/// caller's own `detail` to write over rather than being skipped when the caller
	/// supplied one. That distinction is not academic: `kyc_level_set` is written by two
	/// paths, the `from`/`to` delta is the point of the row (#48), and under a
	/// "only when the caller left it empty" rule the first caller to attach a detail of
	/// their own would silently cost the log that delta, with every test still green.
	async fn mutate_audited(
		&self,
		id: UserId,
		action: &AdminAction,
		now: i64,
		command: impl FnOnce(&mut User) -> Result<(), DomainError>,
		detail: impl FnOnce(&User, Option<serde_json::Value>) -> Option<serde_json::Value>,
	) -> Result<User, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut user = load_for_update(&mut tx, id).await?;
		command(&mut user)?;
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		let mut action = action.clone();
		action.detail = detail(&user, action.detail.take());
		record_action(&mut tx, id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(user)
	}
}

impl Repository for PgUsers {
	type Aggregate = User;
}

impl Reader for PgUsers {
	type Aggregate = User;
}

/// A lightweight, read-only projection for the operator console's user list — mapped
/// straight from SQL (not rehydrated through the aggregate) so it can carry the
/// DB-managed `created_at` the identity aggregate deliberately omits.
#[derive(sqlx::FromRow)]
pub struct AdminUserRow {
	pub id: Uuid,
	pub email: Option<String>,
	pub status: String,
	pub kyc_level: i32,
	pub role: String,
	pub token_version: i64,
	pub created_at: i64,
	pub suspended_by: Option<String>,
	pub hold_expires_at: Option<i64>,
}
/// One operator decision about one person, on its way to the `admin_action` log.
///
/// It travels WITH the command rather than being written by the caller afterwards,
/// because the row and the change it describes have to commit together: an audit trail
/// that can be missing the entry for a change that happened is not an audit trail, it is
/// a source of false confidence. Every method that takes one writes it inside the same
/// transaction as the mutation.
#[derive(Clone, Default)]
pub struct AdminAction {
	/// Who acted. `None` when no human did, and recording it as though an operator had
	/// pressed a button would be worse than recording nothing. Two writers today: the
	/// hold sweep, where nobody acted at all, and the vendor's verdict
	/// ([`UserDirectoryRepository::raise_kyc_level_to`]), where something did act but is
	/// not a row in `users` — that one puts its provenance in [`Self::detail`] instead
	/// (`source`, `case_id`), so a NULL actor is not the end of the question (#48).
	pub actor: Option<UserId>,
	/// The verb, in the log's own vocabulary (`held`, `reinstated`, `kyc_level_set`, …).
	pub action: &'static str,
	/// The actor's stated cause. Empty where the surface does not ask for one.
	pub reason: String,
	/// The proposal that authorized this, when one did.
	pub proposal_id: Option<Uuid>,
	/// What the action did, in the vocabulary of the action itself.
	pub detail: Option<serde_json::Value>,
	/// Where the request came from. Same provenance the consilium records.
	pub client_ip: String,
	pub user_agent: String,
}

impl AdminAction {
	/// An action with no human behind it.
	pub fn system(action: &'static str) -> Self {
		Self { action, ..Self::default() }
	}

	/// An action by a signed-in operator, with the request's provenance attached.
	pub fn by(actor: UserId, action: &'static str, audit: &super::governance::Audit) -> Self {
		Self {
			actor: Some(actor),
			action,
			client_ip: audit.client_ip.clone(),
			user_agent: audit.user_agent.clone(),
			..Self::default()
		}
	}

	pub fn with_reason(mut self, reason: &str) -> Self {
		self.reason = reason.chars().take(500).collect();
		self
	}

	pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
		self.detail = Some(detail);
		self
	}

	pub fn with_proposal(mut self, proposal_id: Uuid) -> Self {
		self.proposal_id = Some(proposal_id);
		self
	}
}

/// What [`UserDirectoryRepository::reinstate_outside_governance`] did.
///
/// The refusal is the point. `ReinstateUser` is one admin's button, and a suspension the
/// OWNERS voted for must not be liftable by one admin — that would make the consilium
/// advisory. The decision is taken inside the write transaction from the row held
/// `FOR UPDATE`, for the same TOCTOU reason `set_role_outside_ownership` is.
pub enum Reinstatement {
	/// The account is active again, and exactly one `REINSTATED` went to the outbox.
	Applied(Box<User>),
	/// The suspension is the owners' verdict; only they may lift it.
	GovernanceHeld,
}

/// The fields the admin authz gate decides on: the persisted access role, the account
/// status (a suspended principal is denied even while an unexpired token still verifies),
/// and the authoritative `token_version` (a "revoke all" bumps it, so a token minted
/// under an older version is rejected at the privileged surface at once).
pub struct AuthzRecord {
	pub role: Role,
	pub status: UserStatus,
	pub token_version: u64,
}
#[derive(sqlx::FromRow)]
struct UserRow {
	id: Uuid,
	auth_subject: String,
	email: Option<String>,
	email_verified: bool,
	status: String,
	suspended_by: Option<String>,
	hold_expires_at: Option<i64>,
	hold_ended_at: Option<i64>,
	token_version: i64,
	kyc_level: i32,
	role: String,
	legal_name: Option<String>,
	preferred_name: Option<String>,
	phone: Option<String>,
	date_of_birth: Option<String>,
	nationality: Option<String>,
	tax_residence: Option<String>,
	residential_address: Option<String>,
	language: Option<String>,
	base_currency: Option<String>,
	timezone: Option<String>,
	row_version: i64,
}

impl UserRow {
	fn into_domain(self) -> Result<User, DomainError> {
		let email = self.email.ok_or_else(|| DomainError::Repository("user row is missing an email".into()))?;
		Ok(User::rehydrate(
			UserId::from_raw(self.id),
			AuthSubject::parse(&self.auth_subject)?,
			Email::parse(&email)?,
			self.email_verified,
			UserStatus::parse(&self.status)?,
			// A disabled row with no `suspended_by` predates the column and is meant to
			// read as `None` — see the migration: those accounts keep the one-act,
			// never-lapsing semantics they were actually suspended under.
			self.suspended_by.as_deref().map(|by| Suspension::parse(by, self.hold_expires_at)).transpose()?,
			self.hold_ended_at,
			self.token_version as u64,
			self.kyc_level as u32,
			Role::parse(&self.role)?,
			ProfileFields {
				legal_name: self.legal_name,
				preferred_name: self.preferred_name,
				phone: self.phone,
				date_of_birth: self.date_of_birth,
				nationality: self.nationality,
				tax_residence: self.tax_residence,
				residential_address: self.residential_address,
				language: self.language,
				base_currency: self.base_currency,
				timezone: self.timezone,
			},
			self.row_version as u64,
		))
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

#[async_trait]
impl UserDirectoryRepository for PgUsers {
	async fn find_by_id(&self, id: UserId) -> Result<Option<User>, DomainError> {
		let row = sqlx::query_as::<_, UserRow>(concat!("SELECT ", user_columns!(), " FROM users WHERE id = $1"))
			.bind(id.raw())
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)?;
		row.map(UserRow::into_domain).transpose()
	}

	/// Upsert the user behind a verified identity. First sign-in inserts (emitting
	/// `Created`); a repeat sign-in applies the IdP's current email. Idempotent under a
	/// concurrent first-login race via `ON CONFLICT DO NOTHING` + re-read.
	async fn provision(&self, subject: AuthSubject, email: Email, email_verified: bool) -> Result<User, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;

		let existing = sqlx::query_as::<_, UserRow>(concat!("SELECT ", user_columns!(), " FROM users WHERE auth_subject = $1 FOR UPDATE"))
			.bind(subject.as_str())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;

		let mut user = match existing {
			Some(row) => {
				let mut user = row.into_domain()?;
				user.change_email(email, email_verified);
				update_row(&mut tx, &user).await?;
				user
			}
			None => {
				let candidate = User::provision(UserId::new(), subject.clone(), email.clone(), email_verified);
				let inserted = sqlx::query_scalar::<_, Uuid>(
					"INSERT INTO users (id, auth_subject, email, email_verified, status, token_version, kyc_level, role, row_version) \
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (auth_subject) DO NOTHING RETURNING id",
				)
				.bind(candidate.id().raw())
				.bind(candidate.auth_subject().as_str())
				.bind(candidate.email().as_str())
				.bind(candidate.email_verified())
				.bind(candidate.status().as_str())
				.bind(candidate.token_version() as i64)
				.bind(candidate.kyc_level() as i32)
				.bind(candidate.role().as_str())
				.bind(candidate.row_version() as i64)
				.fetch_optional(&mut *tx)
				.await
				.map_err(repo_err)?;

				match inserted {
					Some(_) => candidate,
					None => {
						// Lost the first-login race: re-read the row the other transaction
						// created and take the email-update path. Idempotent.
						let row = sqlx::query_as::<_, UserRow>(concat!("SELECT ", user_columns!(), " FROM users WHERE auth_subject = $1 FOR UPDATE"))
							.bind(subject.as_str())
							.fetch_one(&mut *tx)
							.await
							.map_err(repo_err)?;
						let mut user = row.into_domain()?;
						user.change_email(email, email_verified);
						update_row(&mut tx, &user).await?;
						user
					}
				}
			}
		};

		drain_outbox(&mut tx, &mut user).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(user)
	}

	async fn update_profile(&self, id: UserId, fields: ProfileFields) -> Result<User, DomainError> {
		self.mutate(id, |user| user.update_profile(fields)).await
	}

	async fn revoke_tokens(&self, id: UserId, action: &AdminAction, now: i64) -> Result<User, DomainError> {
		self.mutate_audited(
			id,
			action,
			now,
			|user| {
				user.revoke_tokens();
				Ok(())
			},
			|user, caller| Some(detail_with(caller, serde_json::json!({ "token_version": user.token_version() }))),
		)
		.await
	}

	async fn disable_user(&self, id: UserId) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.disable();
			Ok(())
		})
		.await
	}

	/// The same transaction shape as [`Self::mutate_audited`], written out because the
	/// aggregate needs one more fact decided under the row lock: whether the owners are
	/// already deciding about this account. Read on a separate connection, that is a
	/// TOCTOU window in the direction that matters — a proposal cancelled between the read
	/// and the write would let a hold extend on the strength of a decision nobody is
	/// making any more.
	async fn hold_user(&self, id: UserId, action: &AdminAction, by: Role, now: i64) -> Result<User, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut user = load_for_update(&mut tx, id).await?;
		// The plane's lazy-expiry convention: a proposal past its deadline is not open,
		// whether or not a write path has got round to stamping it so.
		let ratification_pending: bool =
			sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_proposal WHERE subject_user_id = $1 AND kind = 'suspension' AND state = 'open' AND expires_at > $2)")
				.bind(id.raw())
				.bind(now)
				.fetch_one(&mut *tx)
				.await
				.map_err(repo_err)?;
		user.hold(by, now, ratification_pending)?;
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		let action = action.clone().with_detail(serde_json::json!({
			"hold_expires_at": user.suspension().and_then(Suspension::hold_expires_at),
			// Whether this press was an extension under an open proposal or a fresh brake
			// — the one thing a reader of the log cannot otherwise tell apart.
			"ratification_pending": ratification_pending,
		}));
		record_action(&mut tx, id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(user)
	}

	async fn enable_user(&self, id: UserId, now: i64) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.enable(now);
			Ok(())
		})
		.await
	}

	/// One transaction: read the target `FOR UPDATE`, decide from THAT read, and either
	/// write or roll back — the shape [`Self::set_role_outside_ownership`] uses, for the
	/// same reason. Read on a separate connection, "is this suspension the owners'?" is a
	/// TOCTOU window: a proposal executing in between is invisible to it, so the admin's
	/// button sails past the refusal and then blocks on the row only to lift the verdict
	/// the consilium had just imposed.
	async fn reinstate_outside_governance(&self, id: UserId, action: &AdminAction, now: i64) -> Result<Reinstatement, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut user = load_for_update(&mut tx, id).await?;
		if user.suspension().is_some_and(|by| !by.is_reversible_by_one_admin()) {
			// Nothing was written, so dropping the transaction is the same as committing
			// it — and a refusal leaves no audit row, because nothing happened to audit.
			return Ok(Reinstatement::GovernanceHeld);
		}
		user.enable(now);
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		record_action(&mut tx, id, action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Reinstatement::Applied(Box::new(user)))
	}

	/// Let every due hold fall away, each in its own transaction so one bad row cannot
	/// strand the rest, and return who was released.
	///
	/// This one thing does NOT follow the plane's lazy-expiry convention, and the reason
	/// is the bridge. A governance proposal going stale has no effect outside this
	/// database, so projecting it as expired at read time is enough. A hold's whole
	/// purpose is the FROZEN flag the money plane mirrors, and the money plane learns
	/// about it only from a `user_outbox` row — so a lapse that is merely projected would
	/// release the account here and leave it frozen there, forever. The release has to be
	/// a write, which means something has to run.
	async fn lapse_due_holds(&self, now: i64, limit: i64) -> Result<Vec<UserId>, DomainError> {
		let due: Vec<Uuid> = sqlx::query("SELECT id FROM users WHERE hold_expires_at IS NOT NULL AND hold_expires_at <= $1 ORDER BY hold_expires_at LIMIT $2")
			.bind(now)
			.bind(limit)
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?
			.iter()
			.map(|row| row.try_get("id"))
			.collect::<Result<_, _>>()
			.map_err(repo_err)?;

		let mut lapsed = Vec::new();
		for raw in due {
			let id = UserId::from_raw(raw);
			let mut tx = self.pool.begin().await.map_err(repo_err)?;
			let mut user = load_for_update(&mut tx, id).await?;
			// Re-decided under the row lock: the hold may have been ratified, lifted or
			// renewed between the scan and this read, and the scan's answer is not
			// authority to release anybody.
			if !user.lapse_hold(now) {
				continue;
			}
			update_row(&mut tx, &user).await?;
			drain_outbox(&mut tx, &mut user).await?;
			record_action(&mut tx, id, &AdminAction::system("hold_lapsed"), now).await?;
			tx.commit().await.map_err(repo_err)?;
			lapsed.push(id);
		}
		Ok(lapsed)
	}

	async fn set_kyc_level(&self, id: UserId, level: u32, action: &AdminAction, now: i64) -> Result<User, DomainError> {
		// Nobody sets their own KYC level (#47). The RPC handler refuses this first and
		// with a better sentence; this is the same rule where the WRITE is, so the next
		// writer of a level — an admin HTTP route, a batch import, a consilium outcome —
		// inherits it instead of having to remember it. The range rule is already
		// triplicated for exactly this reason (handler, aggregate, `users_kyc_level_range`
		// CHECK), and the aggregate cannot hold this one: it never learns who is asking.
		//
		// HERE and not in `mutate_audited`: actor == subject is legitimate on its
		// siblings — `revoke_tokens` is how a person signs themselves out everywhere.
		// The vendor path is untouched; `raise_kyc_level_to` carries no actor at all.
		if action.actor == Some(id) {
			return Err(DomainError::Forbidden("a KYC level cannot be set on your own account".to_owned()));
		}
		// Captured before the command, because the audit row's whole value is the DELTA.
		// "kyc_level: 3" tells a reader where the account ended up, which they can also
		// see by looking at the account; it does not tell them whether an operator raised
		// somebody to 3 or quietly took them down to it (#48).
		// An atomic rather than a `Cell` only because the future crosses a `Send` bound.
		let from = std::sync::atomic::AtomicU32::new(0);
		// The level reaches here straight from a request, so the aggregate's refusal is
		// the caller's bad input and travels back as `Validation` -> `INVALID_ARGUMENT`.
		self.mutate_audited(
			id,
			action,
			now,
			|user| {
				from.store(user.kyc_level(), std::sync::atomic::Ordering::Relaxed);
				user.set_kyc_level(level)
			},
			|user, caller| Some(kyc_level_detail(from.load(std::sync::atomic::Ordering::Relaxed), user.kyc_level(), caller)),
		)
		.await
	}

	/// One transaction: read the target `FOR UPDATE`, compare from THAT read, and either
	/// raise or roll back. Same shape as [`Self::set_role_outside_ownership`] and for the
	/// same reason — the comparison that decides the write must not be a separate read.
	async fn raise_kyc_level_to(&self, id: UserId, target: u32, action: &AdminAction, now: i64) -> Result<KycLevelChange, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut user = load_for_update(&mut tx, id).await?;
		let current = user.kyc_level();
		if target <= current {
			// Nothing written, so dropping the transaction is the same as committing it.
			// Returning BEFORE `set_kyc_level` is what keeps the outbox clean: the
			// aggregate would no-op on an equal level, but a `target` BELOW `current`
			// would not — it would emit a `KYC_CHANGED` carrying a downgrade.
			return Ok(KycLevelChange::AlreadyHolds(current));
		}
		// Unlike `set_kyc_level`, `target` is NOT a caller's number: it comes from the
		// stored case's tier under this plane's own provider ceiling. A refusal here means
		// that clamp is broken, which is our invariant and not the vendor's request — so it
		// must not go back as `INVALID_ARGUMENT` blaming a delivery that asked for nothing.
		user.set_kyc_level(target)
			.map_err(|e| DomainError::Repository(format!("kyc level {target} is not writable: {e}")))?;
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		// In the SAME transaction as the level, like every other writer of this log. A
		// vendor decision used to write nothing here, so "who set this level, and when"
		// was answerable for the manual half and not the automatic one — an operator
		// opening a user's history saw the admin decisions and had to infer the rest from
		// `kyc_cases`, a table keyed by the vendor's session id and shaped around its
		// verdicts (#48). Same log, same question, both halves.
		//
		// `actor_user_id` stays NULL: no human pressed this. Who decided is in the detail
		// the caller supplies — the provider and the case — because a vendor is not a row
		// in `users` and inventing one would be a worse answer than none.
		let mut action = action.clone();
		action.detail = Some(kyc_level_detail(current, target, action.detail.take()));
		record_action(&mut tx, id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(KycLevelChange::Raised { from: current, to: target })
	}

	async fn set_role(&self, id: UserId, role: Role) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.set_role(role);
			Ok(())
		})
		.await
	}

	/// One transaction: read the target `FOR UPDATE`, decide from THAT read, and either
	/// write or roll back. A refusal returns before the commit, so it leaves nothing —
	/// not even the row lock, once the transaction drops.
	async fn set_role_outside_ownership(&self, id: UserId, role: Role, action: &AdminAction, now: i64) -> Result<RoleChange, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut user = load_for_update(&mut tx, id).await?;
		// The PERSISTED role, never an elevated one: emergency access authorizes an
		// operator, it does not seat them, so it must not decide either branch.
		let holds_seat = user.role() == Role::Owner;
		if role == Role::Owner && !holds_seat {
			return Ok(RoleChange::WouldGrantOwnership);
		}
		if holds_seat && role != Role::Owner {
			return Ok(RoleChange::WouldTakeOwnership);
		}
		// GRANTING admin only. Taking it away stays one act on purpose: de-escalation must
		// never be the slower path, or the fastest way to contain a rogue operator becomes
		// a quorum by mail.
		if role == Role::Admin && user.role() != Role::Admin {
			return Ok(RoleChange::WouldGrantAdmin);
		}
		user.set_role(role);
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		let mut action = action.clone();
		action.detail.get_or_insert_with(|| serde_json::json!({ "role": user.role().as_str() }));
		record_action(&mut tx, id, &action, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(RoleChange::Applied(Box::new(user)))
	}

	/// Seats held, straight from the column the consilium decides on. Suspended owners
	/// count: ownership is the role, and excluding them would let an admin shrink the
	/// roster (and reopen emergency access) by suspending people.
	async fn owner_count(&self) -> Result<i64, DomainError> {
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE role = $1")
			.bind(Role::Owner.as_str())
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)
	}

	/// The role + status + authoritative `token_version` for a user id, read together so
	/// the admin authz gate can deny a suspended or revoked principal at request time —
	/// the stateless token verifier can't see either (it validates only the signed
	/// claims). `None` when the user does not exist.
	async fn authz_record(&self, id: UserId) -> Result<Option<AuthzRecord>, DomainError> {
		let row: Option<(String, String, i64)> = sqlx::query_as("SELECT role, status, token_version FROM users WHERE id = $1")
			.bind(id.raw())
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)?;
		row.map(|(role, status, token_version)| {
			Ok(AuthzRecord {
				role: Role::parse(&role)?,
				status: UserStatus::parse(&status)?,
				token_version: token_version as u64,
			})
		})
		.transpose()
	}

	/// Empty-string filters are treated as "no filter" so the query stays a single
	/// static statement (sqlx 0.9 needs a `&'static str`).
	async fn list(&self, query: &str, role: &str, status: &str, limit: i64, offset: i64) -> Result<(Vec<AdminUserRow>, i64), DomainError> {
		let rows = sqlx::query_as::<_, AdminUserRow>(
			"SELECT id, email, status, kyc_level, role, token_version, suspended_by, hold_expires_at, \
			 EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at \
			 FROM users \
			 WHERE ($1 = '' OR email ILIKE '%' || $1 || '%' OR id::text ILIKE '%' || $1 || '%') \
			   AND ($2 = '' OR role = $2) \
			   AND ($3 = '' OR status = $3) \
			 ORDER BY created_at DESC LIMIT $4 OFFSET $5",
		)
		.bind(query)
		.bind(role)
		.bind(status)
		.bind(limit)
		.bind(offset)
		.fetch_all(&self.pool)
		.await
		.map_err(repo_err)?;

		let total: i64 = sqlx::query_scalar(
			"SELECT COUNT(*) FROM users \
			 WHERE ($1 = '' OR email ILIKE '%' || $1 || '%' OR id::text ILIKE '%' || $1 || '%') \
			   AND ($2 = '' OR role = $2) \
			   AND ($3 = '' OR status = $3)",
		)
		.bind(query)
		.bind(role)
		.bind(status)
		.fetch_one(&self.pool)
		.await
		.map_err(repo_err)?;

		Ok((rows, total))
	}
}

/// Read one user `FOR UPDATE` on an open transaction. Shared with the governance
/// adapter, which must take a seat and append the resulting `ROLE_CHANGED` in the same
/// transaction as the consilium's verdict — one identity writer, not two.
pub(crate) async fn load_for_update(conn: &mut PgConnection, id: UserId) -> Result<User, DomainError> {
	sqlx::query_as::<_, UserRow>(concat!("SELECT ", user_columns!(), " FROM users WHERE id = $1 FOR UPDATE"))
		.bind(id.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound { entity: "user", id: id.to_string() })?
		.into_domain()
}

/// Persist the full editable surface, identity flags, and `row_version` of a user row.
pub(crate) async fn update_row(conn: &mut PgConnection, user: &User) -> Result<(), DomainError> {
	sqlx::query(
		"UPDATE users SET email = $2, email_verified = $3, status = $4, token_version = $5, kyc_level = $6, \
		legal_name = $7, preferred_name = $8, phone = $9, date_of_birth = $10, nationality = $11, \
		tax_residence = $12, residential_address = $13, language = $14, base_currency = $15, \
		timezone = $16, role = $17, row_version = $18, suspended_by = $19, hold_expires_at = $20, hold_ended_at = $21, \
		updated_at = now() WHERE id = $1",
	)
	.bind(user.id().raw())
	.bind(user.email().as_str())
	.bind(user.email_verified())
	.bind(user.status().as_str())
	.bind(user.token_version() as i64)
	.bind(user.kyc_level() as i32)
	.bind(user.legal_name())
	.bind(user.preferred_name())
	.bind(user.phone())
	.bind(user.date_of_birth())
	.bind(user.nationality())
	.bind(user.tax_residence())
	.bind(user.residential_address())
	.bind(user.language())
	.bind(user.base_currency())
	.bind(user.timezone())
	.bind(user.role().as_str())
	.bind(user.row_version() as i64)
	.bind(user.suspension().map(Suspension::as_str))
	// `i64::MAX` is what a hold with no stored deadline rehydrates as (the column is
	// nullable independently of `suspended_by`). Writing it back as NULL rather than as
	// the sentinel keeps the round trip stable and keeps the sweep's index useful.
	.bind(user.suspension().and_then(Suspension::hold_expires_at).filter(|expires| *expires != i64::MAX))
	.bind(user.hold_ended_at())
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}

/// The `detail` both KYC writers record, so the two halves of the history read alike.
///
/// `kyc_level` is kept beside `to` and is the same number. Rows written before this
/// carried only `kyc_level`, and an audit log whose shape silently forked in the middle
/// is one whose readers quietly get half the answer; one redundant key is the cheaper
/// side of that trade.
fn kyc_level_detail(from: u32, to: u32, base: Option<serde_json::Value>) -> serde_json::Value {
	detail_with(base, serde_json::json!({ "from": from, "to": to, "kyc_level": to }))
}

/// The caller's `detail`, with the keys the adapter itself knows written over it.
///
/// One direction, for every writer of this log: what the write DID wins over what the
/// caller said about it. The caller describes an intention and cannot see the row it
/// landed on — the level before it, the token version after it — so a collision between
/// the two is the adapter's to settle.
fn detail_with(base: Option<serde_json::Value>, keys: serde_json::Value) -> serde_json::Value {
	let mut merged = match base {
		Some(object @ serde_json::Value::Object(_)) => object,
		_ => serde_json::json!({}),
	};
	if let (Some(target), serde_json::Value::Object(keys)) = (merged.as_object_mut(), keys) {
		target.extend(keys);
	}
	merged
}

/// Append one operator decision to `admin_action` on the OPEN transaction, so the row and
/// the mutation it describes commit together or not at all.
pub(crate) async fn record_action(conn: &mut PgConnection, subject: UserId, action: &AdminAction, now: i64) -> Result<(), DomainError> {
	sqlx::query(
		"INSERT INTO admin_action (subject_user_id, actor_user_id, action, proposal_id, reason, detail, occurred_at, client_ip, user_agent) \
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
	)
	.bind(subject.raw())
	.bind(action.actor.map(|a| a.raw()))
	.bind(action.action)
	.bind(action.proposal_id)
	.bind(&action.reason)
	.bind(action.detail.as_ref())
	.bind(now)
	.bind(action.client_ip.chars().take(64).collect::<String>())
	.bind(action.user_agent.chars().take(256).collect::<String>())
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}

/// Drain the aggregate's pending lifecycle events into `user_outbox` on the open
/// transaction, so identity state and the cross-plane events commit together or not at
/// all. Each row carries the bridge `Kind`, the per-user `sequence` (the `row_version`
/// at which the event was emitted), and the identity snapshot the banking consumer
/// materializes from.
pub(crate) async fn drain_outbox(conn: &mut PgConnection, user: &mut User) -> Result<(), DomainError> {
	let events = user.drain_events();
	if events.is_empty() {
		return Ok(());
	}

	// Serialize outbox appends against COMMIT order. `position` is a BIGSERIAL assigned at
	// INSERT time, but two concurrent transactions can be assigned positions in one order
	// and commit in the opposite order. The banking bridge consumer advances a high-water
	// `position` cursor (`WHERE position > after_position`), so a lower-positioned row that
	// commits AFTER the cursor has already passed a higher one is skipped forever — a
	// dropped SUSPENDED/SESSIONS_REVOKED would leave a revoked user un-frozen on the money
	// plane. Holding this transaction-scoped advisory lock from before the first INSERT
	// (which assigns the BIGSERIAL) until commit makes position order equal commit order,
	// so the cursor can never skip a committed event.
	sqlx::query("SELECT pg_advisory_xact_lock($1)")
		.bind(USER_OUTBOX_ADVISORY_LOCK)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;

	let occurred_at = unix_now();
	// Every emit path bumps `row_version` exactly once per event (`bump_and_emit`), so
	// the i-th of n drained events was minted at `row_version - (n - 1 - i)`. Stamping
	// the FINAL `row_version` on every row would give a multi-event command duplicate
	// sequences, and the banking consumer's per-user monotonic gate would drop every
	// event after the first — losing a SUSPENDED/SESSIONS_REVOKED.
	let count = events.len() as u64;
	for (i, event) in events.into_iter().enumerate() {
		let sequence = user.row_version() - (count - 1 - i as u64);
		sqlx::query(
			"INSERT INTO user_outbox (user_id, kind, kyc_level, occurred_at, sequence, auth_subject, email, email_verified, token_version, role) \
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
		)
		.bind(user.id().raw())
		.bind(event.kind())
		.bind(user.kyc_level() as i32)
		.bind(occurred_at)
		.bind(sequence as i64)
		.bind(user.auth_subject().as_str())
		.bind(user.email().as_str())
		.bind(user.email_verified())
		.bind(user.token_version() as i64)
		.bind(user.role().as_str())
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	}
	Ok(())
}

fn unix_now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}
