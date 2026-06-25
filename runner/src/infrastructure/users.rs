//! Postgres adapter for the user directory (the identity control plane).
//!
//! Each mutating method opens one transaction, writes the user row, and appends the
//! aggregate's drained lifecycle events to `user_outbox` in that same transaction —
//! the single ACID point that keeps the cross-plane bridge consistent with the
//! identity record. Each outbox row is stamped with the new `row_version` as the
//! bridge `sequence` and a snapshot of the identity payload the banking consumer needs.
//! Runtime queries (`sqlx::query*`, not the compile-time macros) keep `cargo build`
//! independent of a live database, mirroring banking.

use std::time::{SystemTime, UNIX_EPOCH};

use domain::{
	error::DomainError,
	users::{AuthSubject, Email, ProfileFields, User, UserId, UserStatus},
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

pub struct PgUsers {
	pool: PgPool,
}

impl PgUsers {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

#[derive(sqlx::FromRow)]
struct UserRow {
	id: Uuid,
	auth_subject: String,
	email: Option<String>,
	email_verified: bool,
	status: String,
	token_version: i64,
	kyc_level: i32,
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
			self.token_version as u64,
			self.kyc_level as u32,
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

/// The full column projection for the [`UserRow`] reads. sqlx 0.9 requires a
/// `&'static str` query, so each `SELECT` splices this literal in via `concat!` rather
/// than a runtime `format!` — keep this list in sync with [`UserRow`].
macro_rules! user_columns {
	() => {
		"id, auth_subject, email, email_verified, status, token_version, kyc_level, \
		legal_name, preferred_name, phone, date_of_birth, nationality, tax_residence, \
		residential_address, language, base_currency, timezone, row_version"
	};
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

impl PgUsers {
	pub async fn find_by_id(&self, id: UserId) -> Result<Option<User>, DomainError> {
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
	pub async fn provision(&self, subject: AuthSubject, email: Email, email_verified: bool) -> Result<User, DomainError> {
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
					"INSERT INTO users (id, auth_subject, email, email_verified, status, token_version, kyc_level, row_version) \
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (auth_subject) DO NOTHING RETURNING id",
				)
				.bind(candidate.id().raw())
				.bind(candidate.auth_subject().as_str())
				.bind(candidate.email().as_str())
				.bind(candidate.email_verified())
				.bind(candidate.status().as_str())
				.bind(candidate.token_version() as i64)
				.bind(candidate.kyc_level() as i32)
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

	/// Full-replace the caller's editable profile fields.
	pub async fn update_profile(&self, id: UserId, fields: ProfileFields) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.update_profile(fields);
		})
		.await
	}

	/// Bump the user's authoritative `token_version` ("revoke all"); emits SESSIONS_REVOKED.
	pub async fn revoke_tokens(&self, id: UserId) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.revoke_tokens();
		})
		.await
	}

	/// Disable a user (freeze sign-in/refresh); emits SUSPENDED.
	pub async fn disable_user(&self, id: UserId) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.disable();
		})
		.await
	}

	/// Re-enable a disabled user; emits REINSTATED.
	pub async fn enable_user(&self, id: UserId) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.enable();
		})
		.await
	}

	/// Set a user's KYC level; emits KYC_CHANGED.
	pub async fn set_kyc_level(&self, id: UserId, level: u32) -> Result<User, DomainError> {
		self.mutate(id, |user| {
			user.set_kyc_level(level);
		})
		.await
	}

	/// Load-mutate-persist in one transaction: read the row `FOR UPDATE`, run the
	/// aggregate command, write the row back, and drain its events to the outbox.
	async fn mutate(&self, id: UserId, command: impl FnOnce(&mut User)) -> Result<User, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let row = sqlx::query_as::<_, UserRow>(concat!("SELECT ", user_columns!(), " FROM users WHERE id = $1 FOR UPDATE"))
			.bind(id.raw())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?
			.ok_or_else(|| DomainError::NotFound { entity: "user", id: id.to_string() })?;
		let mut user = row.into_domain()?;
		command(&mut user);
		update_row(&mut tx, &user).await?;
		drain_outbox(&mut tx, &mut user).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(user)
	}
}

/// Persist the full editable surface, identity flags, and `row_version` of a user row.
async fn update_row(conn: &mut PgConnection, user: &User) -> Result<(), DomainError> {
	sqlx::query(
		"UPDATE users SET email = $2, email_verified = $3, status = $4, token_version = $5, kyc_level = $6, \
		legal_name = $7, preferred_name = $8, phone = $9, date_of_birth = $10, nationality = $11, \
		tax_residence = $12, residential_address = $13, language = $14, base_currency = $15, \
		timezone = $16, row_version = $17, updated_at = now() WHERE id = $1",
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
	.bind(user.row_version() as i64)
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}

/// Drain the aggregate's pending lifecycle events into `user_outbox` on the open
/// transaction, so identity state and the cross-plane events commit together or not at
/// all. Each row carries the bridge `Kind`, the per-user `sequence` (the user's
/// `row_version`), and the identity snapshot the banking consumer materializes from.
async fn drain_outbox(conn: &mut PgConnection, user: &mut User) -> Result<(), DomainError> {
	let occurred_at = unix_now();
	for event in user.drain_events() {
		sqlx::query(
			"INSERT INTO user_outbox (user_id, kind, kyc_level, occurred_at, sequence, auth_subject, email, email_verified, token_version) \
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		)
		.bind(user.id().raw())
		.bind(event.kind())
		.bind(user.kyc_level() as i32)
		.bind(occurred_at)
		.bind(user.row_version() as i64)
		.bind(user.auth_subject().as_str())
		.bind(user.email().as_str())
		.bind(user.email_verified())
		.bind(user.token_version() as i64)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	}
	Ok(())
}

fn unix_now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}
