//! Postgres adapter for relying parties (`rp_clients`, `rp_codes`, `rp_sessions`,
//! migration 0025).
//!
//! Nothing secret is stored in a form that can be presented back: client secrets, codes
//! and refresh secrets are all SHA-256 digests. A plain digest and not a slow KDF because
//! every one of them is 256 bits of CSPRNG output (or refused at boot as too short to be
//! one), so there is nothing to brute-force that a work factor would slow down.
//!
//! The decisions that must not race are taken under a row lock in one transaction: a
//! code is burned, or found already burned and marked replayed, inside the transaction
//! that read it; a family is opened only if its code was not replayed in the meantime;
//! a rotation succeeds only against the secret it was checked against.

use async_trait::async_trait;
use domain::{clients::AccessPolicy, error::DomainError, users::UserId};
use sqlx::PgPool;
use uuid::Uuid;

use crate::ports::{ClientRecord, CodeClaim, CodeOutcome, NewCode, NewSession, RelyingPartyRepository, SessionRevocation, SessionRow};

/// How long a spent or expired code row is kept after its expiry, so a replay inside that
/// window is still recognised as one and revokes what the code bought.
const CODE_RETENTION_SECS: i64 = 24 * 60 * 60;

pub struct PgRelyingParties {
	pool: PgPool,
}

impl PgRelyingParties {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

#[derive(sqlx::FromRow)]
struct ClientRow {
	client_id: String,
	audience: String,
	redirect_uris: Vec<String>,
	access_policy: String,
	secret_hash: Option<Vec<u8>>,
	disabled_at: Option<i64>,
	namespace: Option<String>,
}

impl TryFrom<ClientRow> for ClientRecord {
	type Error = DomainError;

	fn try_from(row: ClientRow) -> Result<Self, DomainError> {
		Ok(Self {
			access_policy: AccessPolicy::parse(&row.access_policy)?,
			client_id: row.client_id,
			audience: row.audience,
			redirect_uris: row.redirect_uris,
			secret_hash: row.secret_hash,
			disabled: row.disabled_at.is_some(),
			namespace: row.namespace,
		})
	}
}

#[derive(sqlx::FromRow)]
struct CodeRow {
	client_id: String,
	redirect_uri: String,
	code_challenge: String,
	user_id: Uuid,
	token_version: i64,
	expires_at: i64,
	redeemed_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct SessionDbRow {
	client_id: String,
	user_id: Uuid,
	current_hash: Vec<u8>,
	prev_hash: Option<Vec<u8>>,
	token_version: i64,
	expires_at: i64,
	absolute_expires_at: i64,
	revoked_at: Option<i64>,
}

#[async_trait]
impl RelyingPartyRepository for PgRelyingParties {
	async fn client(&self, client_id: &str) -> Result<Option<ClientRecord>, DomainError> {
		sqlx::query_as::<_, ClientRow>(
			"SELECT c.client_id, c.audience, c.redirect_uris, c.access_policy, c.secret_hash, c.disabled_at, t.namespace \
			 FROM rp_clients c LEFT JOIN tenants t ON t.id = c.tenant_id WHERE c.client_id = $1",
		)
		.bind(client_id)
		.fetch_optional(&self.pool)
		.await
		.map_err(repo_err)?
		.map(ClientRecord::try_from)
		.transpose()
	}

	async fn clients(&self) -> Result<Vec<ClientRecord>, DomainError> {
		sqlx::query_as::<_, ClientRow>(
			"SELECT c.client_id, c.audience, c.redirect_uris, c.access_policy, c.secret_hash, c.disabled_at, t.namespace \
			 FROM rp_clients c LEFT JOIN tenants t ON t.id = c.tenant_id ORDER BY c.client_id",
		)
		.fetch_all(&self.pool)
		.await
		.map_err(repo_err)?
		.into_iter()
		.map(ClientRecord::try_from)
		.collect()
	}

	async fn set_secret_hash(&self, client_id: &str, secret_hash: Option<&[u8]>, now: i64) -> Result<bool, DomainError> {
		// `secret_set_at` moves only when the hash does, so it dates the ROTATION rather
		// than the last boot.
		let changed: Option<bool> = sqlx::query_scalar(
			"WITH before AS (SELECT secret_hash FROM rp_clients WHERE client_id = $1 FOR UPDATE)
			 UPDATE rp_clients SET
			     secret_hash = $2,
			     secret_set_at = CASE WHEN $2::BYTEA IS NULL THEN NULL
			                          WHEN rp_clients.secret_hash IS NOT DISTINCT FROM $2::BYTEA THEN rp_clients.secret_set_at
			                          ELSE $3 END
			 FROM before WHERE rp_clients.client_id = $1
			 RETURNING before.secret_hash IS DISTINCT FROM $2::BYTEA",
		)
		.bind(client_id)
		.bind(secret_hash)
		.bind(now)
		.fetch_optional(&self.pool)
		.await
		.map_err(repo_err)?;
		changed.ok_or_else(|| DomainError::NotFound {
			entity: "relying party",
			id: client_id.to_owned(),
		})
	}

	async fn issue_code(&self, code: NewCode<'_>) -> Result<(), DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// Reaped here rather than by a sweeper: the table only grows on this path, so this
		// is the one place that can keep it bounded, and the expiry index makes it cheap.
		sqlx::query("DELETE FROM rp_codes WHERE expires_at < $1")
			.bind(code.issued_at - CODE_RETENTION_SECS)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		sqlx::query(
			"INSERT INTO rp_codes (code_hash, client_id, redirect_uri, code_challenge, user_id, token_version, upstream_family, issued_at, expires_at, client_ip, user_agent)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
		)
		.bind(code.code_hash)
		.bind(code.client_id)
		.bind(code.redirect_uri)
		.bind(code.code_challenge)
		.bind(code.user.raw())
		.bind(code.token_version as i64)
		.bind(code.upstream_family)
		.bind(code.issued_at)
		.bind(code.expires_at)
		.bind(code.client_ip)
		.bind(code.user_agent)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)
	}

	async fn claim_code(&self, claim: CodeClaim<'_>) -> Result<CodeOutcome, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let row: Option<CodeRow> = sqlx::query_as(
			"SELECT client_id, redirect_uri, code_challenge, user_id, token_version, expires_at, redeemed_at
			 FROM rp_codes WHERE code_hash = $1 FOR UPDATE",
		)
		.bind(claim.code_hash)
		.fetch_optional(&mut *tx)
		.await
		.map_err(repo_err)?;
		let Some(row) = row else {
			return Ok(CodeOutcome::Unknown);
		};

		if row.redeemed_at.is_some() {
			// Presented twice: whoever holds it now may not be whoever held it first, so
			// what the first redemption bought is revoked too. `replayed_at` also closes
			// the window between a redemption's burn and its `open_session`.
			sqlx::query("UPDATE rp_codes SET replayed_at = COALESCE(replayed_at, $2) WHERE code_hash = $1")
				.bind(claim.code_hash)
				.bind(claim.now)
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;
			let revoked = sqlx::query("UPDATE rp_sessions SET revoked_at = $2, revoked_reason = 'code_replay' WHERE code_hash = $1 AND revoked_at IS NULL")
				.bind(claim.code_hash)
				.bind(claim.now)
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?
				.rows_affected();
			tx.commit().await.map_err(repo_err)?;
			return Ok(CodeOutcome::Replayed {
				client_id: row.client_id,
				user: UserId::from_raw(row.user_id),
				revoked_sessions: revoked,
			});
		}

		// Burned on EVERY presentation, matching or not: a code is one attempt, so a thief
		// holding it without the verifier gets one guess and spends it for everybody.
		sqlx::query("UPDATE rp_codes SET redeemed_at = $2 WHERE code_hash = $1")
			.bind(claim.code_hash)
			.bind(claim.now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;

		if claim.now >= row.expires_at {
			return Ok(CodeOutcome::Expired);
		}
		// Plain `==` is enough here: none of these is secret from the presenter (the client
		// id and redirect are public, and the challenge was sent through the browser).
		if row.client_id != claim.client_id || row.redirect_uri != claim.redirect_uri || row.code_challenge != claim.challenge_of_verifier {
			return Ok(CodeOutcome::Mismatch);
		}
		Ok(CodeOutcome::Redeemed {
			user: UserId::from_raw(row.user_id),
			token_version: row.token_version as u64,
		})
	}

	async fn open_session(&self, session: NewSession<'_>) -> Result<bool, DomainError> {
		// `FOR SHARE` is what makes the two guards below hold: a replay (`claim_code`) or an
		// upstream sign-out (`revoke_upstream`) that has the code row locked but not yet
		// committed is WAITED for, and the row re-read after it — instead of this insert
		// reading the pre-commit version and opening a session nothing then revokes.
		let opened = sqlx::query(
			"INSERT INTO rp_sessions (id, client_id, user_id, code_hash, current_hash, token_version, upstream_family, created_at, last_used_at, expires_at, absolute_expires_at, client_ip, user_agent)
			 SELECT $1, $2, $3, $4, $5, $6, c.upstream_family, $7, $7, $8, $9, c.client_ip, c.user_agent
			 FROM rp_codes c WHERE c.code_hash = $4 AND c.replayed_at IS NULL AND c.expires_at > $7
			 FOR SHARE OF c",
		)
		.bind(session.id)
		.bind(session.client_id)
		.bind(session.user.raw())
		.bind(session.code_hash)
		.bind(session.secret_hash)
		.bind(session.token_version as i64)
		.bind(session.now)
		.bind(session.expires_at)
		.bind(session.absolute_expires_at)
		.execute(&self.pool)
		.await
		.map_err(repo_err)?
		.rows_affected();
		Ok(opened == 1)
	}

	async fn session(&self, id: Uuid) -> Result<Option<SessionRow>, DomainError> {
		let row: Option<SessionDbRow> =
			sqlx::query_as("SELECT client_id, user_id, current_hash, prev_hash, token_version, expires_at, absolute_expires_at, revoked_at FROM rp_sessions WHERE id = $1")
				.bind(id)
				.fetch_optional(&self.pool)
				.await
				.map_err(repo_err)?;
		Ok(row.map(|row| SessionRow {
			client_id: row.client_id,
			user: UserId::from_raw(row.user_id),
			current_hash: row.current_hash,
			prev_hash: row.prev_hash,
			token_version: row.token_version as u64,
			expires_at: row.expires_at,
			absolute_expires_at: row.absolute_expires_at,
			revoked: row.revoked_at.is_some(),
		}))
	}

	async fn rotate_session(&self, id: Uuid, presented_hash: &[u8], next_hash: &[u8], expires_at: i64, now: i64) -> Result<bool, DomainError> {
		// Conditional on the secret that was checked, so two concurrent rotations of one
		// token cannot both succeed: the loser sees 0 rows and is refused.
		let rotated = sqlx::query(
			"UPDATE rp_sessions SET prev_hash = current_hash, current_hash = $3, expires_at = LEAST($4, absolute_expires_at), last_used_at = $5
			 WHERE id = $1 AND current_hash = $2 AND revoked_at IS NULL",
		)
		.bind(id)
		.bind(presented_hash)
		.bind(next_hash)
		.bind(expires_at)
		.bind(now)
		.execute(&self.pool)
		.await
		.map_err(repo_err)?
		.rows_affected();
		Ok(rotated == 1)
	}

	async fn revoke_session(&self, id: Uuid, reason: SessionRevocation, now: i64) -> Result<(), DomainError> {
		sqlx::query("UPDATE rp_sessions SET revoked_at = $2, revoked_reason = $3 WHERE id = $1 AND revoked_at IS NULL")
			.bind(id)
			.bind(now)
			.bind(reason.as_str())
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	async fn revoke_upstream(&self, user: UserId, upstream_family: Option<&str>, now: i64) -> Result<u64, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// Codes FIRST, and every code of the family, spent or not: `open_session` takes
		// the code row `FOR SHARE` and requires it unexpired, so a redemption racing this
		// either lands before the sessions UPDATE below (which then sees it) or waits for
		// this commit and finds its code expired.
		sqlx::query("UPDATE rp_codes SET expires_at = LEAST(expires_at, $3) WHERE user_id = $1 AND ($2::TEXT IS NULL OR upstream_family = $2)")
			.bind(user.raw())
			.bind(upstream_family)
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		let revoked = sqlx::query(
			"UPDATE rp_sessions SET revoked_at = $3, revoked_reason = 'upstream_revoked'
			 WHERE user_id = $1 AND ($2::TEXT IS NULL OR upstream_family = $2) AND revoked_at IS NULL",
		)
		.bind(user.raw())
		.bind(upstream_family)
		.bind(now)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?
		.rows_affected();
		tx.commit().await.map_err(repo_err)?;
		Ok(revoked)
	}

	async fn session_live(&self, id: Uuid, audience: &str, now: i64) -> Result<bool, DomainError> {
		let live: Option<bool> = sqlx::query_scalar(
			"SELECT s.revoked_at IS NULL AND s.expires_at > $3 AND c.disabled_at IS NULL
			 FROM rp_sessions s JOIN rp_clients c USING (client_id)
			 WHERE s.id = $1 AND c.audience = $2",
		)
		.bind(id)
		.bind(audience)
		.bind(now)
		.fetch_optional(&self.pool)
		.await
		.map_err(repo_err)?;
		Ok(live.unwrap_or(false))
	}
}
