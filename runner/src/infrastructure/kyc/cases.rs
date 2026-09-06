//! Postgres adapter for [`KycCaseRepository`] — the `kyc_cases` table.
//!
//! Runtime queries (`sqlx::query*`, not the compile-time macros) keep `cargo build`
//! independent of a live database, matching the rest of the plane.

use async_trait::async_trait;
use domain::{error::DomainError, users::UserId};
use sqlx::PgPool;
use uuid::Uuid;

use crate::ports::{CaseDecision, KycCase, KycCaseRepository, KycDecision, KycStatus};

pub struct PgKycCases {
	pool: PgPool,
}

impl PgKycCases {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

/// Rehydrate the closed [`KycStatus`] from the column. A value the enum does not know
/// can only come from a hand-written UPDATE — the CHECK constraint and this adapter are
/// the only writers — so it is a repository error, not a status.
fn status_from_column(raw: &str) -> Result<KycStatus, DomainError> {
	const KNOWN: [KycStatus; 9] = [
		KycStatus::Pending,
		KycStatus::InProgress,
		KycStatus::InReview,
		KycStatus::Approved,
		KycStatus::Declined,
		KycStatus::Abandoned,
		KycStatus::Expired,
		KycStatus::NotFinished,
		KycStatus::KycExpired,
	];
	KNOWN
		.into_iter()
		.find(|s| s.as_str() == raw)
		.ok_or_else(|| DomainError::Repository(format!("kyc_cases.status holds an unknown value: {raw}")))
}

#[async_trait]
impl KycCaseRepository for PgKycCases {
	async fn open_case(&self, id: Uuid, user_id: UserId, provider: &str, provider_ref: &str, requested_tier: u32) -> Result<(), DomainError> {
		sqlx::query("INSERT INTO kyc_cases (id, user_id, provider, provider_ref, requested_tier, status) VALUES ($1, $2, $3, $4, $5, 'pending')")
			.bind(id)
			.bind(user_id.raw())
			.bind(provider)
			.bind(provider_ref)
			.bind(requested_tier as i32)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	/// One transaction: take the case `FOR UPDATE`, compare the stored status with the
	/// incoming one, and write only if it actually moves.
	///
	/// The lock is the idempotency, not a detail. Two redeliveries of the same event can
	/// arrive at two replicas at once; read outside a lock they would both see the old
	/// status, both call themselves a transition, and both apply the level — emitting two
	/// `KYC_CHANGED` rows onto the cross-plane outbox for one decision. Holding the row
	/// across the comparison makes the second one see the first's write and report
	/// [`CaseDecision::Redelivered`].
	async fn record_decision(&self, provider: &str, decision: &KycDecision) -> Result<CaseDecision, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;

		let row: Option<(Uuid, Uuid, i32, String)> = sqlx::query_as("SELECT id, user_id, requested_tier, status FROM kyc_cases WHERE provider = $1 AND provider_ref = $2 FOR UPDATE")
			.bind(provider)
			.bind(&decision.provider_ref)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;

		let Some((id, user_id, requested_tier, stored_status)) = row else {
			return Ok(CaseDecision::Unknown);
		};
		let stored = status_from_column(&stored_status)?;
		let case = KycCase {
			id,
			user_id: UserId::from_raw(user_id),
			requested_tier: requested_tier.max(0) as u32,
			status: decision.status,
		};

		if stored == decision.status {
			// Nothing to write: the transaction only ever held a read lock, so dropping it
			// here is the same as committing it.
			return Ok(CaseDecision::Redelivered(case));
		}

		// `decision_at` follows `is_decided` exactly, which is what the
		// `kyc_cases_decision_at` CHECK asserts — a disagreement fails the write rather
		// than leaving a row whose "still running?" has two answers.
		sqlx::query(
			"UPDATE kyc_cases SET status = $2, payload = $3, \
			 decision_at = CASE WHEN $4 THEN now() ELSE NULL END, updated_at = now() \
			 WHERE id = $1",
		)
		.bind(id)
		.bind(decision.status.as_str())
		.bind(&decision.metadata)
		.bind(decision.status.is_decided())
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;

		tx.commit().await.map_err(repo_err)?;
		Ok(CaseDecision::Recorded(case))
	}
}
