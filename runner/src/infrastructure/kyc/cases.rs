//! Postgres adapter for [`KycCaseRepository`] — the `kyc_cases` table.
//!
//! Runtime queries (`sqlx::query*`, not the compile-time macros) keep `cargo build`
//! independent of a live database, matching the rest of the plane.

use async_trait::async_trait;
use domain::{error::DomainError, users::UserId};
use sqlx::PgPool;
use uuid::Uuid;

use crate::ports::{CaseDecision, KycCase, KycCaseRepository, KycDecision, KycStatus, LiveCase, StartGate};

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
	KycStatus::ALL
		.into_iter()
		.find(|s| s.as_str() == raw)
		.ok_or_else(|| DomainError::Repository(format!("kyc_cases.status holds an unknown value: {raw}")))
}

/// The `status` values a case is still MOVING through, derived from the enum rather than
/// typed out: a running status missing from this list would read as finished, and the
/// user would be sold a second vendor session for the attempt they are already in.
fn running_statuses() -> Vec<&'static str> {
	KycStatus::ALL.into_iter().filter(|s| !s.is_decided()).map(KycStatus::as_str).collect()
}

#[async_trait]
impl KycCaseRepository for PgKycCases {
	async fn open_case(&self, id: Uuid, user_id: UserId, provider: &str, provider_ref: &str, requested_tier: u32, redirect_url: &str) -> Result<(), DomainError> {
		sqlx::query("INSERT INTO kyc_cases (id, user_id, provider, provider_ref, requested_tier, status, redirect_url) VALUES ($1, $2, $3, $4, $5, 'pending', $6)")
			.bind(id)
			.bind(user_id.raw())
			.bind(provider)
			.bind(provider_ref)
			.bind(requested_tier as i32)
			.bind(redirect_url)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	/// Two reads, both served by `kyc_cases_user_idx (user_id, created_at DESC)`.
	///
	/// Not one transaction, and not one statement, because neither would buy anything: the
	/// answer is stale the moment it is returned either way — the caller acts on it outside
	/// any database lock — and the guarantee this gate offers is a bound on volume. Mutual
	/// exclusion between two starts is the caller's, held in process around this read.
	/// Keeping them separate keeps each one a query a reader can check by eye.
	async fn start_gate(&self, user_id: UserId, window_secs: i64) -> Result<StartGate, DomainError> {
		let live = self.live_case(user_id).await?;

		let recent: i64 = sqlx::query_scalar("SELECT count(*) FROM kyc_cases WHERE user_id = $1 AND created_at > now() - make_interval(secs => $2)")
			.bind(user_id.raw())
			.bind(window_secs as f64)
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;

		Ok(StartGate { live, recent })
	}

	/// `created_at` leaves Postgres as epoch seconds rather than a timestamp: it is
	/// answered to a browser, and converting here keeps the one time format this plane
	/// publishes from depending on which type the adapter happened to bind.
	async fn live_case(&self, user_id: UserId) -> Result<Option<LiveCase>, DomainError> {
		let row: Option<(Uuid, Option<String>, String, i32, i64)> = sqlx::query_as(
			"SELECT id, redirect_url, status, requested_tier, EXTRACT(EPOCH FROM created_at)::bigint \
			 FROM kyc_cases WHERE user_id = $1 AND status = ANY($2) ORDER BY created_at DESC LIMIT 1",
		)
		.bind(user_id.raw())
		.bind(running_statuses())
		.fetch_optional(&self.pool)
		.await
		.map_err(repo_err)?;

		row.map(|(id, redirect_url, status, requested_tier, created_at)| {
			Ok(LiveCase {
				id,
				redirect_url,
				status: status_from_column(&status)?,
				requested_tier: requested_tier.max(0) as u32,
				created_at,
			})
		})
		.transpose()
	}

	async fn approved_cover(&self, user_id: UserId, excluding: Uuid) -> Result<Option<u32>, DomainError> {
		let row: Option<(Option<i32>,)> = sqlx::query_as("SELECT max(requested_tier) FROM kyc_cases WHERE user_id = $1 AND id <> $2 AND status = $3")
			.bind(user_id.raw())
			.bind(excluding)
			.bind(KycStatus::Approved.as_str())
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)?;

		Ok(row.and_then(|(tier,)| tier).map(|tier| tier.max(0) as u32))
	}

	/// One transaction: take the case `FOR UPDATE`, judge the incoming verdict against
	/// the stored one, and write only if it actually moves the case FORWARD.
	///
	/// The lock is the idempotency, not a detail. Two redeliveries of the same event can
	/// arrive at two replicas at once; read outside a lock they would both see the old
	/// status, both call themselves a transition, and both apply the level — emitting two
	/// `KYC_CHANGED` rows onto the cross-plane outbox for one decision. Holding the row
	/// across the comparison makes the second one see the first's write and report
	/// [`CaseDecision::Redelivered`].
	///
	/// "Different status ⇒ write it" is NOT enough, which is what `event_at` is here for.
	/// Deliveries do not arrive in the order they were sent — Didit retries at roughly one
	/// and four minutes — so the last packet to land is not the vendor's latest word. The
	/// stored signed instant is what makes the outcome depend on what was decided rather
	/// than on which retry won the race.
	async fn record_decision(&self, provider: &str, decision: &KycDecision) -> Result<CaseDecision, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;

		let row: Option<(Uuid, Uuid, i32, String, Option<i64>)> =
			sqlx::query_as("SELECT id, user_id, requested_tier, status, event_at FROM kyc_cases WHERE provider = $1 AND provider_ref = $2 FOR UPDATE")
				.bind(provider)
				.bind(&decision.provider_ref)
				.fetch_optional(&mut *tx)
				.await
				.map_err(repo_err)?;

		let Some((id, user_id, requested_tier, stored_status, stored_at)) = row else {
			return Ok(CaseDecision::Unknown);
		};
		let stored = status_from_column(&stored_status)?;
		let case = |status| KycCase {
			id,
			user_id: UserId::from_raw(user_id),
			requested_tier: requested_tier.max(0) as u32,
			status,
		};

		// The cross-check, before anything is judged and long before anything is written.
		// `vendor_data` is the correlation value WE handed the vendor, echoed back through
		// a body an attacker also controls, so it can never SELECT a case — it can only
		// disagree with the one `provider_ref` already found, and a disagreement means the
		// two ends are talking about different things. It used to be compared by the
		// handler on the case this method returned, which is to say after the commit: the
		// delivery was refused with a 400 and its status kept (#54).
		//
		// An EMPTY value stays exempt, and that is a real exemption rather than a pass: a
		// vendor that never echoes the field would otherwise have every delivery refused,
		// and the field is not what authenticates a delivery — the HMAC is, and this row
		// was found by the vendor's own session id.
		if !decision.vendor_data.is_empty() && decision.vendor_data != id.to_string() {
			return Ok(CaseDecision::Mismatch(case(stored)));
		}

		if stored == decision.status {
			// Nothing to write: the transaction only ever held a read lock, so dropping it
			// here is the same as committing it.
			return Ok(CaseDecision::Redelivered(case(decision.status)));
		}

		// STRICTLY older only. Equal seconds still transition: the vendor stamps whole
		// seconds, and `in_review` → `approved` inside one of them is an ordinary flow —
		// dropping it would cost a real user their level to save a tie-break nobody needs.
		// A replay cannot exploit that: to be judged here at all a delivery must already
		// have carried a valid signature over a body whose own timestamp sits inside the
		// 300-second window, and a replayed OLDER verdict is refused by this very check.
		//
		// A NULL `stored_at` is a case last written before that column existed. It means
		// "no ordering evidence", not "the beginning of time", so it allows the
		// transition — the behaviour these rows were written under.
		if stored_at.is_some_and(|at| decision.signed_at < at) {
			return Ok(CaseDecision::Ignored(case(stored)));
		}

		// A finished case never goes back to running. The timestamp check above cannot
		// cover this one: a genuine `in_review` retry can carry a LATER stamp than the
		// `approved` that superseded it when the vendor re-sends the older event after
		// deciding. Reopening would clear `decision_at`, so the row would stop claiming
		// the outcome the user's level was granted on — an audit trail contradicting the
		// account it explains. Decided → decided stays allowed: `approved` → `kyc_expired`
		// is a real vendor transition, and it moves no level down, since only an approval
		// grants one at all.
		if stored.is_decided() && !decision.status.is_decided() {
			return Ok(CaseDecision::Ignored(case(stored)));
		}

		// `decision_at` follows `is_decided` exactly, which is what the
		// `kyc_cases_decision_at` CHECK asserts — a disagreement fails the write rather
		// than leaving a row whose "still running?" has two answers.
		sqlx::query(
			"UPDATE kyc_cases SET status = $2, payload = $3, \
			 decision_at = CASE WHEN $4 THEN now() ELSE NULL END, event_at = $5, updated_at = now() \
			 WHERE id = $1",
		)
		.bind(id)
		.bind(decision.status.as_str())
		.bind(&decision.metadata)
		.bind(decision.status.is_decided())
		.bind(decision.signed_at)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;

		tx.commit().await.map_err(repo_err)?;
		Ok(CaseDecision::Recorded(case(decision.status)))
	}
}
