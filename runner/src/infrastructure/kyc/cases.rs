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
		let live: Option<(Uuid, Option<String>)> = sqlx::query_as("SELECT id, redirect_url FROM kyc_cases WHERE user_id = $1 AND status = ANY($2) ORDER BY created_at DESC LIMIT 1")
			.bind(user_id.raw())
			.bind(running_statuses())
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)?;

		let recent: i64 = sqlx::query_scalar("SELECT count(*) FROM kyc_cases WHERE user_id = $1 AND created_at > now() - make_interval(secs => $2)")
			.bind(user_id.raw())
			.bind(window_secs as f64)
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;

		Ok(StartGate {
			live: live.map(|(id, redirect_url)| LiveCase { id, redirect_url }),
			recent,
		})
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

		// ONE PERSON, N ACCOUNTS (#51). Asked here — inside the transaction that holds
		// this case, and BEFORE the status that would grant a level is written — because
		// it is the last point at which the answer can still change what happens. The
		// scenario needs no forgery: somebody registers several accounts and honestly
		// verifies each with their own real passport, so every check the vendor runs
		// passes and every account reaches level >= 1.
		//
		// The duplicate is not REFUSED. The honest explanations are real — a person who
		// lost an account and made another, a shared device, a family — and an automatic
		// rejection would lock those people out with no recourse and no human involved.
		// So the verdict is recorded as `held_duplicate`: no level moves, an operator is
		// alarmed, and the user is told the attempt needs a look.
		//
		// `held_duplicate` and NOT `in_review`, which is what this started as. `in_review`
		// is a RUNNING status, and writing one here broke two things at once. It cleared
		// `decision_at` on a case the vendor had already decided — a `declined` case
		// re-delivered as `approved` came out of this branch running again, contradicting
		// the guard twenty lines above that exists to stop exactly that. And a running
		// case is a case `start_gate` keeps handing back, so `/kyc/start` would return the
		// spent vendor session for ever: no new attempt, no vendor event that could move
		// the row, and no operator handle in this plane that closes a case. A decided hold
		// leaves the user free to start again and the operator free to raise the level
		// with `SetKycLevel` once they have looked.
		//
		// Skipped entirely when no digest was computed (no `KYC_IDENTITY_PEPPER`, or a
		// verdict carrying no document number). Detection degrades; the decision does not.
		let mut status = decision.status;
		if status == KycStatus::Approved
			&& let Some(digest) = decision.identity_digest.as_deref()
		{
			// Serialised per DOCUMENT, and without it the question below is worth little.
			// The row lock taken at the top covers THIS case and nothing else, so two
			// verdicts on two accounts presenting the same document do not exclude each
			// other: under READ COMMITTED neither sees the other's uncommitted row, both
			// find no twin and both grant a level — and since the check only ever runs on
			// a status transition, nothing looks again afterwards. There is no unique
			// index to fall back on, deliberately (0021 says why), so this lock is the
			// mutual exclusion.
			//
			// Every transaction that takes both locks takes the case row first and this
			// one second, so the acquisition order is the same everywhere and no wait
			// cycle can form. `_xact_` — it is released by the COMMIT below, or by the
			// rollback, and never outlives a connection returned to the pool.
			sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
				.bind(digest)
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;

			// "Has this document already BOUGHT somebody else a level" — asked as TWO
			// facts OR-ed together, and the pair is the whole point.
			//
			// `u.kyc_level >= 1` alone is not enough, and that is not a refinement: it is
			// the hole this branch exists to close, left open. The level is written by a
			// DIFFERENT transaction on a different connection — `web::kyc::apply` →
			// `UserDirectoryRepository::raise_kyc_level_to` — which only begins once THIS
			// one has committed. The advisory lock above is released by that same commit,
			// so the twin waiting on it wakes precisely inside the window where the first
			// account's case says `approved` and its account still says 0, reads the
			// level, finds nothing, and is approved too. The lock does not close that; it
			// aims the second verdict straight at it.
			//
			// The same gap without any concurrency, and permanent: `apply` failing
			// between the two writes (a 5xx, a pod rolled) leaves an `approved` case at
			// level 0 — a state this plane treats as ordinary and repairs on redelivery —
			// and Didit retries twice before giving up. For as long as it lasted, a
			// level-only question would have protected that document from nothing.
			//
			// `c.status = approved` alone is not enough either, for the reason the level
			// was asked about in the first place: a case LEAVES `approved` by routes the
			// vendor drives on its own — `approved` → `kyc_expired` when a verification
			// ages out, `approved` → `declined` on a post-hoc review — and neither takes
			// the level back down, because only a human under `KycManage` ever lowers
			// one. So the status arm covers the verdict this plane has already recorded,
			// committed but not yet applied included, and the level arm covers the grant
			// that outlived the verdict which bought it.
			//
			// A level an OPERATOR granted counts too: the join asks what the account
			// holds, not where it came from. That errs towards a human looking at a case,
			// which is the direction this whole branch errs in.
			let twin: Option<Uuid> = sqlx::query_scalar(
				"SELECT c.user_id FROM kyc_cases c JOIN users u ON u.id = c.user_id \
				 WHERE c.identity_digest = $1 AND c.user_id <> $2 AND c.decision_at IS NOT NULL \
				 AND (c.status = $3 OR u.kyc_level >= 1) LIMIT 1",
			)
			.bind(digest)
			.bind(user_id)
			.bind(KycStatus::Approved.as_str())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
			if let Some(twin) = twin {
				status = KycStatus::HeldDuplicate;
				// A redelivery of the verdict we already held. Didit retries at roughly
				// one and four minutes, and each retry re-enters this branch: without
				// this it would rewrite the same row and raise the same alarm again for a
				// decision already taken.
				if stored == status {
					return Ok(CaseDecision::Redelivered(case(status)));
				}
				// `error!` because `error_monitoring::tracing_layer()` forwards it to
				// Sentry, which is the only channel here that reaches a person rather
				// than a log nobody reads. The digest is NOT logged: it is the one
				// cross-account handle this plane holds, and a log aggregator is not
				// where it belongs.
				tracing::error!(
					case_id = %id,
					%user_id,
					twin_user_id = %twin,
					"kyc: this document has already raised the level of a different account — the verdict is held and no level was raised"
				);
			}
		}

		// `decision_at` follows `is_decided` exactly, which is what the
		// `kyc_cases_decision_at` CHECK asserts — a disagreement fails the write rather
		// than leaving a row whose "still running?" has two answers.
		//
		// `identity_digest` is written with COALESCE so a later verdict that carries no
		// document number — or one recorded after the pepper was unset — cannot erase the
		// fingerprint an earlier verdict on the same case established.
		sqlx::query(
			"UPDATE kyc_cases SET status = $2, payload = $3, \
			 decision_at = CASE WHEN $4 THEN now() ELSE NULL END, event_at = $5, \
			 identity_digest = COALESCE($6, identity_digest), updated_at = now() \
			 WHERE id = $1",
		)
		.bind(id)
		.bind(status.as_str())
		.bind(&decision.metadata)
		.bind(status.is_decided())
		.bind(decision.signed_at)
		.bind(decision.identity_digest.as_deref())
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;

		tx.commit().await.map_err(repo_err)?;
		Ok(CaseDecision::Recorded(case(status)))
	}
}
