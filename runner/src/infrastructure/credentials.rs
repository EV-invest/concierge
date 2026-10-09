//! Postgres adapter for the credentials this plane checks itself: emailed one-time codes
//! (and passwords, beside them). The code shape is the consilium self-decision code's: a
//! digest at rest, attempts counted before the comparison in the same transaction, burned
//! on the last wrong guess, compared in constant time. The plaintext lives only in the
//! queued mail's payload, which the dispatcher strikes once the mail is sent or parked.

use async_trait::async_trait;
use domain::{
	error::DomainError,
	users::{AuthSubject, Email, User, UserId},
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::users::{Named, account_named, drain_outbox, free_username, insert_user, load_for_update, lock_email, update_row, verified_holder};
use crate::ports::{
	CODE_MAX_ATTEMPTS, CODE_SEND_WINDOW_SECS, CODE_SENDS_PER_WINDOW, CODE_TTL_SECS, CodeIssue, CodePurpose, CodeRefusal, CredentialRepository, PASSWORD_LOCK_SECS, PASSWORD_MAX_FAILURES,
	SignInMethods, SignUp, StoredPassword, VerifyRefusal,
};

pub struct PgCredentials {
	pool: PgPool,
}

impl PgCredentials {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

/// Six uniform digits. Rejection sampling, so no code is likelier than another.
fn six_digits() -> String {
	const SPAN: u32 = 1_000_000;
	let limit = u32::MAX - u32::MAX % SPAN;
	loop {
		let mut bytes = [0u8; 4];
		getrandom::fill(&mut bytes).expect("CSPRNG unavailable");
		let n = u32::from_le_bytes(bytes);
		if n < limit {
			return format!("{:06}", n % SPAN);
		}
	}
}

/// Bound to the row, so equal codes on two rows never share a digest.
fn digest(id: Uuid, code: &str) -> Vec<u8> {
	let mut hasher = Sha256::new();
	hasher.update(id.as_bytes());
	hasher.update(code.as_bytes());
	hasher.finalize().to_vec()
}

#[derive(sqlx::FromRow)]
struct CodeRow {
	id: Uuid,
	code_hash: Vec<u8>,
	expires_at: i64,
	attempts: i32,
	burned_at: Option<i64>,
}

/// Spend the live code sent to `email` for `purpose` (and `user`, for a verification).
/// Issuing one burns its predecessors, so there is at most one to compare against.
async fn redeem(conn: &mut PgConnection, email: &Email, purpose: &str, user: Option<UserId>, code: &str, now: i64) -> Result<Result<(), CodeRefusal>, DomainError> {
	let Some(row) = sqlx::query_as::<_, CodeRow>(
		"SELECT id, code_hash, expires_at, attempts, burned_at FROM email_codes \
		 WHERE email = $1 AND purpose = $2 AND user_id IS NOT DISTINCT FROM $3 \
		 ORDER BY burned_at IS NULL DESC, created_at DESC LIMIT 1 FOR UPDATE",
	)
	.bind(email.as_str())
	.bind(purpose)
	.bind(user.map(|u| u.raw()))
	.fetch_optional(&mut *conn)
	.await
	.map_err(repo_err)?
	else {
		return Ok(Err(CodeRefusal::Missing));
	};
	if row.burned_at.is_some() {
		return Ok(Err(if row.attempts >= CODE_MAX_ATTEMPTS { CodeRefusal::Exhausted } else { CodeRefusal::Missing }));
	}
	if row.expires_at <= now {
		return Ok(Err(CodeRefusal::Expired));
	}
	let attempts = row.attempts + 1;
	let presented = digest(row.id, code.trim());
	let matches = presented.len() == row.code_hash.len() && bool::from(presented.ct_eq(&row.code_hash));
	let burned = matches || attempts >= CODE_MAX_ATTEMPTS;
	sqlx::query("UPDATE email_codes SET attempts = $2, burned_at = $3 WHERE id = $1")
		.bind(row.id)
		.bind(attempts)
		.bind(burned.then_some(now))
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(match (matches, burned) {
		(true, _) => Ok(()),
		(false, true) => Err(CodeRefusal::Exhausted),
		(false, false) => Err(CodeRefusal::Wrong),
	})
}

/// The account's address, read WITHOUT the row lock: the email lock comes first, here as
/// in `resolve`, or the two would deadlock each other.
async fn email_of(conn: &mut PgConnection, user: UserId) -> Result<Email, DomainError> {
	let raw: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound {
			entity: "user",
			id: user.to_string(),
		})?;
	Email::parse(&raw)
}

#[async_trait]
impl CredentialRepository for PgCredentials {
	async fn issue_code(&self, purpose: CodePurpose, now: i64) -> Result<CodeIssue, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let (email, purpose, user) = match purpose {
			CodePurpose::Login(email) => (email, "login", None),
			CodePurpose::Verify(user) => (email_of(&mut tx, user).await?, "verify", Some(user)),
		};
		lock_email(&mut tx, &email).await?;
		let recent: i64 = sqlx::query_scalar("SELECT count(*) FROM email_codes WHERE email = $1 AND created_at > $2")
			.bind(email.as_str())
			.bind(now - CODE_SEND_WINDOW_SECS)
			.fetch_one(&mut *tx)
			.await
			.map_err(repo_err)?;
		if recent >= CODE_SENDS_PER_WINDOW {
			return Ok(CodeIssue::Throttled);
		}
		sqlx::query("UPDATE email_codes SET burned_at = $4 WHERE email = $1 AND purpose = $2 AND user_id IS NOT DISTINCT FROM $3 AND burned_at IS NULL")
			.bind(email.as_str())
			.bind(purpose)
			.bind(user.map(|u| u.raw()))
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		let id = Uuid::new_v4();
		let code = six_digits();
		let expires_at = now + CODE_TTL_SECS;
		sqlx::query("INSERT INTO email_codes (id, email, purpose, user_id, code_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
			.bind(id)
			.bind(email.as_str())
			.bind(purpose)
			.bind(user.map(|u| u.raw()))
			.bind(digest(id, &code))
			.bind(expires_at)
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		sqlx::query("INSERT INTO notification_deliveries (kind, recipient, dedupe_key, payload) VALUES ('email_code', $1, $2, $3)")
			.bind(email.as_str())
			.bind(format!("email_code:{id}"))
			.bind(serde_json::json!({ "purpose": purpose, "code": code, "expires_at": expires_at }))
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;
		Ok(CodeIssue::Sent)
	}

	async fn redeem_login_code(&self, email: &Email, code: &str, now: i64) -> Result<Result<(), CodeRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let outcome = redeem(&mut tx, email, "login", None, code, now).await?;
		// Committed whatever the outcome: a wrong guess must stay counted.
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn verify_email(&self, user: UserId, code: &str, now: i64) -> Result<Result<User, VerifyRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let outcome = verify_with_code(&mut tx, user, code, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn sign_up(&self, email: &Email, phc: String, now: i64) -> Result<SignUp, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_email(&mut tx, email).await?;
		let backs_password: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users u JOIN password_credentials p ON p.user_id = u.id WHERE lower(u.email) = $1)")
			.bind(email.as_str())
			.fetch_one(&mut *tx)
			.await
			.map_err(repo_err)?;
		if backs_password || verified_holder(&mut tx, email).await?.is_some() {
			return Ok(SignUp::Taken);
		}
		let id = UserId::new();
		let user = User::provision(id, AuthSubject::parse(&id.to_string())?, email.clone(), false, free_username(&mut tx, email).await?);
		let mut user = insert_user(&mut tx, user).await?;
		write_password(&mut tx, id, &phc, now).await?;
		drain_outbox(&mut tx, &mut user).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(SignUp::Created(Box::new(user)))
	}

	async fn password_named(&self, handle: &str) -> Result<Option<StoredPassword>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let Named::One(user) = account_named(&mut conn, handle).await? else {
			return Ok(None);
		};
		let row: Option<(String, Option<i64>)> = sqlx::query_as("SELECT phc, locked_until FROM password_credentials WHERE user_id = $1")
			.bind(user.raw())
			.fetch_optional(&mut *conn)
			.await
			.map_err(repo_err)?;
		Ok(row.map(|(phc, locked_until)| StoredPassword { user, phc, locked_until }))
	}

	async fn record_password_attempt(&self, user: UserId, succeeded: bool, now: i64) -> Result<(), DomainError> {
		let query = match succeeded {
			true => sqlx::query("UPDATE password_credentials SET failed_attempts = 0, locked_until = NULL WHERE user_id = $1").bind(user.raw()),
			false => sqlx::query(
				"UPDATE password_credentials SET \
				 locked_until = CASE WHEN failed_attempts + 1 >= $2 THEN $3 + $4 ELSE locked_until END, \
				 failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END \
				 WHERE user_id = $1",
			)
			.bind(user.raw())
			.bind(PASSWORD_MAX_FAILURES)
			.bind(now)
			.bind(PASSWORD_LOCK_SECS),
		};
		query.execute(&self.pool).await.map_err(repo_err)?;
		Ok(())
	}

	async fn methods(&self, user: UserId) -> Result<SignInMethods, DomainError> {
		let password: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM password_credentials WHERE user_id = $1)")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		let providers = sqlx::query_scalar("SELECT provider FROM user_identities WHERE user_id = $1 ORDER BY provider")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(SignInMethods { password, providers })
	}

	async fn set_password(&self, user: UserId, code: &str, phc: String, now: i64) -> Result<Result<(), VerifyRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let outcome = verify_with_code(&mut tx, user, code, now).await?;
		if outcome.is_ok() {
			write_password(&mut tx, user, &phc, now).await?;
		}
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome.map(|_| ()))
	}
}

/// Spend a verification code and mark the account's address verified. The caller commits
/// whatever the outcome: a wrong guess must stay counted.
async fn verify_with_code(conn: &mut PgConnection, user: UserId, code: &str, now: i64) -> Result<Result<User, VerifyRefusal>, DomainError> {
	let email = email_of(conn, user).await?;
	lock_email(conn, &email).await?;
	if let Err(refusal) = redeem(conn, &email, "verify", Some(user), code, now).await? {
		return Ok(Err(VerifyRefusal::Code(refusal)));
	}
	if verified_holder(conn, &email).await?.is_some_and(|holder| holder != user) {
		return Ok(Err(VerifyRefusal::Taken));
	}
	let mut account = load_for_update(conn, user).await?;
	// Moved between the read and the lock: the code proved the old address.
	if *account.email() != email {
		return Ok(Err(VerifyRefusal::Code(CodeRefusal::Missing)));
	}
	account.verify_email();
	update_row(conn, &account).await?;
	Ok(Ok(account))
}

async fn write_password(conn: &mut PgConnection, user: UserId, phc: &str, now: i64) -> Result<(), DomainError> {
	sqlx::query(
		"INSERT INTO password_credentials (user_id, phc, updated_at) VALUES ($1, $2, $3) \
		 ON CONFLICT (user_id) DO UPDATE SET phc = EXCLUDED.phc, failed_attempts = 0, locked_until = NULL, updated_at = EXCLUDED.updated_at",
	)
	.bind(user.raw())
	.bind(phc)
	.bind(now)
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn codes_are_six_digits_and_digests_are_bound_to_their_row() {
		for _ in 0..1000 {
			let code = six_digits();
			assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()), "{code}");
		}
		let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
		assert_ne!(digest(a, "123456"), digest(b, "123456"));
		assert_eq!(digest(a, "123456").len(), 32);
	}
}
