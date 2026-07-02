//! Driven ports — the outbound interfaces the runner's services depend on,
//! implemented by `infrastructure`. The hexagonal "domain/port" layer over the
//! generic DDD building blocks in [`domain::architecture`], mirroring banking.
//!
//! [`UserDirectoryRepository`] ties the [`User`] aggregate to its Postgres
//! persistence and the narrow read side ([`Reader`]). Methods are use-case-shaped
//! and each is internally atomic — the aggregate's drained lifecycle events are
//! written to the cross-plane `user_outbox` in the same transaction as the state
//! change (the ACID point), so callers never juggle a transaction across the port
//! boundary. [`PlatformConfigRepository`] is the plain-config port for the
//! platform/cabinet control surface (no aggregate, so no kernel markers).

use async_trait::async_trait;
use domain::{
	architecture::{Reader, Repository},
	authz::Role,
	error::DomainError,
	users::{AuthSubject, Email, ProfileFields, User, UserId},
};

use crate::infrastructure::{
	platform::{FeatureFlagRow, PlatformConfigRow},
	users::{AdminUserRow, AuthzRecord},
};

/// Persistence + read port for the [`User`] aggregate (the identity control plane).
#[async_trait]
pub trait UserDirectoryRepository: Repository<Aggregate = User> + Reader<Aggregate = User> {
	/// Find a user by canonical id.
	async fn find_by_id(&self, id: UserId) -> Result<Option<User>, DomainError>;

	/// Upsert by the immutable [`AuthSubject`] at sign-in: create (emitting `CREATED`)
	/// or refresh the email. Idempotent for concurrent first-logins.
	async fn provision(&self, subject: AuthSubject, email: Email, email_verified: bool) -> Result<User, DomainError>;

	/// Full-replace the caller's editable profile fields.
	async fn update_profile(&self, id: UserId, fields: ProfileFields) -> Result<User, DomainError>;

	/// Bump the user's authoritative `token_version` ("revoke all"); emits SESSIONS_REVOKED.
	async fn revoke_tokens(&self, id: UserId) -> Result<User, DomainError>;

	/// Disable a user (freeze sign-in/refresh); emits SUSPENDED.
	async fn disable_user(&self, id: UserId) -> Result<User, DomainError>;

	/// Re-enable a disabled user; emits REINSTATED.
	async fn enable_user(&self, id: UserId) -> Result<User, DomainError>;

	/// Set a user's KYC level; emits KYC_CHANGED.
	async fn set_kyc_level(&self, id: UserId, level: u32) -> Result<User, DomainError>;

	/// Set a user's platform access role; emits ROLE_CHANGED across the bridge.
	async fn set_role(&self, id: UserId, role: Role) -> Result<User, DomainError>;

	/// The role + status + authoritative `token_version` the authz gates decide on.
	/// `None` when the user does not exist.
	async fn authz_record(&self, id: UserId) -> Result<Option<AuthzRecord>, DomainError>;

	/// The operator console's user list: filtered + paginated summaries plus the total
	/// matching the filters.
	async fn list(&self, query: &str, role: &str, status: &str, limit: i64, offset: i64) -> Result<(Vec<AdminUserRow>, i64), DomainError>;
}

/// Port for the platform/cabinet control config (maintenance mode, announcement
/// banner, feature flags) — plain config state, not a domain aggregate.
#[async_trait]
pub trait PlatformConfigRepository: Send + Sync {
	async fn config(&self) -> Result<PlatformConfigRow, DomainError>;

	async fn flags(&self) -> Result<Vec<FeatureFlagRow>, DomainError>;

	async fn set_maintenance(&self, enabled: bool) -> Result<(), DomainError>;

	async fn set_announcement(&self, title: &str, body: &str, active: bool) -> Result<(), DomainError>;

	async fn upsert_flag(&self, key: &str, description: &str, enabled: bool, rollout: i32) -> Result<(), DomainError>;
}
