//! `users` bounded context — the platform's canonical identity record.
//!
//! The [`User`] aggregate is `concierge`'s record of a person: provisioned on
//! first sign-in and kept in sync with the session-auth identity. It is
//! **identity-only** — it holds no money, balances, or subscriptions (those are
//! the banking money plane's concern, reached one-way over the cross-plane bridge).
//!
//! Mutating transitions accumulate [`UserEvent`]s; the persistence adapter drains
//! them into the cross-plane `user_outbox` in the same transaction as the state
//! change (the one ACID point), stamping each with the new `row_version` as the
//! bridge `sequence`.
//!
//! Pure and wasm-safe: no crypto, no I/O, no clock reads. Identities are supplied
//! by the (host-only) application layer, so this stays compilable to wasm and
//! trivially testable.

use ev::architecture::{AggregateRoot, DomainEvent, EmitsEvents, Entity, Id};
use serde::{Deserialize, Serialize};

// Re-exported so existing `domain::users::AuthSubject` paths keep working; the type
// itself lives in the `auth` bounded context (mirroring banking).
pub use crate::auth::AuthSubject;
use crate::{authz::Role, error::DomainError};

/// The platform's canonical user id (a UUID). **This** value is the `sub` of the
/// first-party session JWT — never the IdP's `sub` (see [`AuthSubject`]).
pub type UserId = Id<UserTag>;
/// Phantom tag making [`UserId`] a distinct, incompatible identity type.
pub struct UserTag;

/// A user email. Parse-don't-validate: lowercased and trimmed on construction, so
/// equality and the storage form are normalized. Deliberately **not** a unique key —
/// a person may change the email behind a stable [`AuthSubject`]. Serializes
/// transparently as the bare string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Email(String);

impl Email {
	/// Normalize and minimally check an email. Full validation is the IdP's job
	/// (Google has already verified deliverability); this only guards against an
	/// obviously malformed value reaching the aggregate.
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		let normalized = raw.trim().to_lowercase();
		if normalized.len() < 3 || !normalized.contains('@') {
			return Err(DomainError::Validation("email must contain '@'".into()));
		}
		Ok(Self(normalized))
	}

	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl core::fmt::Display for Email {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.write_str(&self.0)
	}
}

/// The minimal user lifecycle. `Disabled` freezes sign-in/refresh without deleting
/// the record (the audit trail must outlive a deactivation).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
	Active,
	Disabled,
}

impl UserStatus {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Active => "active",
			Self::Disabled => "disabled",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"active" => Ok(Self::Active),
			"disabled" => Ok(Self::Disabled),
			other => Err(DomainError::Validation(format!("unknown user status: {other}"))),
		}
	}
}

/// The caller's editable profile fields (the full-replace set). All optional —
/// `None`/an empty value clears the field. Identity/auth fields (email, status) are
/// deliberately absent: they are not user-editable here.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileFields {
	pub legal_name: Option<String>,
	pub preferred_name: Option<String>,
	pub phone: Option<String>,
	pub date_of_birth: Option<String>,
	pub nationality: Option<String>,
	pub tax_residence: Option<String>,
	pub residential_address: Option<String>,
	pub language: Option<String>,
	pub base_currency: Option<String>,
	pub timezone: Option<String>,
}

/// The platform's canonical user identity. Construct it with [`User::provision`]
/// (first sign-in, raises [`UserEvent::Provisioned`]) or [`User::rehydrate`] (load
/// from the store, no events). Mutating transitions accumulate [`UserEvent`]s drained
/// by the adapter into the cross-plane outbox in the same unit of work.
#[derive(Clone, Debug)]
pub struct User {
	id: UserId,
	auth_subject: AuthSubject,
	email: Email,
	email_verified: bool,
	status: UserStatus,
	token_version: u64,
	kyc_level: u32,
	/// The platform-wide access role. This plane OWNS it; a change is mirrored to the
	/// banking money plane over the bridge ([`UserEvent::RoleChanged`]).
	role: Role,
	profile: ProfileFields,
	/// Per-user mutation counter; the bridge `sequence`. Bumped on every mutation,
	/// and stamped onto each emitted event by the adapter.
	row_version: u64,
	pending: Vec<UserEvent>,
}

impl User {
	/// Provision a brand-new user at first sign-in. The application layer mints the
	/// [`UserId`] (host-only), keeping this pure.
	pub fn provision(id: UserId, auth_subject: AuthSubject, email: Email, email_verified: bool) -> Self {
		let mut user = Self {
			id,
			auth_subject,
			email,
			email_verified,
			status: UserStatus::Active,
			token_version: 0,
			kyc_level: 0,
			role: Role::default(),
			profile: ProfileFields::default(),
			row_version: 0,
			pending: Vec::new(),
		};
		user.bump_and_emit(UserEvent::Created);
		user
	}

	/// Reconstitute an existing user from the store, including the editable profile
	/// and the current `row_version`. Raises no events.
	#[allow(clippy::too_many_arguments)]
	pub fn rehydrate(
		id: UserId,
		auth_subject: AuthSubject,
		email: Email,
		email_verified: bool,
		status: UserStatus,
		token_version: u64,
		kyc_level: u32,
		role: Role,
		profile: ProfileFields,
		row_version: u64,
	) -> Self {
		Self {
			id,
			auth_subject,
			email,
			email_verified,
			status,
			token_version,
			kyc_level,
			role,
			profile,
			row_version,
			pending: Vec::new(),
		}
	}

	/// Update the email (and its verified flag) to the IdP's current value. No-op
	/// (and no event) when unchanged, so a routine sign-in does not churn outbox rows.
	///
	/// An already-verified stored email is never overwritten by an unverified one: a
	/// principal whose IdP `sub` later carries an unverified (or attacker-influenced)
	/// email must not be able to downgrade the account's verified address.
	pub fn change_email(&mut self, email: Email, email_verified: bool) {
		if self.email_verified && !email_verified {
			return;
		}
		if self.email == email && self.email_verified == email_verified {
			return;
		}
		self.email = email;
		self.email_verified = email_verified;
		// An email change carries no distinct bridge Kind; banking re-reads the email
		// snapshot on the next lifecycle event, so this mutation bumps row_version
		// without emitting an outbox row.
		self.row_version += 1;
	}

	/// Full-replace the editable profile fields. Raises no cross-plane event — profile
	/// metadata is the identity plane's own concern and the money plane does not gate on
	/// it — but still bumps `row_version` so the per-user sequence stays monotonic.
	pub fn update_profile(&mut self, fields: ProfileFields) {
		self.profile = fields;
		self.row_version += 1;
	}

	/// Bump `token_version`, invalidating every outstanding token for this user
	/// ("revoke all"). Returns the new version and emits [`UserEvent::SessionsRevoked`].
	pub fn revoke_tokens(&mut self) -> u64 {
		self.token_version += 1;
		self.bump_and_emit(UserEvent::SessionsRevoked);
		self.token_version
	}

	/// Disable the user, freezing future sign-in/refresh, and emit
	/// [`UserEvent::Suspended`]. No-op when already disabled.
	pub fn disable(&mut self) {
		if self.status == UserStatus::Disabled {
			return;
		}
		self.status = UserStatus::Disabled;
		self.bump_and_emit(UserEvent::Suspended);
	}

	/// Re-enable a disabled user and emit [`UserEvent::Reinstated`]. No-op when already
	/// active.
	pub fn enable(&mut self) {
		if self.status == UserStatus::Active {
			return;
		}
		self.status = UserStatus::Active;
		self.bump_and_emit(UserEvent::Reinstated);
	}

	/// Set the KYC level and emit [`UserEvent::KycChanged`]. No-op when unchanged.
	pub fn set_kyc_level(&mut self, level: u32) {
		if self.kyc_level == level {
			return;
		}
		self.kyc_level = level;
		self.bump_and_emit(UserEvent::KycChanged);
	}

	/// Set the platform access role and emit [`UserEvent::RoleChanged`] (the money plane
	/// mirrors it over the bridge). No-op when unchanged, so re-granting the same role
	/// does not churn outbox rows.
	pub fn set_role(&mut self, role: Role) {
		if self.role == role {
			return;
		}
		self.role = role;
		self.bump_and_emit(UserEvent::RoleChanged);
	}

	fn bump_and_emit(&mut self, event: UserEvent) {
		self.row_version += 1;
		self.pending.push(event);
	}

	pub fn id(&self) -> UserId {
		self.id
	}

	pub fn auth_subject(&self) -> &AuthSubject {
		&self.auth_subject
	}

	pub fn email(&self) -> &Email {
		&self.email
	}

	pub fn email_verified(&self) -> bool {
		self.email_verified
	}

	pub fn status(&self) -> UserStatus {
		self.status
	}

	pub fn is_active(&self) -> bool {
		self.status == UserStatus::Active
	}

	pub fn token_version(&self) -> u64 {
		self.token_version
	}

	pub fn kyc_level(&self) -> u32 {
		self.kyc_level
	}

	pub fn role(&self) -> Role {
		self.role
	}

	pub fn row_version(&self) -> u64 {
		self.row_version
	}

	pub fn legal_name(&self) -> Option<&str> {
		self.profile.legal_name.as_deref()
	}

	pub fn preferred_name(&self) -> Option<&str> {
		self.profile.preferred_name.as_deref()
	}

	pub fn phone(&self) -> Option<&str> {
		self.profile.phone.as_deref()
	}

	pub fn date_of_birth(&self) -> Option<&str> {
		self.profile.date_of_birth.as_deref()
	}

	pub fn nationality(&self) -> Option<&str> {
		self.profile.nationality.as_deref()
	}

	pub fn tax_residence(&self) -> Option<&str> {
		self.profile.tax_residence.as_deref()
	}

	pub fn residential_address(&self) -> Option<&str> {
		self.profile.residential_address.as_deref()
	}

	pub fn language(&self) -> Option<&str> {
		self.profile.language.as_deref()
	}

	pub fn base_currency(&self) -> Option<&str> {
		self.profile.base_currency.as_deref()
	}

	pub fn timezone(&self) -> Option<&str> {
		self.profile.timezone.as_deref()
	}
}

impl Entity for User {
	type Id = UserId;

	fn id(&self) -> UserId {
		self.id
	}
}

impl AggregateRoot for User {
	const NAME: &'static str = "user";
}

impl EmitsEvents for User {
	type Event = UserEvent;

	fn drain_events(&mut self) -> Vec<UserEvent> {
		core::mem::take(&mut self.pending)
	}
}

/// The cross-plane lifecycle facts the [`User`] aggregate raises. Each maps to a
/// `user_outbox` row (one bridge `Kind`) the banking money plane consumes to
/// gate/freeze money ops. Identity-internal mutations (email, profile) carry no
/// `Kind` and are not represented here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UserEvent {
	Created,
	SessionsRevoked,
	Suspended,
	Reinstated,
	KycChanged,
	RoleChanged,
}
impl UserEvent {
	/// The stored `user_outbox.kind` discriminant — the bridge `Kind`. Kept in lockstep
	/// with `concierge.v1.UserLifecycleEvent.Kind` so the puller maps it straight through.
	pub fn kind(self) -> &'static str {
		match self {
			Self::Created => "CREATED",
			Self::SessionsRevoked => "SESSIONS_REVOKED",
			Self::Suspended => "SUSPENDED",
			Self::Reinstated => "REINSTATED",
			Self::KycChanged => "KYC_CHANGED",
			Self::RoleChanged => "ROLE_CHANGED",
		}
	}
}

impl DomainEvent for UserEvent {
	const KIND: &'static str = "users";
}

#[cfg(test)]
mod tests {
	use super::*;

	fn fixture() -> User {
		User::provision(UserId::new(), AuthSubject::parse("g-123").unwrap(), Email::parse("Ada@Example.com").unwrap(), true)
	}

	#[test]
	fn status_round_trips_through_str() {
		assert_eq!(UserStatus::parse(UserStatus::Active.as_str()).unwrap(), UserStatus::Active);
		assert_eq!(UserStatus::parse(UserStatus::Disabled.as_str()).unwrap(), UserStatus::Disabled);
		assert!(UserStatus::parse("nope").is_err());
	}

	#[test]
	fn email_is_normalized() {
		assert_eq!(Email::parse("  Ada@Example.COM ").unwrap().as_str(), "ada@example.com");
		assert!(Email::parse("nope").is_err());
	}

	#[test]
	fn provision_emits_created_and_bumps_row_version() {
		let mut user = fixture();
		assert_eq!(user.token_version(), 0);
		assert!(user.is_active());
		assert_eq!(user.row_version(), 1);
		let events = user.drain_events();
		assert_eq!(events, [UserEvent::Created]);
		assert!(user.drain_events().is_empty());
	}

	#[test]
	fn verified_email_is_not_overwritten_by_unverified() {
		let mut user = fixture();
		user.drain_events();
		let before = user.row_version();
		user.change_email(Email::parse("attacker@example.com").unwrap(), false);
		assert_eq!(user.email().as_str(), "ada@example.com");
		assert!(user.email_verified());
		assert_eq!(user.row_version(), before);
	}

	#[test]
	fn revoke_increments_version_and_emits() {
		let mut user = fixture();
		user.drain_events();
		assert_eq!(user.revoke_tokens(), 1);
		assert_eq!(user.drain_events(), [UserEvent::SessionsRevoked]);
	}

	#[test]
	fn disable_then_enable_emits_each_once() {
		let mut user = fixture();
		user.drain_events();
		user.disable();
		user.disable();
		assert_eq!(user.drain_events(), [UserEvent::Suspended]);
		assert!(!user.is_active());
		user.enable();
		user.enable();
		assert_eq!(user.drain_events(), [UserEvent::Reinstated]);
		assert!(user.is_active());
	}

	#[test]
	fn kyc_change_is_idempotent() {
		let mut user = fixture();
		user.drain_events();
		user.set_kyc_level(2);
		user.set_kyc_level(2);
		assert_eq!(user.kyc_level(), 2);
		assert_eq!(user.drain_events(), [UserEvent::KycChanged]);
	}

	#[test]
	fn role_defaults_to_investor_and_change_is_idempotent() {
		let mut user = fixture();
		user.drain_events();
		assert_eq!(user.role(), Role::Investor);
		user.set_role(Role::Admin);
		user.set_role(Role::Admin);
		assert_eq!(user.role(), Role::Admin);
		assert_eq!(user.drain_events(), [UserEvent::RoleChanged]);
	}

	#[test]
	fn update_profile_bumps_row_version_without_event() {
		let mut user = fixture();
		user.drain_events();
		let before = user.row_version();
		user.update_profile(ProfileFields {
			legal_name: Some("Ada Lovelace".into()),
			preferred_name: Some("Ada".into()),
			..ProfileFields::default()
		});
		assert_eq!(user.legal_name(), Some("Ada Lovelace"));
		assert_eq!(user.preferred_name(), Some("Ada"));
		assert_eq!(user.row_version(), before + 1);
		assert!(user.drain_events().is_empty());
	}
}
