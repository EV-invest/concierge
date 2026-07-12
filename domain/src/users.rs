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
		// RFC 5321's 254-octet path cap; anything longer is junk, not a mailbox.
		if normalized.chars().count() > 254 {
			return Err(DomainError::Validation("email must be at most 254 characters".into()));
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

impl ProfileFields {
	/// Parse-don't-validate for the whole editable set: every field is trimmed, a
	/// blank value clears the field (`None`), and each field's invariant is checked
	/// (the store backstops the same length caps with CHECK constraints). Errors name
	/// the offending field. [`User::update_profile`] re-runs this, so an unchecked set
	/// can never land on the aggregate; [`User::rehydrate`] deliberately does not —
	/// pre-validation rows must keep loading.
	pub fn parse(raw: ProfileFields) -> Result<Self, DomainError> {
		Ok(Self {
			legal_name: parse_name("legal_name", raw.legal_name, 256)?,
			preferred_name: parse_name("preferred_name", raw.preferred_name, 256)?,
			phone: parse_phone(raw.phone)?,
			date_of_birth: parse_date_of_birth(raw.date_of_birth)?,
			nationality: parse_name("nationality", raw.nationality, 64)?,
			tax_residence: parse_name("tax_residence", raw.tax_residence, 64)?,
			residential_address: parse_address(raw.residential_address)?,
			language: parse_language(raw.language)?,
			base_currency: parse_currency(raw.base_currency)?,
			timezone: parse_timezone(raw.timezone)?,
		})
	}
}

/// Trim, treating a blank value as a clear — the wire contract's "empty string
/// clears the field" semantics.
fn normalized(value: Option<String>) -> Option<String> {
	value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn check_len(field: &'static str, value: &str, max: usize) -> Result<(), DomainError> {
	if value.chars().count() > max {
		return Err(DomainError::Validation(format!("{field} must be at most {max} characters")));
	}
	Ok(())
}

/// Human-name shape shared by names/nationality/tax residence: letters (any
/// script), spaces, hyphen, apostrophe, period — and at least 2 letters, so
/// single-character garbage is rejected. The allowlist excludes control characters.
fn parse_name(field: &'static str, value: Option<String>, max: usize) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	check_len(field, &value, max)?;
	if !value.chars().all(|c| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | '.')) {
		return Err(DomainError::Validation(format!("{field} may only contain letters, spaces, hyphens, apostrophes, and periods")));
	}
	if value.chars().filter(|c| c.is_alphabetic()).count() < 2 {
		return Err(DomainError::Validation(format!("{field} must contain at least 2 letters")));
	}
	Ok(Some(value))
}

fn parse_phone(value: Option<String>) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	check_len("phone", &value, 32)?;
	if !value.chars().all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')')) {
		return Err(DomainError::Validation("phone may only contain digits, '+', '-', spaces, and parentheses".into()));
	}
	if value.chars().filter(char::is_ascii_digit).count() < 5 {
		return Err(DomainError::Validation("phone must contain at least 5 digits".into()));
	}
	Ok(Some(value))
}

/// Exact `YYYY-MM-DD`, a real calendar date, year 1900..=2100. Hand-rolled because
/// this crate has no time dependency (and must not grow one).
fn parse_date_of_birth(value: Option<String>) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	let err = || DomainError::Validation("date_of_birth must be a valid YYYY-MM-DD date with year 1900-2100".into());
	let bytes = value.as_bytes();
	if bytes.len() != 10 || !bytes.iter().enumerate().all(|(i, b)| if i == 4 || i == 7 { *b == b'-' } else { b.is_ascii_digit() }) {
		return Err(err());
	}
	let (year, month, day): (u32, u32, u32) = (value[0..4].parse().unwrap(), value[5..7].parse().unwrap(), value[8..10].parse().unwrap());
	if !(1900..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
		return Err(err());
	}
	Ok(Some(value))
}

fn days_in_month(year: u32, month: u32) -> u32 {
	match month {
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		4 | 6 | 9 | 11 => 30,
		2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => 29,
		_ => 28,
	}
}

fn parse_address(value: Option<String>) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	check_len("residential_address", &value, 256)?;
	if value.chars().any(char::is_control) {
		return Err(DomainError::Validation("residential_address must not contain control characters".into()));
	}
	Ok(Some(value))
}

/// Lenient BCP 47 shape: a 2-3 letter primary subtag, then optional `-`/`_`
/// separated alphanumeric subtags of 2-8 characters ("ja", "en-US", "vi_VN") —
/// full words like "japanese" are not codes.
fn parse_language(value: Option<String>) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	check_len("language", &value, 16)?;
	let err = || DomainError::Validation("language must be a BCP 47 code such as 'en' or 'en-US'".into());
	let mut subtags = value.split(['-', '_']);
	let primary = subtags.next().unwrap_or_default();
	if !(2..=3).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
		return Err(err());
	}
	for subtag in subtags {
		if !(2..=8).contains(&subtag.len()) || !subtag.bytes().all(|b| b.is_ascii_alphanumeric()) {
			return Err(err());
		}
	}
	Ok(Some(value))
}

fn parse_currency(value: Option<String>) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	if value.len() != 3 || !value.bytes().all(|b| b.is_ascii_alphabetic()) {
		return Err(DomainError::Validation("base_currency must be a 3-letter code such as 'USD'".into()));
	}
	Ok(Some(value.to_ascii_uppercase()))
}

/// The IANA tz database's top-level areas — the only prefixes an `Area/Location`
/// name may start with. Keeping the list here (vs a tz crate) preserves the no-deps
/// rule; new areas have not been added to the database in decades.
const IANA_AREAS: [&str; 11] = ["Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic", "Australia", "Etc", "Europe", "Indian", "Pacific"];

fn parse_timezone(value: Option<String>) -> Result<Option<String>, DomainError> {
	let Some(value) = normalized(value) else { return Ok(None) };
	check_len("timezone", &value, 64)?;
	if value == "UTC" || value == "GMT" {
		return Ok(Some(value));
	}
	let err = || DomainError::Validation("timezone must be 'UTC', 'GMT', or an IANA name such as 'Asia/Ho_Chi_Minh'".into());
	let mut segments = value.split('/');
	if !IANA_AREAS.contains(&segments.next().unwrap_or_default()) {
		return Err(err());
	}
	let mut locations = 0;
	for segment in segments {
		if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-')) {
			return Err(err());
		}
		locations += 1;
	}
	if locations == 0 {
		return Err(err());
	}
	Ok(Some(value))
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

	/// Full-replace the editable profile fields, re-parsing them so an
	/// invariant-violating set can never land on the aggregate no matter the caller.
	/// Raises no cross-plane event — profile metadata is the identity plane's own
	/// concern and the money plane does not gate on it — but still bumps
	/// `row_version` so the per-user sequence stays monotonic.
	pub fn update_profile(&mut self, fields: ProfileFields) -> Result<(), DomainError> {
		self.profile = ProfileFields::parse(fields)?;
		self.row_version += 1;
		Ok(())
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
		})
		.unwrap();
		assert_eq!(user.legal_name(), Some("Ada Lovelace"));
		assert_eq!(user.preferred_name(), Some("Ada"));
		assert_eq!(user.row_version(), before + 1);
		assert!(user.drain_events().is_empty());
	}

	#[test]
	fn update_profile_rejects_invalid_fields_without_mutating() {
		let mut user = fixture();
		user.drain_events();
		let before = user.row_version();
		let err = user
			.update_profile(ProfileFields {
				phone: Some("https://spam.example".into()),
				..ProfileFields::default()
			})
			.unwrap_err();
		assert!(matches!(err, DomainError::Validation(_)));
		assert_eq!(user.row_version(), before, "a rejected update must not advance the sequence");
	}

	#[test]
	fn email_caps_total_length_at_254() {
		// "@example.com" is 12 characters, so 242 + 12 = 254 is the boundary.
		assert!(Email::parse(&format!("{}@example.com", "a".repeat(242))).is_ok());
		assert!(Email::parse(&format!("{}@example.com", "a".repeat(243))).is_err());
	}

	#[test]
	fn profile_parse_trims_and_clears_blank_fields() {
		let parsed = ProfileFields::parse(ProfileFields {
			legal_name: Some("  Ada Lovelace  ".into()),
			preferred_name: Some("   ".into()),
			..ProfileFields::default()
		})
		.unwrap();
		assert_eq!(parsed.legal_name.as_deref(), Some("Ada Lovelace"));
		assert_eq!(parsed.preferred_name, None, "blank-after-trim stays a clear");
		assert_eq!(ProfileFields::parse(ProfileFields::default()).unwrap(), ProfileFields::default());
	}

	#[test]
	fn profile_names_enforce_charset_length_and_letter_minimum() {
		let name = |v: &str| {
			ProfileFields::parse(ProfileFields {
				legal_name: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(name("Ada Lovelace").is_ok());
		assert!(name("Nguyễn Thị Minh-Khai").is_ok(), "diacritics are letters");
		assert!(name("O'Brien Jr.").is_ok());
		assert!(name("zX").is_ok(), "two letters is the minimum");
		assert!(name(&"a".repeat(256)).is_ok());
		assert!(name(&"a".repeat(257)).is_err());
		// Observed junk: one-letter garbage and control characters.
		assert!(name("z").is_err());
		assert!(name("Ada\u{7}Lovelace").is_err());
		assert!(name("<b>Ada</b>").is_err());
		let err = name("z").unwrap_err();
		assert!(err.to_string().contains("legal_name"), "the message names the offending field: {err}");
	}

	#[test]
	fn profile_phone_rejects_urls_and_short_numbers() {
		let phone = |v: &str| {
			ProfileFields::parse(ProfileFields {
				phone: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(phone("+84 (28) 3822-9284").is_ok());
		assert!(phone(&"1".repeat(32)).is_ok());
		// Observed junk: an https URL stored as a phone number.
		assert!(phone("https://t.me/somejunk").is_err());
		assert!(phone("+1-23").is_err(), "fewer than 5 digits");
		assert!(phone(&"1".repeat(33)).is_err());
	}

	#[test]
	fn profile_date_of_birth_is_a_real_calendar_date() {
		let dob = |v: &str| {
			ProfileFields::parse(ProfileFields {
				date_of_birth: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(dob("1990-07-13").is_ok());
		assert!(dob("2000-02-29").is_ok(), "2000 is a leap year (400 rule)");
		assert!(dob("1999-02-29").is_err(), "1999 is not a leap year");
		assert!(dob("1900-02-29").is_err(), "1900 is not a leap year (100 rule)");
		assert!(dob("1899-12-31").is_err(), "year below 1900");
		assert!(dob("2101-01-01").is_err(), "year above 2100");
		assert!(dob("1990-13-01").is_err());
		assert!(dob("1990-04-31").is_err());
		assert!(dob("1990-00-10").is_err());
		assert!(dob("13/07/1990").is_err());
		assert!(dob("1990-7-13").is_err(), "exact YYYY-MM-DD only");
	}

	#[test]
	fn profile_nationality_and_tax_residence_cap_at_64() {
		let nat = |v: &str| {
			ProfileFields::parse(ProfileFields {
				nationality: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(nat("Vietnamese").is_ok());
		assert!(nat(&"a".repeat(64)).is_ok());
		assert!(nat(&"a".repeat(65)).is_err());
		assert!(nat("V").is_err());
		let err = ProfileFields::parse(ProfileFields {
			tax_residence: Some("1234".into()),
			..ProfileFields::default()
		})
		.unwrap_err();
		assert!(err.to_string().contains("tax_residence"), "the message names the offending field: {err}");
	}

	#[test]
	fn profile_address_allows_punctuation_but_not_control_chars() {
		let addr = |v: &str| {
			ProfileFields::parse(ProfileFields {
				residential_address: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(addr("12/34 Nguyễn Huệ, Q.1, TP.HCM").is_ok());
		assert!(addr(&"a".repeat(256)).is_ok());
		assert!(addr(&"a".repeat(257)).is_err());
		assert!(addr("line one\nline two").is_err());
	}

	#[test]
	fn profile_language_takes_bcp47_codes_not_words() {
		let lang = |v: &str| {
			ProfileFields::parse(ProfileFields {
				language: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(lang("ja").is_ok());
		assert!(lang("en-US").is_ok());
		assert!(lang("vi_VN").is_ok());
		assert!(lang("zh-Hant-TW").is_ok());
		// Observed junk: a full language word instead of a code.
		assert!(lang("japanese").is_err());
		assert!(lang("j").is_err());
		assert!(lang("en-").is_err());
		assert!(lang("en-x").is_err(), "subtags are 2-8 characters");
	}

	#[test]
	fn profile_currency_is_three_letters_normalized_uppercase() {
		let cur = |v: &str| {
			ProfileFields::parse(ProfileFields {
				base_currency: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert_eq!(cur("usd").unwrap().base_currency.as_deref(), Some("USD"));
		assert_eq!(cur(" VND ").unwrap().base_currency.as_deref(), Some("VND"));
		assert!(cur("US").is_err());
		assert!(cur("USDT").is_err());
		assert!(cur("U5D").is_err());
	}

	#[test]
	fn profile_timezone_takes_iana_names_not_bare_words() {
		let tz = |v: &str| {
			ProfileFields::parse(ProfileFields {
				timezone: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(tz("Asia/Ho_Chi_Minh").is_ok());
		assert!(tz("Etc/GMT+7").is_ok());
		assert!(tz("UTC").is_ok());
		assert!(tz("GMT").is_ok());
		assert!(tz("America/Argentina/Buenos_Aires").is_ok());
		// Observed junk: a bare word.
		assert!(tz("zalupka").is_err());
		assert!(tz("Asia").is_err(), "an area alone is not a timezone");
		assert!(tz("Asia/").is_err());
		assert!(tz("Mars/Olympus").is_err());
	}
}
