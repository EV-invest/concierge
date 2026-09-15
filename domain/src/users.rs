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

/// The IANA tz database's top-level areas — the only prefixes an `Area/Location`
/// name may start with. Keeping the list here (vs a tz crate) preserves the no-deps
/// rule; new areas have not been added to the database in decades.
const IANA_AREAS: [&str; 11] = ["Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic", "Australia", "Etc", "Europe", "Indian", "Pacific"];
/// The inclusive ceiling of the platform's KYC tiers, and the aggregate's only bound on
/// the level.
///
/// The wire contract carries a bare `uint32` and the banking money plane mirrors whatever
/// arrives, so nothing outside this plane will ever reject a nonsense tier: an account at
/// level 999 clears every threshold banking gates a money operation on. The range is
/// therefore an invariant of the identity record itself rather than a guard clause in the
/// one handler that happens to be validated today.
pub const MAX_KYC_LEVEL: u32 = 3;
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

/// How long one admin's emergency brake lasts before it lapses on its own.
///
/// TWENTY-FOUR HOURS, and the number is the whole design. Freezing an account is the
/// only control that stops money ALREADY queued — the money plane re-reads the frozen
/// flag at dispatch, so a hold catches a withdrawal inside the dispatcher's sweep. A
/// quorum by mail takes hours, and in those hours a compromised account can have a
/// broadcast on chain, which is irreversible. So one actor may stop money TEMPORARILY.
/// Making it permanent is [`Suspension::Governance`], and that needs the owners.
pub const HOLD_TTL_SECS: i64 = 24 * 60 * 60;

/// How long after a hold ends before one admin may place another on the same account
/// without the owners being asked.
///
/// SEVEN DAYS, and the number is what keeps [`HOLD_TTL_SECS`] honest. The brake is safe
/// to hand to one person only because it lapses; a hold that could be pressed again the
/// moment it lapsed would lapse in name only — twenty-four hours on, one sweep interval
/// off, forever, with no consilium ever asked. So a second hold inside this window is
/// refused unless a suspension proposal about the account is OPEN, in which case the
/// owners are already deciding and keeping the account frozen until they do is the
/// point. A week is longer than a proposal lives ([`crate::governance::REMOVAL_TTL_SECS`],
/// 72h), so "the owners never got round to it" cannot be bridged by re-holding, and
/// short enough that a threat which genuinely returns after the owners declined can be
/// braked again without a change of policy.
pub const HOLD_COOLDOWN_SECS: i64 = 7 * 24 * 60 * 60;

/// WHY a disabled account is disabled — and therefore who is allowed to undo it.
///
/// The split exists because the two are not the same decision. A hold is one operator's
/// reflex under `Permission::UserSuspend`, deliberately cheap to reach and deliberately
/// self-cancelling. A governance suspension is the owners' ratified verdict, and a
/// single admin must not be able to overturn it from the console — which is exactly what
/// would happen if reinstatement stayed unqualified.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Suspension {
	/// One operator's emergency brake. Lapses at `expires_at` unless the owners ratify
	/// it, and until then reinstatement lifts it in one act.
	AdminHold { expires_at: i64 },
	/// Ratified by the owner consilium. Reinstatement refuses it and names the proposal
	/// that undoes it; nothing lapses.
	Governance,
}

impl Suspension {
	/// The stored `users.suspended_by` discriminant.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::AdminHold { .. } => "admin_hold",
			Self::Governance => "governance",
		}
	}

	/// Parse a stored row. `expires_at` is the column beside it; absent there means a
	/// hold with no clock, which never lapses.
	pub fn parse(raw: &str, expires_at: Option<i64>) -> Result<Self, DomainError> {
		match raw {
			"admin_hold" => Ok(Self::AdminHold {
				expires_at: expires_at.unwrap_or(i64::MAX),
			}),
			"governance" => Ok(Self::Governance),
			other => Err(DomainError::Validation(format!("unknown suspension: {other}"))),
		}
	}

	/// The instant this lapses, when it lapses at all.
	pub fn hold_expires_at(self) -> Option<i64> {
		match self {
			Self::AdminHold { expires_at } => Some(expires_at),
			Self::Governance => None,
		}
	}

	/// Whether one admin may lift this alone.
	pub fn is_reversible_by_one_admin(self) -> bool {
		match self {
			Self::AdminHold { .. } => true,
			Self::Governance => false,
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
			preferred_name: parse_name("preferred_name", raw.preferred_name, 64)?,
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
	/// Why the account is disabled, when it is. `None` on an active user — and also on a
	/// row disabled before this field existed, which therefore reads as the unqualified
	/// suspension it was: liftable in one act, and lapsing never.
	suspension: Option<Suspension>,
	/// When the last admin hold on this account ended — lapsed, or lifted by one act.
	/// `None` if none ever did. What [`Self::hold`] measures [`HOLD_COOLDOWN_SECS`]
	/// against; a hold the owners ratified into a verdict never ends this way.
	hold_ended_at: Option<i64>,
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
			suspension: None,
			hold_ended_at: None,
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
		suspension: Option<Suspension>,
		hold_ended_at: Option<i64>,
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
			suspension,
			hold_ended_at,
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

	/// Disable the user UNQUALIFIED, freezing future sign-in/refresh, and emit
	/// [`UserEvent::Suspended`]. No-op when already disabled.
	///
	/// ⚠️ This records no [`Suspension`], so the account reads as liftable by one admin
	/// and lapses never. It is the raw brake the fixtures and the unqualified port method
	/// are built on — a request-driven path calls [`Self::hold`] or, for the owners'
	/// verdict, [`Self::suspend`], the same way `set_role` sits beneath
	/// `set_role_outside_ownership`.
	pub fn disable(&mut self) {
		self.suspend_as(None);
	}

	/// One operator's emergency brake: freeze now, and lapse in [`HOLD_TTL_SECS`] unless
	/// the owners ratify it.
	///
	/// Refused over an already-ratified suspension. A hold is the WEAKER measure, and
	/// letting one admin restate the owners' verdict as their own would hand them the
	/// expiry clock that goes with it — the verdict would then lapse in a day because one
	/// person pressed the softer button.
	///
	/// Refused, too, while a hold is already live and for [`HOLD_COOLDOWN_SECS`] after
	/// one ends — UNLESS `ratification_pending`, meaning a suspension proposal about this
	/// account is open. Re-holding used to restart the clock, on the argument that the
	/// audit rows made a renewed brake visible; visible is not the same as governed. One
	/// admin pressing the button once a day held an investor indefinitely with no owner
	/// ever asked, and held every OTHER owner out of their sessions — and out of the very
	/// votes that could stop it. The one legitimate reason to keep the account frozen past
	/// a day is that the owners are deciding whether to, and then the hold extends until
	/// they have.
	///
	/// `by` is the PERSISTED role of whoever is pressing. An admin or owner seat may be
	/// held only by a fund owner: the votes on every user proposal need a session, so an
	/// admin who could hold the owners could hold them out of the very consilium that
	/// decides whether the hold stands — and the one control over a rogue operator is
	/// another operator being able to stop them. An owner holding an admin is that
	/// control; an admin holding an owner is its inversion.
	pub fn hold(&mut self, by: Role, now: i64, ratification_pending: bool) -> Result<(), DomainError> {
		if self.suspension == Some(Suspension::Governance) {
			return Err(DomainError::Conflict(
				"this account is suspended by the owner consilium; a hold cannot replace that verdict".into(),
			));
		}
		if matches!(self.role, Role::Admin | Role::Owner) && by != Role::Owner {
			return Err(DomainError::Forbidden(format!(
				"an account holding the {} seat is held only by a fund owner; anyone else asks the owners through GovernanceService.OpenUserSuspension",
				self.role.as_str()
			)));
		}
		if !ratification_pending {
			if let Some(expires_at) = self.suspension.and_then(Suspension::hold_expires_at) {
				return Err(DomainError::Forbidden(format!(
					"this account is already held until {expires_at}; a hold is not renewed by holding again — keeping it frozen past that is the owners' decision, through GovernanceService.OpenUserSuspension, and the hold extends while they decide"
				)));
			}
			if let Some(ended_at) = self.hold_ended_at
				&& now < ended_at.saturating_add(HOLD_COOLDOWN_SECS)
			{
				return Err(DomainError::Forbidden(format!(
					"a hold on this account ended at {ended_at}, less than {} days ago; a second one needs the owners — open GovernanceService.OpenUserSuspension, and the account may be held again while they decide",
					HOLD_COOLDOWN_SECS / (24 * 60 * 60)
				)));
			}
		}
		self.suspend_as(Some(Suspension::AdminHold {
			expires_at: now.saturating_add(HOLD_TTL_SECS),
		}));
		Ok(())
	}

	/// The owners' ratified verdict. Freezes the account if it was not frozen already and
	/// stamps it as theirs, so [`Self::suspension`] tells reinstatement to refuse.
	pub fn suspend(&mut self) {
		self.suspend_as(Some(Suspension::Governance));
	}

	/// Re-enable a disabled user and emit [`UserEvent::Reinstated`]. No-op when already
	/// active. Unqualified: the decision about WHO may lift a given suspension is taken
	/// from [`Self::suspension`] by the caller, not here.
	///
	/// `now` is remembered only when what ends is an admin hold — that is the instant
	/// [`Self::hold`] measures its cooldown from. Lifting the owners' verdict, or a
	/// pre-column suspension, starts no cooldown: neither was one actor's brake.
	pub fn enable(&mut self, now: i64) {
		if let Some(Suspension::AdminHold { expires_at }) = self.suspension {
			// A hold past its deadline ended AT the deadline, whoever noticed first: the
			// sweep runs on an interval and an operator lifting it by hand comes later
			// still, and the cooldown is a promise about the deadline, not about who got
			// round to it. Dating it from the act would stretch the cooldown by that lag.
			self.hold_ended_at = Some(now.min(expires_at));
		}
		self.suspension = None;
		if self.status == UserStatus::Active {
			return;
		}
		self.status = UserStatus::Active;
		self.bump_and_emit(UserEvent::Reinstated);
	}

	/// Let a due hold fall away, emitting [`UserEvent::Reinstated`] so the money plane
	/// unfreezes too. True when it did.
	///
	/// This is the half of the design that makes a hold safe to hand to one person: the
	/// brake releases itself, and staying stopped is something only the owners can
	/// decide. A governance suspension has no expiry and is never touched here.
	pub fn lapse_hold(&mut self, now: i64) -> bool {
		let Some(expires_at) = self.suspension.and_then(Suspension::hold_expires_at) else {
			return false;
		};
		if now < expires_at {
			return false;
		}
		self.enable(now);
		true
	}

	/// The one writer of `status = disabled`, so "was it already frozen?" is asked in
	/// exactly one place: the event marks the FREEZE, and re-stamping why an already
	/// frozen account is frozen is not a second suspension for the money plane to mirror.
	fn suspend_as(&mut self, by: Option<Suspension>) {
		let was_active = self.status == UserStatus::Active;
		self.status = UserStatus::Disabled;
		self.suspension = by;
		if was_active {
			self.bump_and_emit(UserEvent::Suspended);
		}
	}

	/// Set the KYC level and emit [`UserEvent::KycChanged`]. No-op when unchanged.
	///
	/// Rejects anything above [`MAX_KYC_LEVEL`]. This is the ONE writer of the level, so
	/// bounding it here bounds every path that reaches it — the operator RPC, the vendor
	/// webhook, and whatever writer is added next — instead of trusting each to re-check.
	pub fn set_kyc_level(&mut self, level: u32) -> Result<(), DomainError> {
		if level > MAX_KYC_LEVEL {
			return Err(DomainError::Validation(format!("kyc_level must be between 0 and {MAX_KYC_LEVEL}")));
		}
		if self.kyc_level == level {
			return Ok(());
		}
		self.kyc_level = level;
		self.bump_and_emit(UserEvent::KycChanged);
		Ok(())
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

	/// Why the account is frozen, when it is. `None` on an active user, and also on a row
	/// frozen before the field existed — which therefore reads as liftable in one act,
	/// preserving exactly the behaviour those rows were suspended under.
	pub fn suspension(&self) -> Option<Suspension> {
		self.suspension
	}

	/// When the last admin hold ended, if one ever did — see [`Self::hold`].
	pub fn hold_ended_at(&self) -> Option<i64> {
		self.hold_ended_at
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
	// Storage cap (the SQL CHECK enforces this too).
	check_len("phone", &value, 32)?;
	// Delegate E.164 validation to the shared TypeObject (ev::types::PhoneNumber,
	// mirrors @evinvest/types). The error messages are the Display impl of
	// PhoneNumberError — human-readable and stable.
	if let Err(err) = ev::types::PhoneNumber::validate(&value) {
		return Err(DomainError::Validation(err.to_string()));
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
		user.enable(2_000);
		user.enable(2_000);
		assert_eq!(user.drain_events(), [UserEvent::Reinstated]);
		assert!(user.is_active());
	}

	#[test]
	fn kyc_change_is_idempotent() {
		let mut user = fixture();
		user.drain_events();
		user.set_kyc_level(2).expect("2 is a real tier");
		user.set_kyc_level(2).expect("2 is a real tier");
		assert_eq!(user.kyc_level(), 2);
		assert_eq!(user.drain_events(), [UserEvent::KycChanged]);
	}

	#[test]
	fn kyc_level_above_the_ceiling_is_refused() {
		let mut user = fixture();
		user.set_kyc_level(MAX_KYC_LEVEL).expect("the ceiling itself is a real tier");
		user.drain_events();

		for level in [MAX_KYC_LEVEL + 1, 4, 999, u32::MAX] {
			let err = user.set_kyc_level(level).expect_err("a tier the platform does not define must not be writable");
			assert!(matches!(err, DomainError::Validation(_)), "an out-of-range level is bad input, not a policy refusal: {err}");
		}

		assert_eq!(user.kyc_level(), MAX_KYC_LEVEL, "a refused write leaves the level alone");
		assert_eq!(user.drain_events(), [], "and emits nothing onto the cross-plane outbox");
	}

	#[test]
	fn kyc_level_accepts_every_defined_tier() {
		let mut user = fixture();
		for level in 0..=MAX_KYC_LEVEL {
			user.set_kyc_level(level).expect("every defined tier is writable");
			assert_eq!(user.kyc_level(), level);
		}
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
	fn profile_phone_rejects_invalid_and_accepts_e164() {
		let phone = |v: &str| {
			ProfileFields::parse(ProfileFields {
				phone: Some(v.into()),
				..ProfileFields::default()
			})
		};
		// Valid E.164
		assert!(phone("+842838229284").is_ok(), "Vietnam");
		assert!(phone("+12345678901").is_ok(), "US");
		assert!(phone("+442012345678").is_ok(), "UK");
		assert!(phone("+79161234567").is_ok(), "Russia");
		assert!(phone("+85212345678").is_ok(), "Hong Kong 3-digit cc");
		// Rejected
		assert!(phone("+84 (28) 3822-9284").is_err(), "spaces and parens not allowed in E.164");
		assert!(phone("+").is_err(), "no digits");
		assert!(phone("1234567890").is_err(), "missing +");
		assert!(phone("+1").is_err(), "too short (< 7 digits)");
		assert!(phone("+12345678901234567").is_err(), "too long (> 15 digits)");
		assert!(phone("+9991234567").is_err(), "unknown country code");
		assert!(phone("https://t.me/somejunk").is_err(), "URLs rejected");
		assert!(phone(&"+".repeat(33)).is_err(), "over 32 chars rejected");
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
	fn profile_preferred_name_caps_at_64() {
		let pref = |v: &str| {
			ProfileFields::parse(ProfileFields {
				preferred_name: Some(v.into()),
				..ProfileFields::default()
			})
		};
		assert!(pref("Ada").is_ok());
		assert!(pref(&"a".repeat(64)).is_ok());
		assert!(pref(&"a".repeat(65)).is_err());
		// The message names the offending field.
		let err = ProfileFields::parse(ProfileFields {
			preferred_name: Some("a".repeat(65)),
			..ProfileFields::default()
		})
		.unwrap_err();
		assert!(err.to_string().contains("preferred_name"), "the message names the offending field: {err}");
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

	// -----------------------------------------------------------------------------
	// The split verb: a hold that lapses, and a verdict that does not.
	// -----------------------------------------------------------------------------

	#[test]
	fn a_hold_freezes_now_and_carries_its_own_deadline() {
		let mut user = fixture();
		user.drain_events();
		user.hold(Role::Admin, 1_000, false).expect("nothing is suspending this account yet");
		assert_eq!(user.status(), UserStatus::Disabled);
		assert_eq!(user.suspension(), Some(Suspension::AdminHold { expires_at: 1_000 + HOLD_TTL_SECS }));
		assert_eq!(user.drain_events(), [UserEvent::Suspended], "the money plane learns of the freeze");
	}

	/// The half that makes a one-actor brake safe to hand out: it releases itself, and a
	/// REINSTATED goes with it so the money plane unfreezes too.
	#[test]
	fn a_hold_lapses_on_its_own_and_tells_the_bridge() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		user.drain_events();

		assert!(!user.lapse_hold(1_000 + HOLD_TTL_SECS - 1), "not due yet");
		assert_eq!(user.status(), UserStatus::Disabled);

		assert!(user.lapse_hold(1_000 + HOLD_TTL_SECS), "due");
		assert_eq!(user.status(), UserStatus::Active);
		assert_eq!(user.suspension(), None);
		assert_eq!(user.drain_events(), [UserEvent::Reinstated]);
		assert_eq!(user.hold_ended_at(), Some(1_000 + HOLD_TTL_SECS), "the lapse is what the cooldown counts from");
		assert!(!user.lapse_hold(i64::MAX), "there is nothing left to lapse");
	}

	/// The sweep runs on an interval, so it reaches a due hold late. The cooldown counts
	/// from the deadline the hold was given, not from the sweep that noticed it passing.
	#[test]
	fn a_late_sweep_dates_the_end_of_a_hold_at_its_deadline() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		let deadline = 1_000 + HOLD_TTL_SECS;

		assert!(user.lapse_hold(deadline + 3_600), "an hour late is still a lapse");
		assert_eq!(user.hold_ended_at(), Some(deadline), "dated at the deadline, not at the sweep");
		user.drain_events();

		user.hold(Role::Admin, deadline + HOLD_COOLDOWN_SECS, false)
			.expect("the cooldown is measured from the deadline and is over");
	}

	/// The owners' verdict has no clock, and the weaker measure cannot restate it — which
	/// would hand one admin the expiry that goes with a hold.
	#[test]
	fn a_governance_suspension_never_lapses_and_a_hold_cannot_replace_it() {
		let mut user = fixture();
		user.suspend();
		user.drain_events();
		assert_eq!(user.suspension(), Some(Suspension::Governance));
		assert_eq!(user.suspension().unwrap().hold_expires_at(), None);
		assert!(!user.lapse_hold(i64::MAX), "a verdict does not expire");

		let err = user.hold(Role::Owner, 2_000, false).expect_err("a hold must not downgrade the owners' verdict");
		assert!(matches!(err, DomainError::Conflict(_)));
		assert_eq!(user.suspension(), Some(Suspension::Governance), "the refusal left it alone");
	}

	#[test]
	fn only_a_hold_is_reversible_by_one_admin() {
		assert!(Suspension::AdminHold { expires_at: 1 }.is_reversible_by_one_admin());
		assert!(!Suspension::Governance.is_reversible_by_one_admin());
	}

	/// The freeze is the event, not the reason for it: ratifying an account that is
	/// already held must not emit a second SUSPENDED for the money plane to mirror.
	#[test]
	fn ratifying_a_live_hold_restamps_it_without_a_second_event() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		user.drain_events();
		let version = user.row_version();

		user.suspend();
		assert_eq!(user.suspension(), Some(Suspension::Governance));
		assert!(user.drain_events().is_empty(), "it was already frozen");
		assert_eq!(user.row_version(), version);
	}

	/// A row disabled before the column existed reads as `None`, which is the OLD
	/// semantics on purpose — liftable in one act, lapsing never — because that is the
	/// rule those accounts were actually suspended under.
	#[test]
	fn a_pre_existing_suspension_keeps_the_semantics_it_was_made_under() {
		let mut user = fixture();
		user.disable();
		assert_eq!(user.status(), UserStatus::Disabled);
		assert_eq!(user.suspension(), None);
		assert!(!user.lapse_hold(i64::MAX), "nothing to lapse");
		user.enable(2_000);
		assert_eq!(user.status(), UserStatus::Active);
		assert_eq!(user.hold_ended_at(), None, "lifting a pre-column suspension starts no cooldown");
	}

	/// The brake lapses, and that has to mean something: pressed again while live it is
	/// refused, and pressed again within the cooldown it is refused. What lifts both is
	/// the owners already deciding — an open suspension proposal — and then the hold
	/// extends until they have.
	#[test]
	fn a_hold_is_not_renewed_by_holding_again() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("the first brake");
		user.drain_events();

		let err = user.hold(Role::Admin, 2_000, false).expect_err("a second press while held must not restart the clock");
		assert!(matches!(err, DomainError::Forbidden(_)), "{err}");
		assert_eq!(user.suspension(), Some(Suspension::AdminHold { expires_at: 1_000 + HOLD_TTL_SECS }), "the deadline stood");
		assert!(user.drain_events().is_empty());

		user.hold(Role::Admin, 2_000, true)
			.expect("with a suspension proposal open, the hold extends until the owners decide");
		assert_eq!(user.suspension(), Some(Suspension::AdminHold { expires_at: 2_000 + HOLD_TTL_SECS }));
		assert!(user.drain_events().is_empty(), "still one freeze for the money plane");
	}

	#[test]
	fn a_lapsed_hold_starts_a_cooldown_that_only_the_owners_can_shorten() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		let ended = 1_000 + HOLD_TTL_SECS;
		assert!(user.lapse_hold(ended));
		user.drain_events();

		let err = user.hold(Role::Admin, ended + HOLD_COOLDOWN_SECS - 1, false).expect_err("inside the cooldown");
		assert!(matches!(err, DomainError::Forbidden(_)), "{err}");
		assert_eq!(user.status(), UserStatus::Active, "the refusal changed nothing");

		user.hold(Role::Admin, ended + 1, true).expect("an open suspension proposal lifts the cooldown");
		assert_eq!(user.status(), UserStatus::Disabled);
		assert_eq!(user.drain_events(), [UserEvent::Suspended]);

		let mut again = fixture();
		again.hold(Role::Admin, 1_000, false).expect("hold");
		again.lapse_hold(ended);
		again
			.hold(Role::Admin, ended + HOLD_COOLDOWN_SECS, false)
			.expect("the cooldown is over, one actor may brake again");
	}

	/// Lifted early by one act counts the same as lapsing: the account was one actor's
	/// to brake and one actor's to release, and the next brake waits.
	#[test]
	fn a_lifted_hold_starts_the_cooldown_too() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		user.enable(5_000);
		assert_eq!(user.hold_ended_at(), Some(5_000));
		assert!(matches!(user.hold(Role::Admin, 6_000, false), Err(DomainError::Forbidden(_))));
	}

	/// The sweep may not have reached a due hold when an operator lifts it by hand.
	/// That lift ends a hold that was already over, so the cooldown counts from the
	/// deadline — the same instant the sweep would have recorded.
	#[test]
	fn lifting_an_overdue_hold_by_hand_dates_its_end_at_the_deadline() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		let deadline = 1_000 + HOLD_TTL_SECS;
		user.enable(deadline + 3 * 3_600);
		assert_eq!(user.hold_ended_at(), Some(deadline), "not the lift, the deadline");
		user.drain_events();
		user.hold(Role::Admin, deadline + HOLD_COOLDOWN_SECS, false)
			.expect("the cooldown ran from the deadline and is over");
	}

	/// A hold the owners ratified ended as THEIR verdict, not as a hold; lifting the
	/// verdict later starts no cooldown against the next emergency.
	#[test]
	fn a_ratified_hold_leaves_no_cooldown_behind() {
		let mut user = fixture();
		user.hold(Role::Admin, 1_000, false).expect("hold");
		user.suspend();
		user.enable(9_000);
		assert_eq!(user.hold_ended_at(), None);
		user.hold(Role::Admin, 9_001, false).expect("the owners lifted their verdict; the brake is available again");
	}

	/// The votes on every user proposal need a session, so an admin who could hold the
	/// owners could hold them out of the consilium that decides whether the hold stands.
	/// Only an owner holds a seat; anyone may hold an investor.
	#[test]
	fn a_seat_is_held_only_by_an_owner() {
		for seat in [Role::Admin, Role::Owner] {
			let mut seated = fixture();
			seated.set_role(seat);
			seated.drain_events();
			for pressing in [Role::Investor, Role::Operator, Role::Admin] {
				let err = seated.hold(pressing, 1_000, false).expect_err("not by this role");
				assert!(matches!(err, DomainError::Forbidden(_)), "{err}");
				assert_eq!(seated.status(), UserStatus::Active, "the refusal changed nothing");
			}
			seated.hold(Role::Owner, 1_000, false).expect("an owner may hold a seat");
			assert_eq!(seated.status(), UserStatus::Disabled);
		}

		let mut investor = fixture();
		investor.hold(Role::Admin, 1_000, false).expect("an investor is held by any operator with the permission");
	}

	#[test]
	fn suspension_round_trips_through_the_stored_pair() {
		assert_eq!(Suspension::parse("admin_hold", Some(42)).unwrap(), Suspension::AdminHold { expires_at: 42 });
		assert_eq!(Suspension::parse("governance", None).unwrap(), Suspension::Governance);
		// A hold with no stored deadline is one that never lapses, not one that lapsed
		// at the epoch — the direction of that default is the whole safety of it.
		assert_eq!(Suspension::parse("admin_hold", None).unwrap(), Suspension::AdminHold { expires_at: i64::MAX });
		assert!(Suspension::parse("because", None).is_err());
	}
}
