//! The identity plane's shared authorization gate for admin RPCs, and the
//! self-extinguishing emergency access that keeps a brand-new fund reachable.
//!
//! Resolves the caller's persisted [`Role`] from the verified access-token `sub` and
//! checks it against the RBAC matrix ([`grants`]).
//!
//! # Break-glass, and why it switches itself off
//!
//! `users.role` is the ONE source of truth about ownership: the consilium
//! ([`crate::governance`]) counts it, the quorum is taken from it, and the money plane
//! mirrors it. A config allowlist that silently outranked it produced the bug this
//! module exists to close — the operator console showed three owners while the
//! consilium saw zero.
//!
//! But a fund with an empty registry has nobody who can act, and the genesis seed
//! ([`crate::genesis`]) can fail to land for perfectly ordinary reasons (a founder has
//! not signed in yet, a typo in the list). Removing elevation outright would turn that
//! into an unreachable console recoverable only by hand-editing production SQL. So
//! [`BreakGlass`] keeps it, under exactly one condition:
//!
//! ```text
//! persisted owner count == 0  →  an OWNER_SUBJECTS-listed subject acts as Role::Owner
//! otherwise                   →  only users.role counts; the list means nothing
//! ```
//!
//! This is a one-way door, and it is safe for a reason the domain already enforces
//! rather than one this module asserts: the registry can never fall back to zero. Both
//! expulsion and `ResignOwnership` refuse below `MIN_OWNERS`
//! (`domain::governance::check_floor`), so the first owner to exist closes emergency
//! access permanently and no API call can reopen it. Quorum stuffing is unreachable for
//! the same reason — the instant one owner exists, elevation is already off.
//!
//! Two guardrails keep it honest while it IS on:
//!
//! * it is a ROLE override, never an exemption — [`caller_gate`] enforces the live
//!   record's status and `token_version` floor first, so disabling or revoking a listed
//!   operator still bites;
//! * it never seats anyone. `SetRole` refuses [`Role::Owner`] unconditionally
//!   ([`crate::directory`]), so emergency access can hand out `operator`/`admin` and
//!   nothing more. A seat is born only of the genesis seed or the consilium.
//!
//! Elevation is also VISIBLE: every surface that reports a role reports
//! [`EffectiveRole::break_glass`] beside it, so a console can say the authority came
//! from the environment rather than from the register. The original bug was not that
//! elevation existed — it was that it was invisible.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicBool, Ordering};

use domain::{
	authz::{Permission, Role, grants},
	error::DomainError,
	users::{UserId, UserStatus},
};
use evconcierge_auth::{Claims, claims_of};
use tonic::{Request, Status};
use uuid::Uuid;

use crate::{infrastructure::users::AuthzRecord, ports::UserDirectoryRepository};

/// The verified caller after the live-record gate: the raw token `sub`, its parse as
/// a canonical user id, and the persisted record — already enforced for status and
/// the `token_version` floor — when one exists. How a missing id/record fails is the
/// consumer's policy (emergency access vs. `NOT_FOUND` vs. denial).
pub struct CallerGate {
	pub sub: String,
	pub id: Option<UserId>,
	pub record: Option<AuthzRecord>,
}

/// Resolve the caller from the verified [`Claims`] and enforce the live persisted
/// record: only a `typ=access` token acts as a user, and — whenever a record exists —
/// a suspended or token-revoked principal is rejected at once (the stateless verifier
/// can't see status or the authoritative `token_version`).
pub async fn caller_gate<T>(users: &dyn UserDirectoryRepository, request: &Request<T>) -> Result<CallerGate, Status> {
	// Clone the small facts out so the `Claims` borrow of `request` ends before the
	// async `authz_record` lookup. `token_version` is the version the token was minted
	// under; the persisted value is the authoritative floor.
	let (is_access, sub, token_version) = {
		let claims: &Claims = claims_of(request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		(claims.is_access(), claims.sub.clone(), claims.token_version)
	};
	if !is_access {
		return Err(Status::permission_denied("access token required"));
	}
	let id = Uuid::parse_str(&sub).ok().map(UserId::from_raw);
	let record = match id {
		Some(id) => users.authz_record(id).await.map_err(map_err)?,
		None => None,
	};
	if let Some(record) = &record {
		// A suspended principal loses the surface immediately, even while an unexpired
		// access token still verifies.
		if record.status == UserStatus::Disabled {
			return Err(Status::permission_denied("user is disabled"));
		}
		// "Revoke all" bumps the authoritative `token_version`; reject a token minted under
		// an older version so a revoke takes effect at once, not only after the short
		// access-token TTL expires.
		if token_version < record.token_version {
			return Err(Status::unauthenticated("tokens revoked"));
		}
	}
	Ok(CallerGate { sub, id, record })
}

/// A resolved role together with where it came from. `break_glass` is what a client
/// renders its warning from: the authority is real, but it is the environment's rather
/// than the register's, and it disappears the moment the fund has an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveRole {
	pub role: Role,
	pub break_glass: bool,
}

impl EffectiveRole {
	/// The role exactly as `users.role` holds it.
	pub fn persisted(role: Role) -> Self {
		Self { role, break_glass: false }
	}
}

/// The boot-loaded `OWNER_SUBJECTS` list plus the latch that retires it.
///
/// Shared by every surface that resolves or reports a role, so the rule is stated once
/// and cannot drift between the gate and what the console draws.
pub struct BreakGlass {
	subjects: Vec<String>,
	/// Latched `true` the first time a persisted owner is observed, and never cleared.
	///
	/// Caching a mutable fact is normally a bug; this one is sound because the fact is
	/// IRREVERSIBLE. The count of `users.role = 'owner'` can go 0 → n, and from n it can
	/// only ever be pushed down to `MIN_OWNERS` (`domain::governance::check_floor`
	/// refuses to leave fewer). Nothing in the plane can return it to zero, so a latch
	/// that only moves false → true can never be stale in the dangerous direction — the
	/// worst it can do is close emergency access, which is the fail-closed side.
	sealed: AtomicBool,
}

impl BreakGlass {
	/// An empty list elevates nobody, which is the right posture for every deployment
	/// that has already been through genesis.
	pub fn new(subjects: Vec<String>) -> Self {
		Self {
			subjects,
			sealed: AtomicBool::new(false),
		}
	}

	pub fn subjects(&self) -> &[String] {
		&self.subjects
	}

	/// Resolve the rule once for the current request. A caller that reports a role for
	/// many users (`ListUsers`) MUST take one snapshot and apply it per row rather than
	/// asking per row.
	///
	/// A control-plane read failure resolves to "sealed": a database blip must not be
	/// able to hand [`Role::Owner`] to an environment-listed subject.
	pub async fn snapshot<'a>(&'a self, users: &dyn UserDirectoryRepository) -> Elevation<'a> {
		if self.subjects.is_empty() || self.sealed.load(Ordering::Relaxed) {
			return Elevation { subjects: None };
		}
		match users.owner_count().await {
			Ok(0) => Elevation { subjects: Some(&self.subjects) },
			Ok(_) => {
				self.sealed.store(true, Ordering::Relaxed);
				Elevation { subjects: None }
			}
			Err(err) => {
				tracing::warn!(%err, "owner registry unreadable — treating emergency access as closed");
				Elevation { subjects: None }
			}
		}
	}
}

/// The break-glass rule frozen for one request: `Some` while the fund has no persisted
/// owner, `None` once it has one (or when the list is empty).
pub struct Elevation<'a> {
	subjects: Option<&'a [String]>,
}

impl Elevation<'_> {
	/// The role the plane acts on and reports for `sub`.
	pub fn role_of(&self, persisted: Role, sub: &str) -> EffectiveRole {
		if self.elevates(sub) {
			EffectiveRole {
				role: Role::Owner,
				break_glass: true,
			}
		} else {
			EffectiveRole::persisted(persisted)
		}
	}

	/// Whether `sub` is elevated at all — the one case where authority can exist with no
	/// persisted row to read it from.
	pub fn elevates(&self, sub: &str) -> bool {
		self.subjects.is_some_and(|subjects| subjects.iter().any(|s| s == sub))
	}
}

/// Authorize `request` for `permission`, or return a gRPC `PermissionDenied`/
/// `Unauthenticated`.
pub async fn require_permission<T>(users: &dyn UserDirectoryRepository, break_glass: &BreakGlass, request: &Request<T>, permission: Permission) -> Result<(), Status> {
	let caller = caller_gate(users, request).await?;
	// Elevation is applied AFTER the live-record gate, so DisableUser and RevokeTokens
	// bite an environment-listed principal too — it grants a role, never an exemption
	// from status/revocation.
	let elevation = break_glass.snapshot(users).await;
	let role = if let Some(record) = caller.record {
		elevation.role_of(record.role, &caller.sub).role
	} else if elevation.elevates(&caller.sub) {
		// Emergency bootstrap: while the registry is empty a listed subject holds Owner
		// even with no persisted record, so the console stays reachable before anyone's
		// first sign-in has minted a row.
		Role::Owner
	} else if caller.id.is_none() {
		return Err(Status::unauthenticated("subject is not a user id"));
	} else {
		// An unknown user holds nothing — fail closed rather than defaulting to Investor's
		// (empty) grant set with no status/revocation check.
		return Err(Status::permission_denied("insufficient role"));
	};
	if grants(role, permission) {
		Ok(())
	} else {
		Err(Status::permission_denied("insufficient role"))
	}
}

fn map_err(err: DomainError) -> Status {
	match err {
		DomainError::Validation(_) => Status::internal("corrupt role in control plane"),
		_ => Status::unavailable("internal error"),
	}
}
