//! The identity plane's shared authorization gate for admin RPCs.
//!
//! Resolves the caller's persisted [`Role`] from the verified access-token `sub` and
//! checks it against the RBAC matrix ([`grants`]). An `ADMIN_SUBJECTS`-listed subject
//! is treated as [`Role::Owner`] (break-glass bootstrap, so the first operator can
//! grant roles before any role is persisted) — but the allowlist is only a ROLE
//! override: a persisted record's status and `token_version` floor are enforced for
//! everyone, so disabling or revoking an allowlisted operator still takes effect. A
//! service token, or a missing/unknown user, holds nothing — the gate fails closed.
//! Shared by the `directory` and `platform` services so the matrix is enforced in
//! exactly one place; [`caller_gate`] is the same live-record enforcement the
//! self-service surface (`directory::active_caller_id`) reuses.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

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
/// consumer's policy (allowlist bootstrap vs. `NOT_FOUND` vs. denial).
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

/// Authorize `request` for `permission`, or return a gRPC `PermissionDenied`/
/// `Unauthenticated`.
pub async fn require_permission<T>(users: &dyn UserDirectoryRepository, admins: &[String], request: &Request<T>, permission: Permission) -> Result<(), Status> {
	let caller = caller_gate(users, request).await?;
	// The allowlist is applied AFTER the live-record gate, so DisableUser and
	// RevokeTokens bite the most privileged principals too — it grants a role, never
	// an exemption from status/revocation.
	let role = if admins.iter().any(|s| s == &caller.sub) {
		// Break-glass superadmin bootstrap: config-listed subjects hold Owner even with no
		// persisted record, so the first operator can grant roles before any role exists.
		Role::Owner
	} else {
		if caller.id.is_none() {
			return Err(Status::unauthenticated("subject is not a user id"));
		}
		// An unknown user holds nothing — fail closed rather than defaulting to Investor's
		// (empty) grant set with no status/revocation check.
		caller.record.ok_or_else(|| Status::permission_denied("insufficient role"))?.role
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
