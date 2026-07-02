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
//! exactly one place.
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

use crate::infrastructure::users::PgUsers;

/// Authorize `request` for `permission`, or return a gRPC `PermissionDenied`/
/// `Unauthenticated`.
pub async fn require_permission<T>(users: &PgUsers, admins: &[String], request: &Request<T>, permission: Permission) -> Result<(), Status> {
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
	let allowlisted = admins.iter().any(|s| s == &sub);
	let record = match Uuid::parse_str(&sub) {
		Ok(raw) => users.authz_record(UserId::from_raw(raw)).await.map_err(map_err)?,
		// Not a canonical user id, so no record can exist; only the record-less
		// allowlist bootstrap below may proceed.
		Err(_) if allowlisted => None,
		Err(_) => return Err(Status::unauthenticated("subject is not a user id")),
	};
	// Enforce the live record BEFORE any allowlist role override, so DisableUser and
	// RevokeTokens bite the most privileged principals too — the allowlist grants a
	// role, never an exemption from status/revocation.
	if let Some(record) = &record {
		// A suspended principal loses the operator console immediately, even while an
		// unexpired access token still verifies (the stateless verifier can't see status).
		if record.status == UserStatus::Disabled {
			return Err(Status::permission_denied("user is disabled"));
		}
		// "Revoke all" bumps the authoritative `token_version`; reject a token minted under
		// an older version so a revoke takes effect on the privileged surface at once, not
		// only after the short access-token TTL expires.
		if token_version < record.token_version {
			return Err(Status::unauthenticated("tokens revoked"));
		}
	}
	let role = if allowlisted {
		// Break-glass superadmin bootstrap: config-listed subjects hold Owner even with no
		// persisted record, so the first operator can grant roles before any role exists.
		Role::Owner
	} else {
		// An unknown user holds nothing — fail closed rather than defaulting to Investor's
		// (empty) grant set with no status/revocation check.
		record.ok_or_else(|| Status::permission_denied("insufficient role"))?.role
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
