//! The identity plane's shared authorization gate for admin RPCs.
//!
//! Resolves the caller's persisted [`Role`] from the verified access-token `sub` and
//! checks it against the RBAC matrix ([`grants`]). An `ADMIN_SUBJECTS`-listed subject
//! is treated as [`Role::Owner`] (break-glass bootstrap, so the first operator can
//! grant roles before any role is persisted). A service token, or a missing/unknown
//! user, holds nothing — the gate fails closed. Shared by the `directory` and
//! `platform` services so the matrix is enforced in exactly one place.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use domain::{
	authz::{Permission, Role, grants},
	error::DomainError,
	users::UserId,
};
use evconcierge_auth::{Claims, claims_of};
use tonic::{Request, Status};
use uuid::Uuid;

use crate::infrastructure::users::PgUsers;

/// Authorize `request` for `permission`, or return a gRPC `PermissionDenied`/
/// `Unauthenticated`.
pub async fn require_permission<T>(users: &PgUsers, admins: &[String], request: &Request<T>, permission: Permission) -> Result<(), Status> {
	// Clone the small facts out so the `Claims` borrow of `request` ends before the
	// async `role_of` lookup.
	let (is_access, sub) = {
		let claims: &Claims = claims_of(request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		(claims.is_access(), claims.sub.clone())
	};
	if !is_access {
		return Err(Status::permission_denied("access token required"));
	}
	let role = if admins.iter().any(|s| s == &sub) {
		Role::Owner
	} else {
		let id = Uuid::parse_str(&sub).map(UserId::from_raw).map_err(|_| Status::unauthenticated("subject is not a user id"))?;
		users.role_of(id).await.map_err(map_err)?.unwrap_or_default()
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
