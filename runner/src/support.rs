//! Cross-module gRPC plumbing shared by the runner's services.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::error::DomainError;
use subtle::ConstantTimeEq;
use tonic::{Request, Status};

/// Map a domain error to a gRPC status without leaking control-plane internals.
pub fn domain_to_status(err: DomainError) -> Status {
	match err {
		DomainError::NotFound { .. } => Status::not_found(err.to_string()),
		DomainError::Validation(_) => Status::invalid_argument(err.to_string()),
		DomainError::Forbidden(_) => Status::permission_denied(err.to_string()),
		DomainError::Conflict(_) => Status::already_exists(err.to_string()),
		DomainError::Repository(_) => Status::unavailable("internal error"),
	}
}

/// Authenticate a SERVICE-to-service caller against a shared bearer token.
///
/// The two seams that cross a plane boundary without a user behind them — the
/// lifecycle bridge the money plane pulls, and the mail relay it pushes to — both
/// authenticate this way rather than through the user `grpc_auth_layer`, and both are
/// mounted outside it. The comparison is constant time, so verifying leaks nothing
/// through timing; an unconfigured token fails CLOSED, because a seam that quietly
/// stops checking is worse than one that stops working.
///
/// WHY a shared token and not mTLS: this is the platform-bring-up transport. Graduate
/// to mTLS/SPIFFE workload identity at platform scale.
pub fn authenticate_service<T>(expected: Option<&Arc<str>>, request: &Request<T>, seam: &str) -> Result<(), Status> {
	let Some(expected) = expected else {
		return Err(Status::unavailable(format!("{seam} not configured")));
	};
	match bearer_token(request) {
		Some(presented) if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) => Ok(()),
		_ => Err(Status::unauthenticated(format!("invalid {seam} service token"))),
	}
}

fn bearer_token<T>(request: &Request<T>) -> Option<String> {
	let value = request.metadata().get("authorization")?.to_str().ok()?;
	value.strip_prefix("Bearer ").map(str::to_owned)
}
