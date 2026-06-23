use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
	#[error("{entity} not found: {id}")]
	NotFound { entity: &'static str, id: String },
	#[error("conflict: {0}")]
	Conflict(String),
	#[error("validation failed: {0}")]
	Validation(String),
	/// A domain policy forbids the action for this caller. Distinct from
	/// `Validation` (bad input) — it maps to gRPC `permission_denied`, not
	/// `invalid_argument`.
	#[error("forbidden: {0}")]
	Forbidden(String),
	/// Unexpected failure from a driven adapter. Carries a description for logging
	/// only — it is never surfaced verbatim to clients.
	#[error("repository error: {0}")]
	Repository(String),
}
