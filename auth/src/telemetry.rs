//! Observability seam — forwards unexpected auth failures to the shared
//! `ev::error_monitoring` library (Sentry).
//!
//! Auth runs in-process inside the concierge runner, which initialises Sentry for
//! the whole process; this seam reuses that client, so it is a no-op when Sentry is
//! unconfigured (and in consumers of this crate that never initialise it).
//!
//! Call [`report`] only for genuinely unexpected failures (5xx territory).
//! Expected auth outcomes — [`AuthError::InvalidToken`](crate::AuthError),
//! `UnknownKid`, `NotConfigured` — are client mistakes, not incidents.

/// Captures an unexpected error and forwards it to the error monitoring service.
pub fn report(err: &dyn std::error::Error) {
	ev::error_monitoring::report(err);
}

/// Reports `err` only when [`AuthError::is_unexpected`](crate::AuthError::is_unexpected)
/// says it is an operational incident; expected client outcomes stay quiet.
pub fn report_unexpected(err: &crate::AuthError) {
	if err.is_unexpected() {
		report(err);
	}
}
