//! Infrastructure: driven adapters over the concrete external systems the
//! concierge plane runs on.
//!
//! - [`db`] — Postgres **control plane**: pool and migrations-on-boot.
//! - [`users`] — the user directory repository: upsert/profile/admin mutations,
//!   each emitting cross-plane lifecycle events to `user_outbox` in the write tx.
//! - [`notifications`] — subscribers, subscriptions, the in-app inbox, and the
//!   outbound email queue (`emit` writes the inbox row and the queued mail in one tx).
//! - [`email`] — the SMTP transport seam and the rendered messages that cross it.

pub mod db;
pub mod email;
pub mod notifications;
pub mod platform;
pub mod users;
