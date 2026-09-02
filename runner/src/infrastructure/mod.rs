//! Infrastructure: driven adapters over the concrete external systems the
//! concierge plane runs on.
//!
//! - [`db`] — Postgres **control plane**: pool and migrations-on-boot.
//! - [`users`] — the user directory repository: upsert/profile/admin mutations,
//!   each emitting cross-plane lifecycle events to `user_outbox` in the write tx.
//! - [`notifications`] — subscribers, subscriptions, the in-app inbox, and the
//!   outbound email queue (`emit` writes the inbox row and the queued mail in one tx).
//! - [`governance`] — the ownership consilium: proposals, the snapshotted peer set,
//!   the target's emailed token, and the seat change itself (written through the
//!   `users` helpers, in the same transaction as the verdict).
//! - [`email`] — the SMTP transport seam and the rendered messages that cross it.
//! - [`config_drift`] — watches the mounted settings Secret and warns when the
//!   values this process booted with stop matching it.

pub mod config_drift;
pub mod db;
pub mod email;
pub mod governance;
pub mod notifications;
pub mod platform;
pub mod users;
