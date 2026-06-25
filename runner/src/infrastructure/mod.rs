//! Infrastructure: driven adapters over the concrete external systems the
//! concierge plane runs on.
//!
//! - [`db`] — Postgres **control plane**: pool and migrations-on-boot.
//! - [`users`] — the user directory repository: upsert/profile/admin mutations,
//!   each emitting cross-plane lifecycle events to `user_outbox` in the write tx.

pub mod db;
pub mod users;
