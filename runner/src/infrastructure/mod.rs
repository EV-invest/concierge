//! Infrastructure: driven adapters over the concrete external systems the
//! concierge plane runs on.
//!
//! - [`db`] — Postgres **control plane**: pool and migrations-on-boot. The user
//!   directory repository and the cross-plane bridge outbox layer on top.

pub mod db;
