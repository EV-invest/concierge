//! `concierge` — the identity/platform-plane runner library.
//!
//! The modular monolith's internal modules, exposed as a library so the binary
//! (`main.rs`) composes them and integration tests (`tests/`) can drive the real
//! adapters against a live Postgres. Mirrors the banking hub's lib+bin split.
//!
//! Hexagonal layout over the shared `domain`:
//!   directory       — the user/profile gRPC service + the auth→directory provisioner loop
//!   bridge          — the cross-plane (identity→money) producer over the user_outbox
//!   infrastructure  — driven adapters (Postgres control plane + the user directory repo)
//!   notification/log — DEFERRED stubs (no platform messaging/audit yet)

pub mod authz;
pub mod bridge;
pub mod config;
pub mod directory;
pub mod infrastructure;
pub mod log;
pub mod notification;
pub mod platform;
pub mod ports;
