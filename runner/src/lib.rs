#![feature(default_field_values)]
// `ev::settings!` expands one recursion level per field, and `AppConfig` has outgrown
// the default limit of 128.
#![recursion_limit = "256"]
//! `concierge` — the identity/platform-plane runner library.
//!
//! The modular monolith's internal modules, exposed as a library so the binary
//! (`main.rs`) composes them and integration tests (`tests/`) can drive the real
//! adapters against a live Postgres. Mirrors the banking hub's lib+bin split.
//!
//! Hexagonal layout over the shared `domain`:
//!   directory       — the user/profile gRPC service + the auth→directory provisioner loop
//!   bridge          — the cross-plane (identity→money) producer over the user_outbox
//!   bridge_tls      — the TLS listener that serves the bridge seams to the money plane
//!   platform        — the platform/cabinet config service (maintenance · announcement · flags)
//!   governance      — the consilia: the owner roster, owner admission/removal proposals,
//!                     the user proposals over suspension/reinstatement/`admin`, the
//!                     target's emailed approval surface, and the money plane's mail relay
//!   authz           — the shared RBAC gate (persisted role + status/revocation enforcement),
//!                     plus the emergency access that retires itself at the first owner
//!   genesis         — the boot-time seeding of the fund's first owner registry
//!   ports           — the driven-port traits (`UserDirectoryRepository`, `PlatformConfigRepository`,
//!                     `NotificationRepository`, `NotificationDispatchRepository`)
//!   infrastructure  — driven adapters (Postgres control plane + the port implementations)
//!   support         — cross-module gRPC plumbing (domain-error → Status mapping)
//!   web             — the site-level auth HTTP surface (login/callback/session cookies)
//!   notification    — the notification plane: subscribers, the in-app inbox, queued email
//!   dispatch        — the background loops: draining the outbound email queue, and the
//!                     hold sweep (the ONE thing here that sweeps — a lapse must be a
//!                     write, or the money plane never learns the account is unfrozen)
//!   log             — DEFERRED stub (no platform audit surface yet)

pub mod authz;
pub mod bridge;
pub mod bridge_tls;
pub mod config;
pub mod directory;
pub mod dispatch;
pub mod genesis;
pub mod governance;
pub mod infrastructure;
pub mod log;
pub mod notification;
pub mod platform;
pub mod ports;
pub mod support;
pub mod web;
