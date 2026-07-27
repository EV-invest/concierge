#![feature(default_field_values)]
//! `concierge` — the identity/platform-plane runner library.
//!
//! The modular monolith's internal modules, exposed as a library so the binary
//! (`main.rs`) composes them and integration tests (`tests/`) can drive the real
//! adapters against a live Postgres. Mirrors the banking hub's lib+bin split.
//!
//! Hexagonal layout over the shared `domain`:
//!   directory       — the user/profile gRPC service + the auth→directory provisioner loop
//!   bridge          — the cross-plane (identity→money) producer over the user_outbox
//!   platform        — the platform/cabinet config service (maintenance · announcement · flags)
//!   authz           — the shared RBAC gate (persisted role + status/revocation enforcement)
//!   ports           — the driven-port traits (`UserDirectoryRepository`, `PlatformConfigRepository`,
//!                     `NotificationRepository`, `NotificationDispatchRepository`)
//!   infrastructure  — driven adapters (Postgres control plane + the port implementations)
//!   support         — cross-module gRPC plumbing (domain-error → Status mapping)
//!   web             — the site-level auth HTTP surface (login/callback/session cookies)
//!   notification    — the notification plane: subscribers, the in-app inbox, queued email
//!   dispatch        — the background loop draining the outbound email queue
//!   log             — DEFERRED stub (no platform audit surface yet)

pub mod authz;
pub mod bridge;
pub mod config;
pub mod directory;
pub mod dispatch;
pub mod infrastructure;
pub mod log;
pub mod notification;
pub mod platform;
pub mod ports;
pub mod support;
pub mod web;
