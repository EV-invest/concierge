#![feature(default_field_values)]
//! Shared domain crate — the identity/platform plane.
//!
//! The single source of truth for `concierge` domain types. The runner binary
//! (`concierge`) depends on it, and so do other service repos and their wasm
//! frontends (it stays wasm-safe). It never depends on the runner, on
//! `evconcierge_auth`, or on any adapter.
//!
//! It carries the cross-cutting [`error::DomainError`], re-exports the `ev`
//! architecture building blocks, and holds the live identity bounded contexts:
//! [`auth`] (the IdP-asserted [`AuthSubject`](auth::AuthSubject)), [`authz`] (the
//! role/permission RBAC matrix), and [`users`] (the [`User`](users::User)
//! aggregate and its cross-plane lifecycle events).

pub mod auth;

pub mod authz;

pub mod error;

pub mod users;

/// Re-export of the `architecture` feature of the external `ev` crate — the
/// shared DDD tactical building blocks (`Id`, `Entity`, `AggregateRoot`,
/// `Repository`, `Gateway`, `UnitOfWork`, …) — so consumers reach them via
/// `domain::architecture::…` without depending on `ev` directly.
pub use ev::architecture;
