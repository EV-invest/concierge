//! Shared domain crate — the identity/platform plane.
//!
//! The single source of truth for `concierge` domain types. The runner binary
//! (`concierge`) depends on it, and so do other service repos and their wasm
//! frontends (it stays wasm-safe). It never depends on the runner, on
//! `evconcierge_auth`, or on any adapter.
//!
//! Scaffold: this seeds the cross-cutting [`error::DomainError`], re-exports the
//! `ev` architecture building blocks, and declares the identity bounded context.
//! The context module is a placeholder — value objects and ports land there as
//! real features arrive.

pub mod error;

pub mod users;

/// Re-export of the `architecture` feature of the external `ev` crate — the
/// shared DDD tactical building blocks (`Id`, `Entity`, `AggregateRoot`,
/// `Repository`, `Gateway`, `UnitOfWork`, …) — so consumers reach them via
/// `domain::architecture::…` without depending on `ev` directly.
pub use ev::architecture;
