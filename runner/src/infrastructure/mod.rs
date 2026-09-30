//! Infrastructure: driven adapters over the concrete external systems the
//! concierge plane runs on.
//!
//! - [`db`] — Postgres **control plane**: pool and migrations-on-boot.
//! - [`users`] — the user directory repository: upsert/profile/admin mutations,
//!   each emitting cross-plane lifecycle events to `user_outbox` in the write tx.
//! - [`notifications`] — subscribers, subscriptions, the in-app inbox, and the
//!   outbound email queue (`emit` writes the inbox row and the queued mail in one tx).
//! - [`kyc`] — identity verification: the vendor adapter (and its no-network twin) plus
//!   the `kyc_cases` store a webhook resolves an identity through. The level itself is
//!   written by [`users`], exactly the way an operator's decision is.
//! - [`governance`] — the ownership consilium: proposals, the snapshotted peer set,
//!   the target's emailed token, and the seat change itself (written through the
//!   `users` helpers, in the same transaction as the verdict).
//! - [`scoped_grants`] — a user's role over one resource (`allocation:<service_id>`),
//!   decided and audited inside the transaction that writes it.
//! - [`relying_parties`] — the registry of first-party clients on other origins, their
//!   one-time authorization codes and their refresh families (all secrets as digests).
//! - [`email`] — the SMTP transport seam and the rendered messages that cross it.

pub mod db;
pub mod email;
pub mod governance;
pub mod kyc;
pub mod notifications;
pub mod platform;
pub mod relying_parties;
pub mod scoped_grants;
pub mod users;
