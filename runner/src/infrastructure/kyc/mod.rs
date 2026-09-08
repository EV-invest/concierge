//! Identity-verification adapters: the vendor behind [`crate::ports::KycProvider`] and
//! the Postgres store behind [`crate::ports::KycCaseRepository`].
//!
//! - [`didit`] — the live vendor, plus the signature/replay/parse logic every adapter
//!   shares;
//! - [`stub`] — the same webhook dialect with the network taken out, for local runs and
//!   the integration suite;
//! - [`cases`] — `kyc_cases`: the attempt rows a callback resolves an identity through.

pub mod cases;
pub mod didit;
pub mod stub;
