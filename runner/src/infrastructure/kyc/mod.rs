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

/// One adapter's configured URL as a WHATWG ORIGIN — `scheme://host[:port]` — or `None`
/// when the string has no origin to speak of.
///
/// The origin and not the host, because the host alone is not the boundary this is used
/// for: `https://verification.didit.me:8443/` shares a host with the vendor and is not
/// the vendor, and `https://verification.didit.me@evil.example/` shares a PREFIX with it
/// and is somebody else entirely. `Url::origin` settles both, lower-cases and punycodes
/// what it parsed, and is opaque (`is_tuple() == false`) for exactly the schemes a
/// browser must never be handed — `javascript:`, `data:`, `mailto:` — so an opaque
/// origin is `None` here rather than a string that could match one.
pub(crate) fn origin_of(raw: &str) -> Option<String> {
	let url = reqwest::Url::parse(raw).ok()?;
	let origin = url.origin();
	origin.is_tuple().then(|| origin.ascii_serialization())
}
