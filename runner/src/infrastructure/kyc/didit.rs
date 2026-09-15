//! The Didit adapter — the live implementation of [`KycProvider`].
//!
//! Two halves, deliberately unequal in weight. Opening a session is one HTTP POST.
//! Accepting a verdict is the security-critical half, and it is a PURE function
//! ([`parse_webhook`]): signature, replay window, shape, status. No network, no
//! database, no clock of its own — so the code that decides whether an internet-facing,
//! unauthenticated POST is genuine can be exercised exhaustively by a test.

use async_trait::async_trait;
use domain::error::DomainError;
use hmac::{Hmac, Mac, digest::KeyInit};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::ports::{CallbackHeaders, KYC_CALLBACK_WINDOW_SECS, KycCallbackError, KycDecision, KycProvider, KycSession, KycStatus};

pub const PROVIDER: &str = "didit";

/// Ceiling on the one outbound call this adapter makes.
///
/// A vendor that accepts the connection and then never answers is the same outage as one
/// that refuses it — but without a deadline it would pin the request task open instead of
/// failing, and `/kyc/start` cannot degrade to "temporarily unavailable" for a call that
/// never returns. Opening a session is a single round trip, so the window is generous
/// rather than tight.
const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Where Didit serves the applicant-facing session page from.
///
/// NOT the API host. `DIDIT_BASE_URL` defaults to `https://verification.didit.me` and is
/// where `POST /v3/session/` goes; the `url` that call answers with is on
/// `verify.didit.me` (vendor docs, Create Session). Deriving the expected redirect host
/// from the API base — which is what this adapter did first — refuses EVERY real start
/// and takes verification down for everyone, arriving as silence.
///
/// A constant rather than an env var because it is a fact about the vendor, like the
/// `/v3/session/` path beside it, and a knob here is one more value to carry through the
/// deploy chain for a decision nobody is in a position to make at 3am. A sandbox or
/// self-hosted base URL is covered by [`DiditKyc::session_origins`] admitting the API
/// origin alongside it.
const SESSION_ORIGIN: &str = "https://verify.didit.me";

/// Everything the adapter needs from the environment, resolved once at boot.
pub struct DiditConfig {
	pub base_url: String,
	pub api_key: String,
	pub workflow_id: String,
	pub webhook_secret: String,
	/// Where Didit sends the BROWSER once the flow ends. A public, user-facing page —
	/// never the webhook path, which answers POST only.
	pub return_url: String,
}

pub struct DiditKyc {
	http: reqwest::Client,
	config: DiditConfig,
}

impl DiditKyc {
	pub fn new(config: DiditConfig) -> Self {
		Self {
			// `expect` on a builder that only fails when the TLS backend cannot be
			// initialised: that is a broken process, at boot, before any request exists
			// — the same class of failure as the CSPRNG being unavailable, and the same
			// treatment it already gets in `web::random_token`.
			http: reqwest::Client::builder().timeout(SESSION_TIMEOUT).build().expect("reqwest client (TLS backend unavailable)"),
			config,
		}
	}
}

#[derive(Deserialize)]
struct SessionResponse {
	session_id: String,
	url: String,
}

#[async_trait]
impl KycProvider for DiditKyc {
	fn name(&self) -> &'static str {
		PROVIDER
	}

	/// Two, and the second is not redundant.
	///
	/// [`SESSION_ORIGIN`] is where the vendor actually serves session pages. The origin
	/// of `DIDIT_BASE_URL` is admitted beside it so that a sandbox, a staging tenant or
	/// a self-hosted base keeps working without an edit here — it is still an origin an
	/// operator deliberately pointed this adapter at, which is the whole property being
	/// checked. It is admitted only when it is `https`: a base URL over plain http is a
	/// misconfiguration, and inheriting it here would let the redirect check pass
	/// something a browser must not be sent to.
	fn session_origins(&self) -> Vec<String> {
		let mut origins = vec![SESSION_ORIGIN.to_string()];
		if let Some(origin) = super::origin_of(&self.config.base_url).filter(|o| o.starts_with("https://") && o != SESSION_ORIGIN) {
			origins.push(origin);
		}
		origins
	}

	/// `POST /v3/session/`. `vendor_data` carries the CASE id and nothing else: the
	/// vendor never receives a user id, an email or a name from us, so what it can leak
	/// about our identity space is a correlation handle.
	///
	/// The tier is IGNORED, and that is why `PROVIDER_MAX_TIER` is 1. There is one
	/// configured workflow, so asking for a higher tier here would change nothing the
	/// vendor does while changing what we grant for the answer — which is the exact shape
	/// of the hole this parameter used to open. Honouring it means a second
	/// `DIDIT_WORKFLOW_ID_*`, selected here, and the ceiling raised in the same change.
	async fn start_session(&self, case_id: Uuid, _requested_tier: u32) -> Result<KycSession, DomainError> {
		let url = format!("{}/v3/session/", self.config.base_url.trim_end_matches('/'));
		let response = self
			.http
			.post(&url)
			.header("x-api-key", &self.config.api_key)
			.json(&json!({
				"workflow_id": self.config.workflow_id,
				"vendor_data": case_id.to_string(),
				"callback": self.config.return_url,
			}))
			.send()
			.await
			// Covers the refused connection, the DNS failure and the timeout alike. Every
			// one of them means the same thing to the caller — no session — so none of
			// them gets its own arm.
			.map_err(|e| DomainError::Repository(format!("didit: session request failed: {e}")))?;

		let status = response.status();
		if !status.is_success() {
			// The body may carry the vendor's own error detail; it is for our logs, never
			// for the caller (`DomainError::Repository` is not surfaced verbatim).
			let detail = response.text().await.unwrap_or_default();
			return Err(DomainError::Repository(format!("didit: session rejected with {status}: {detail}")));
		}

		let body: SessionResponse = response.json().await.map_err(|e| DomainError::Repository(format!("didit: unreadable session response: {e}")))?;
		if body.session_id.is_empty() || body.url.is_empty() {
			return Err(DomainError::Repository("didit: session response is missing session_id or url".to_string()));
		}
		Ok(KycSession {
			provider_ref: body.session_id,
			redirect_url: body.url,
		})
	}

	fn parse_callback(&self, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
		parse_webhook(&self.config.webhook_secret, headers, body, now)
	}
}

/// Authenticate and parse one Didit webhook delivery.
///
/// Shared with the stub adapter so the local and CI flow exercises this exact
/// verification rather than a bypass around it.
pub(super) fn parse_webhook(secret: &str, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
	verify_signature(secret, headers, body)?;

	// The transport timestamp first, per Didit's documented replay guidance...
	let sent_at = headers.timestamp.ok_or(KycCallbackError::StaleTimestamp)?;
	if (now - sent_at).abs() > KYC_CALLBACK_WINDOW_SECS {
		return Err(KycCallbackError::StaleTimestamp);
	}

	let payload: Webhook = serde_json::from_slice(body).map_err(|e| KycCallbackError::Malformed(format!("body is not a didit webhook: {e}")))?;

	// ...and then the body's own, which is the one that actually MEANS anything: only
	// the body is covered by the signature, so `X-Timestamp` alone can be re-stamped
	// freely on a captured delivery. Checking the signed copy is what makes the window
	// a replay defence rather than a formality.
	//
	// Which is exactly why its ABSENCE is `Malformed` and never a reason to fall back on
	// the header: a captured delivery whose body carries no `timestamp` would otherwise
	// stay replayable forever, since re-stamping the unsigned `X-Timestamp` costs an
	// attacker nothing. A defence that any of the hops in front of us — the Cloudflare
	// tunnel, Traefik, the rewrite in site_conductor — could switch off by dropping one
	// optional field is not a defence. The vendor documents the field, so requiring it
	// refuses forgeries, not deliveries.
	let signed_at = payload.timestamp.ok_or_else(|| KycCallbackError::Malformed("body carries no timestamp".to_string()))?;
	if (now - signed_at).abs() > KYC_CALLBACK_WINDOW_SECS {
		return Err(KycCallbackError::StaleTimestamp);
	}

	if payload.session_id.is_empty() {
		return Err(KycCallbackError::Malformed("body carries no session_id".to_string()));
	}
	let status = status_from_didit(&payload.status)?;

	let metadata = metadata_of(&payload);
	Ok(KycDecision {
		provider_ref: payload.session_id,
		status,
		vendor_data: payload.vendor_data.unwrap_or_default(),
		metadata,
		signed_at,
	})
}

/// A delivery is authentic when EITHER of the vendor's two signatures checks out.
///
/// WHY BOTH, and not the raw one alone. `X-Signature` covers the bytes exactly as sent;
/// `X-Signature-V2` covers a CANONICALISED re-serialisation, and it exists precisely
/// because intermediate hops re-pack JSON. Ours do: the delivery crosses a Cloudflare
/// tunnel, Traefik, and a Next.js rewrite in the site conductor before it reaches this
/// handler, and any one of them re-serialising the body would break the raw signature
/// for EVERY delivery at once. That failure is silent from a user's seat — verification
/// simply stops working — which makes "pick one and hope" the wrong bet.
///
/// Each check is self-sufficient, so the two failure modes cancel out: re-packing breaks
/// the raw signature and leaves V2 intact, while any disagreement over canonicalisation
/// (a float format, a key-ordering rule, an escape) breaks V2 and leaves the raw one
/// intact. Both would have to fail together to reject a genuine delivery, and neither
/// can be forged without the shared secret — trying two candidates does not weaken
/// anything, it is still one HMAC key.
///
/// V2 is tried first because it is the one the vendor recommends and the one that
/// survives our own topology.
///
/// Each individual comparison is `subtle::ConstantTimeEq`, so a near-miss and a wild
/// guess take the same time and the digest cannot be recovered a byte at a time.
/// Hex-rendering our own digest and lower-casing the caller's header are not
/// secret-dependent, so they are safe to do in the clear. The explicit length guard is
/// what keeps `ct_eq` meaningful: it answers "not equal" on a length mismatch, which
/// alone would leave a wrong-length signature indistinguishable from a wrong one of the
/// right length. Which of the two candidates matched is observable in the total time,
/// and that is fine: it reveals the shape of the delivery, never the key.
fn verify_signature(secret: &str, headers: &CallbackHeaders, body: &[u8]) -> Result<(), KycCallbackError> {
	if let Some(presented) = headers.signature_v2.as_deref()
		&& let Some(canonical) = canonical_v2(body)
		&& signature_matches(secret, presented, canonical.as_bytes())
	{
		return Ok(());
	}
	if let Some(presented) = headers.signature.as_deref()
		&& signature_matches(secret, presented, body)
	{
		return Ok(());
	}
	Err(KycCallbackError::BadSignature)
}

/// One constant-time HMAC-SHA256 comparison over `signed_bytes`.
fn signature_matches(secret: &str, presented: &str, signed_bytes: &[u8]) -> bool {
	let presented = presented.trim().to_ascii_lowercase();
	let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()) else {
		return false;
	};
	mac.update(signed_bytes);
	let expected = hex_lower(&mac.finalize().into_bytes());
	presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

/// Rebuild the exact string Didit signs for `X-Signature-V2`.
///
/// `None` when the body is not JSON at all — there is nothing to canonicalise, and the
/// raw signature is then the only candidate left.
pub(super) fn canonical_v2(body: &[u8]) -> Option<String> {
	let value: Value = serde_json::from_slice(body).ok()?;
	// `to_string` emits unescaped UTF-8 (the `ensure_ascii=False` equivalent), which is
	// what `JSON.stringify` does and therefore what was signed.
	serde_json::to_string(&canonicalise(value)).ok()
}

/// Keys sorted lexicographically, floats shortened, array order untouched — applied all
/// the way down.
fn canonicalise(value: Value) -> Value {
	match value {
		Value::Object(map) => {
			// Sorted EXPLICITLY rather than leaning on `serde_json::Map` being a
			// `BTreeMap`. It is one only while the `preserve_order` feature is off, and
			// cargo features are unified across the whole build: one unrelated crate
			// switching it on would turn `Map` into an insertion-ordered `IndexMap` and
			// silently invalidate every V2 signature we compute. Inserting in sorted
			// order is correct either way.
			let mut sorted: Vec<(String, Value)> = map.into_iter().collect();
			sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
			Value::Object(sorted.into_iter().map(|(k, v)| (k, canonicalise(v))).collect())
		}
		// Element ORDER carries meaning in a list and is preserved; only the elements
		// themselves are canonicalised.
		Value::Array(items) => Value::Array(items.into_iter().map(canonicalise).collect()),
		Value::Number(n) => shorten_float(n),
		other => other,
	}
}

/// `1.0` must serialise as `1`.
///
/// JavaScript has one number type and `JSON.stringify` drops a zero fraction on its own;
/// Rust keeps the `.0` and would sign a different string. Left alone above 2^53, where
/// an `f64` is no longer the integer that was sent and "shortening" it would change the
/// payload rather than reformat it.
fn shorten_float(n: serde_json::Number) -> Value {
	const EXACT_INTEGER_LIMIT: f64 = 9_007_199_254_740_992.0;
	if !n.is_f64() {
		return Value::Number(n);
	}
	match n.as_f64() {
		Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() <= EXACT_INTEGER_LIMIT => Value::Number(serde_json::Number::from(f as i64)),
		_ => Value::Number(n),
	}
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
	use std::fmt::Write;
	bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
		// Writing into a String is infallible; the Result exists only for the trait.
		let _ = write!(out, "{b:02x}");
		out
	})
}

/// Sign a body the way Didit signs `X-Signature-V2` — over the canonicalised form.
///
/// `None` for a body that is not JSON, which has no canonical form to sign.
pub fn sign_body_v2(secret: &str, body: &[u8]) -> Option<String> {
	canonical_v2(body).map(|canonical| sign_body(secret, canonical.as_bytes()))
}

/// Sign a body the way Didit signs `X-Signature` — over the raw bytes. The stub
/// adapter's session flow and the tests both need to produce a delivery this module will
/// accept.
pub fn sign_body(secret: &str, body: &[u8]) -> String {
	let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
	mac.update(body);
	hex_lower(&mac.finalize().into_bytes())
}

/// Didit's status vocabulary, verbatim — spacing and capitalisation included.
///
/// The comparison is case-SENSITIVE and that is not an oversight: a near-miss here is
/// invisible, because the arm simply never fires and the status falls through to the
/// catch-all. `"KYC Expired"` sat in this table for exactly that reason and would have
/// meant every aged-out verification was quietly unclassifiable. Copy the words from the
/// vendor's document; do not retype them from memory.
///
/// An unknown value is [`KycCallbackError::UnknownStatus`], NOT `Malformed`. The vendor
/// will add words to this list, and an endpoint that answers 400 to a delivery it merely
/// does not recognise turns a vocabulary change into an outage. Nothing is guessed
/// either way: an unclassifiable status moves no level (see the handler).
fn status_from_didit(raw: &str) -> Result<KycStatus, KycCallbackError> {
	match raw {
		"Not Started" => Ok(KycStatus::Pending),
		"In Progress" => Ok(KycStatus::InProgress),
		// KYB-only, and we run no KYB flow — but a status we can name is better handled
		// than routed through the unknown-status alarm, so it maps to the running state
		// it actually describes.
		"Awaiting User" => Ok(KycStatus::InProgress),
		"In Review" => Ok(KycStatus::InReview),
		"Resubmitted" => Ok(KycStatus::Resubmitted),
		"Approved" => Ok(KycStatus::Approved),
		"Declined" => Ok(KycStatus::Declined),
		"Abandoned" => Ok(KycStatus::Abandoned),
		"Expired" => Ok(KycStatus::Expired),
		"Kyc Expired" => Ok(KycStatus::KycExpired),
		other => Err(KycCallbackError::UnknownStatus(other.to_string())),
	}
}

/// The webhook body, narrowed to what we are willing to read.
#[derive(Deserialize)]
struct Webhook {
	#[serde(default)]
	session_id: String,
	#[serde(default)]
	status: String,
	#[serde(default)]
	vendor_data: Option<String>,
	#[serde(default)]
	timestamp: Option<i64>,
	#[serde(default)]
	event_id: Option<String>,
	#[serde(default)]
	webhook_type: Option<String>,
	#[serde(default)]
	workflow_id: Option<String>,
	#[serde(default)]
	environment: Option<String>,
	#[serde(default)]
	decision: Option<Value>,
}

/// Build `kyc_cases.payload` by ALLOWLIST, never by redaction.
///
/// The vendor's `decision` object carries document numbers, dates of birth, portrait
/// and document images or links to them. This plane has no object store and this change
/// is not the place to grow one, so nothing is copied unless it is named here: what kind
/// of document, which country issued it, and how each check came out. A field Didit adds
/// tomorrow is absent by construction rather than by our remembering to strip it.
fn metadata_of(payload: &Webhook) -> Value {
	let mut out = Map::new();
	let mut put = |key: &str, value: Option<&String>| {
		if let Some(v) = value.filter(|v| !v.is_empty()) {
			out.insert(key.to_string(), Value::String(v.clone()));
		}
	};
	put("event_id", payload.event_id.as_ref());
	put("webhook_type", payload.webhook_type.as_ref());
	put("workflow_id", payload.workflow_id.as_ref());
	put("environment", payload.environment.as_ref());

	let Some(decision) = payload.decision.as_ref() else {
		return Value::Object(out);
	};
	if let Some(kyc) = decision.get("kyc") {
		if let Some(document_type) = kyc.get("document_type").and_then(Value::as_str) {
			out.insert("document_type".to_string(), Value::String(document_type.to_string()));
		}
		// Didit names the issuing country `issuing_state`; some workflows only fill the
		// spelled-out name.
		if let Some(country) = kyc.get("issuing_state").or_else(|| kyc.get("issuing_state_name")).and_then(Value::as_str) {
			out.insert("document_country".to_string(), Value::String(country.to_string()));
		}
	}

	let mut checks = Map::new();
	for check in ["kyc", "id_verification", "face_match", "liveness", "aml"] {
		if let Some(status) = decision.get(check).and_then(|c| c.get("status")).and_then(Value::as_str) {
			checks.insert(check.to_string(), Value::String(status.to_string()));
		}
	}
	if !checks.is_empty() {
		out.insert("checks".to_string(), Value::Object(checks));
	}
	Value::Object(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	const SECRET: &str = "webhook-secret";

	fn adapter(base_url: &str) -> DiditKyc {
		DiditKyc::new(DiditConfig {
			base_url: base_url.to_string(),
			api_key: "k".to_string(),
			workflow_id: "w".to_string(),
			webhook_secret: SECRET.to_string(),
			return_url: "https://evinvest.test/cabinet".to_string(),
		})
	}

	/// The one that was wrong, and wrong in the direction that takes verification down
	/// for everybody.
	///
	/// `DIDIT_BASE_URL` defaults to the API host, `verification.didit.me`, and the session
	/// URL that API answers with is on `verify.didit.me`. Deriving the expected redirect
	/// from the base URL alone therefore refuses EVERY real start — a 503 per user,
	/// arriving as silence. Nothing in the integration suite can catch that: it runs the
	/// stub, whose two hosts happen to be the same one.
	#[test]
	fn the_live_adapter_expects_the_session_host_and_not_the_api_host() {
		let origins = adapter("https://verification.didit.me").session_origins();
		assert!(origins.contains(&"https://verify.didit.me".to_string()), "the host Didit serves session pages from: {origins:?}");
		assert!(
			origins.contains(&"https://verification.didit.me".to_string()),
			"and the API origin it was pointed at: {origins:?}"
		);
	}

	/// A sandbox or self-hosted base keeps working without an edit here — it is still an
	/// origin an operator deliberately configured.
	#[test]
	fn a_configured_base_url_is_admitted_beside_the_vendor_default() {
		assert_eq!(
			adapter("https://sandbox.didit.example/api/").session_origins(),
			vec!["https://verify.didit.me".to_string(), "https://sandbox.didit.example".to_string()]
		);
	}

	/// A base URL over plain http is a misconfiguration; inheriting it would let the
	/// redirect check pass something a browser must not be sent to.
	#[test]
	fn a_plaintext_or_unparsable_base_url_adds_nothing() {
		for base in ["http://verification.didit.me", "verification.didit.me", "", "not a url"] {
			assert_eq!(adapter(base).session_origins(), vec!["https://verify.didit.me".to_string()], "base: {base}");
		}
	}

	/// The RAW-signature form: `X-Signature` only, no V2 at all. Every pre-existing test
	/// keeps running through it, so the fallback path stays covered.
	fn headers(body: &[u8], now: i64) -> CallbackHeaders {
		CallbackHeaders {
			signature: Some(sign_body(SECRET, body)),
			signature_v2: None,
			timestamp: Some(now),
		}
	}

	/// The V2 form: only `X-Signature-V2`, and a raw signature that CANNOT match, which
	/// is what a hop that re-packed the JSON leaves behind.
	fn headers_v2_only(body: &[u8], now: i64) -> CallbackHeaders {
		CallbackHeaders {
			signature: Some(sign_body(SECRET, b"the bytes before some middlebox re-serialised them")),
			signature_v2: sign_body_v2(SECRET, body),
			timestamp: Some(now),
		}
	}

	fn body(status: &str, now: i64) -> Vec<u8> {
		serde_json::to_vec(&json!({
			"session_id": "sess-1",
			"status": status,
			"vendor_data": "case-1",
			"timestamp": now,
			"webhook_type": "status.updated",
			"decision": {
				"kyc": { "status": "Approved", "document_type": "Passport", "issuing_state": "PRT", "document_number": "X1234567" },
				"face_match": { "status": "Approved", "score": 93.1 },
			},
		}))
		.unwrap()
	}

	#[test]
	fn a_correctly_signed_delivery_parses() {
		let now = 1_800_000_000;
		let raw = body("Approved", now);
		let decision = parse_webhook(SECRET, &headers(&raw, now), &raw, now).expect("accepted");
		assert_eq!(decision.provider_ref, "sess-1");
		assert_eq!(decision.status, KycStatus::Approved);
		assert_eq!(decision.vendor_data, "case-1");
	}

	#[test]
	fn the_signature_covers_the_body_byte_for_byte() {
		let now = 1_800_000_000;
		let raw = body("Approved", now);
		let signed = headers(&raw, now);
		// One byte of the body changed under a signature minted for the original.
		let mut tampered = raw.clone();
		let last = tampered.len() - 1;
		tampered[last] = b' ';
		assert!(matches!(parse_webhook(SECRET, &signed, &tampered, now), Err(KycCallbackError::BadSignature)));
		// And the same body under the wrong secret.
		assert!(matches!(parse_webhook("other-secret", &signed, &raw, now), Err(KycCallbackError::BadSignature)));
	}

	#[test]
	fn a_replayed_delivery_falls_outside_the_window() {
		let sent = 1_800_000_000;
		let raw = body("Approved", sent);
		let signed = headers(&raw, sent);
		let later = sent + KYC_CALLBACK_WINDOW_SECS + 1;
		assert!(matches!(parse_webhook(SECRET, &signed, &raw, later), Err(KycCallbackError::StaleTimestamp)));

		// Re-stamping `X-Timestamp` does not rescue it: the body's own timestamp is the
		// one the signature covers, and it is what puts this delivery out of the window.
		let restamped = CallbackHeaders {
			signature: signed.signature.clone(),
			signature_v2: None,
			timestamp: Some(later),
		};
		assert!(matches!(parse_webhook(SECRET, &restamped, &raw, later), Err(KycCallbackError::StaleTimestamp)));
	}

	#[test]
	fn every_documented_status_maps_and_nothing_else_does() {
		let now = 1_800_000_000;
		// Didit's documented vocabulary, copied verbatim from the integration guide.
		// Capitalisation is load-bearing and is the point of this table: `"Kyc Expired"`
		// was once written `"KYC Expired"` here, and because the match is case-sensitive
		// the arm simply never fired — every aged-out verification fell through to the
		// catch-all with no symptom to notice.
		for (raw_status, expected) in [
			("Not Started", KycStatus::Pending),
			("In Progress", KycStatus::InProgress),
			// KYB-only; we run no KYB flow, but it is handled rather than alarmed on.
			("Awaiting User", KycStatus::InProgress),
			("In Review", KycStatus::InReview),
			("Resubmitted", KycStatus::Resubmitted),
			("Approved", KycStatus::Approved),
			("Declined", KycStatus::Declined),
			("Abandoned", KycStatus::Abandoned),
			("Expired", KycStatus::Expired),
			("Kyc Expired", KycStatus::KycExpired),
		] {
			let raw = body(raw_status, now);
			let decision = parse_webhook(SECRET, &headers(&raw, now), &raw, now).expect(raw_status);
			assert_eq!(decision.status, expected, "{raw_status}");
		}

		// A word we do not know is `UnknownStatus`, never `Malformed`: the delivery is
		// genuine and the route answers 200 to it (see `web::kyc::callback`). The
		// vocabulary is still case-sensitive — `"approved"` is not `"Approved"` — but
		// getting the case wrong now lands here rather than in a silent no-op.
		for unknown in ["approved", "Auto Approved", ""] {
			let raw = body(unknown, now);
			assert!(
				matches!(parse_webhook(SECRET, &headers(&raw, now), &raw, now), Err(KycCallbackError::UnknownStatus(_))),
				"{unknown:?}"
			);
		}
	}

	/// A `Resubmitted` verdict puts the attempt back in the user's hands. It must not
	/// grant anything and must not close the case, or the row would claim an outcome
	/// that has not happened.
	#[test]
	fn a_resubmission_moves_nothing_and_closes_nothing() {
		assert_eq!(KycStatus::Resubmitted.grants_tier(2), None);
		assert!(!KycStatus::Resubmitted.is_decided());
	}

	/// The case the whole dual-signature arrangement exists for: a hop between the
	/// vendor and us re-serialised the JSON, so `X-Signature` over the raw bytes cannot
	/// possibly match — and the delivery is still authentic.
	#[test]
	fn a_repacked_body_is_accepted_on_the_v2_signature_alone() {
		let now = 1_800_000_000;
		let raw = body("Approved", now);
		let repacked = canonical_v2(&raw).expect("json").into_bytes();

		let decision = parse_webhook(SECRET, &headers_v2_only(&repacked, now), &repacked, now).expect("V2 alone authenticates the delivery");
		assert_eq!(decision.status, KycStatus::Approved);
	}

	/// And the reverse: no V2 header at all (or one we cannot reproduce) still leaves the
	/// raw signature sufficient. Neither form is required.
	#[test]
	fn the_raw_signature_alone_is_still_enough() {
		let now = 1_800_000_000;
		let raw = body("Approved", now);

		let only_raw = CallbackHeaders {
			signature: Some(sign_body(SECRET, &raw)),
			signature_v2: None,
			timestamp: Some(now),
		};
		assert!(parse_webhook(SECRET, &only_raw, &raw, now).is_ok());

		// A V2 header that does not check out must not veto a good raw one.
		let bad_v2 = CallbackHeaders {
			signature: Some(sign_body(SECRET, &raw)),
			signature_v2: Some("00".repeat(32)),
			timestamp: Some(now),
		};
		assert!(parse_webhook(SECRET, &bad_v2, &raw, now).is_ok());
	}

	/// Two wrong signatures are still a rejection: accepting either does not mean
	/// accepting neither.
	#[test]
	fn a_delivery_with_neither_signature_valid_is_refused() {
		let now = 1_800_000_000;
		let raw = body("Approved", now);

		let forged = CallbackHeaders {
			signature: Some(sign_body("not-the-secret", &raw)),
			signature_v2: sign_body_v2("not-the-secret", &raw),
			timestamp: Some(now),
		};
		assert!(matches!(parse_webhook(SECRET, &forged, &raw, now), Err(KycCallbackError::BadSignature)));

		let absent = CallbackHeaders {
			signature: None,
			signature_v2: None,
			timestamp: Some(now),
		};
		assert!(matches!(parse_webhook(SECRET, &absent, &raw, now), Err(KycCallbackError::BadSignature)));
	}

	/// Canonicalisation, field by field, against the string JavaScript would have
	/// produced. Each of these is a way to be silently and totally wrong.
	#[test]
	fn the_canonical_form_matches_what_javascript_would_stringify() {
		// Keys sorted lexicographically, all the way down; array ORDER untouched.
		let nested = br#"{"b":1,"a":{"z":[3,1,2],"y":true}}"#;
		assert_eq!(canonical_v2(nested).unwrap(), r#"{"a":{"y":true,"z":[3,1,2]},"b":1}"#);

		// shortenFloats: a zero fraction is dropped, a real one is not. Rust would
		// otherwise print `1.0` where `JSON.stringify` prints `1`.
		let floats = br#"{"whole":1.0,"fraction":1.5,"nested":[2.0,{"k":-7.0}]}"#;
		assert_eq!(canonical_v2(floats).unwrap(), r#"{"fraction":1.5,"nested":[2,{"k":-7}],"whole":1}"#);

		// Unicode stays unescaped (`ensure_ascii=False`), as `JSON.stringify` leaves it.
		let unicode = "{\"name\":\"Ко́нстантин\"}".as_bytes();
		assert_eq!(canonical_v2(unicode).unwrap(), "{\"name\":\"Ко́нстантин\"}");

		// A body that is not JSON has no canonical form; the raw signature is then the
		// only candidate, and that is a `None` here rather than a panic.
		assert!(canonical_v2(b"not json at all").is_none());
	}

	/// The float rule has to survive a round trip through a real signature, not just a
	/// string comparison: `1.0` in a body must not be what breaks V2 in production.
	#[test]
	fn a_whole_float_does_not_break_the_v2_signature() {
		let now = 1_800_000_000;
		let raw = serde_json::to_vec(&json!({
			"session_id": "sess-1",
			"status": "Approved",
			"vendor_data": "case-1",
			"timestamp": now,
			"score": 1.0,
			"decision": { "kyc": { "status": "Approved", "confidence": 99.0 } },
		}))
		.unwrap();

		let decision = parse_webhook(SECRET, &headers_v2_only(&raw, now), &raw, now).expect("a whole float must not break V2");
		assert_eq!(decision.status, KycStatus::Approved);
	}

	#[test]
	fn the_payload_keeps_metadata_and_drops_the_document() {
		let now = 1_800_000_000;
		let raw = body("Approved", now);
		let decision = parse_webhook(SECRET, &headers(&raw, now), &raw, now).expect("accepted");
		let stored = serde_json::to_string(&decision.metadata).unwrap();
		assert!(!stored.contains("X1234567"), "a document number must never reach the database: {stored}");
		assert!(!stored.contains("document_number"), "the allowlist copies fields, it does not redact them: {stored}");
		assert_eq!(decision.metadata["document_type"], "Passport");
		assert_eq!(decision.metadata["document_country"], "PRT");
		assert_eq!(decision.metadata["checks"]["face_match"], "Approved");
	}

	/// RFC 4231 test case 2 — proof the HMAC under the signature check is the standard
	/// one, not something that merely agrees with itself.
	#[test]
	fn hmac_matches_the_published_vector() {
		assert_eq!(
			sign_body("Jefe", b"what do ya want for nothing?"),
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
		);
	}
}
