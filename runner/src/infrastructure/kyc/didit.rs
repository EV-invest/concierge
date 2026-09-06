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
			http: reqwest::Client::new(),
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

	/// `POST /v3/session/`. `vendor_data` carries the CASE id and nothing else: the
	/// vendor never receives a user id, an email or a name from us, so what it can leak
	/// about our identity space is a correlation handle.
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
/// WHY `X-Signature` (raw bytes) AND NOT `X-Signature-V2`. Didit recommends V2 because
/// it survives a middleware that re-serialises the body — it is computed over a
/// canonicalised JSON (keys sorted, floats shortened). We have no such middleware: axum
/// hands the handler a `Bytes` of exactly what arrived. Reproducing someone else's
/// canonicalisation byte-for-byte in Rust, on the other hand, is a way to be silently
/// and totally wrong — one float format or one key-ordering rule apart and EVERY
/// delivery fails the check. The raw bytes are the thing that was actually sent.
///
/// Shared with the stub adapter so the local and CI flow exercises this exact
/// verification rather than a bypass around it.
pub(super) fn parse_webhook(secret: &str, headers: &CallbackHeaders, body: &[u8], now: i64) -> Result<KycDecision, KycCallbackError> {
	verify_signature(secret, headers.signature.as_deref(), body)?;

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
	if let Some(signed_at) = payload.timestamp
		&& (now - signed_at).abs() > KYC_CALLBACK_WINDOW_SECS
	{
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
	})
}

/// Constant-time HMAC-SHA256 check over the raw body.
///
/// The comparison is `subtle::ConstantTimeEq`, so a near-miss and a wild guess take the
/// same time and the digest cannot be recovered a byte at a time. Hex-rendering our own
/// digest and lower-casing the caller's header are not secret-dependent, so they are
/// safe to do in the clear. The explicit length guard is what keeps `ct_eq` meaningful:
/// it answers "not equal" on a length mismatch, which alone would leave a wrong-length
/// signature indistinguishable from a wrong one of the right length.
fn verify_signature(secret: &str, presented: Option<&str>, body: &[u8]) -> Result<(), KycCallbackError> {
	let presented = presented.ok_or(KycCallbackError::BadSignature)?.trim().to_ascii_lowercase();
	let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).map_err(|_| KycCallbackError::BadSignature)?;
	mac.update(body);
	let expected = hex_lower(&mac.finalize().into_bytes());
	if presented.len() != expected.len() || !bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
		return Err(KycCallbackError::BadSignature);
	}
	Ok(())
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
	use std::fmt::Write;
	bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
		// Writing into a String is infallible; the Result exists only for the trait.
		let _ = write!(out, "{b:02x}");
		out
	})
}

/// Sign a body the way Didit does — the stub adapter's session flow and the tests both
/// need to produce a delivery this module will accept.
pub fn sign_body(secret: &str, body: &[u8]) -> String {
	let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
	mac.update(body);
	hex_lower(&mac.finalize().into_bytes())
}

/// Didit's status vocabulary, verbatim — spacing and capitalisation included.
///
/// An unrecognised value is a REFUSAL, not a shrug: a status we cannot classify might
/// be an approval, and guessing in either direction is worse than answering 400 and
/// letting the provider retry while a human reads the log line.
fn status_from_didit(raw: &str) -> Result<KycStatus, KycCallbackError> {
	match raw {
		"Not Started" => Ok(KycStatus::Pending),
		"In Progress" => Ok(KycStatus::InProgress),
		"In Review" => Ok(KycStatus::InReview),
		"Approved" => Ok(KycStatus::Approved),
		"Declined" => Ok(KycStatus::Declined),
		"Abandoned" => Ok(KycStatus::Abandoned),
		"Expired" => Ok(KycStatus::Expired),
		"Not Finished" => Ok(KycStatus::NotFinished),
		"KYC Expired" => Ok(KycStatus::KycExpired),
		other => Err(KycCallbackError::Malformed(format!("unknown didit status: {other}"))),
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

	fn headers(body: &[u8], now: i64) -> CallbackHeaders {
		CallbackHeaders {
			signature: Some(sign_body(SECRET, body)),
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
			timestamp: Some(later),
		};
		assert!(matches!(parse_webhook(SECRET, &restamped, &raw, later), Err(KycCallbackError::StaleTimestamp)));
	}

	#[test]
	fn every_documented_status_maps_and_nothing_else_does() {
		let now = 1_800_000_000;
		for (raw_status, expected) in [
			("Not Started", KycStatus::Pending),
			("In Progress", KycStatus::InProgress),
			("In Review", KycStatus::InReview),
			("Approved", KycStatus::Approved),
			("Declined", KycStatus::Declined),
			("Abandoned", KycStatus::Abandoned),
			("Expired", KycStatus::Expired),
			("Not Finished", KycStatus::NotFinished),
			("KYC Expired", KycStatus::KycExpired),
		] {
			let raw = body(raw_status, now);
			let decision = parse_webhook(SECRET, &headers(&raw, now), &raw, now).expect(raw_status);
			assert_eq!(decision.status, expected, "{raw_status}");
		}
		let raw = body("approved", now);
		assert!(
			matches!(parse_webhook(SECRET, &headers(&raw, now), &raw, now), Err(KycCallbackError::Malformed(_))),
			"the vocabulary is case-sensitive: a status we cannot classify is refused, never guessed"
		);
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
