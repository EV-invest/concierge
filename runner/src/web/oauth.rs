//! The browser-facing half of an OAuth handshake (PKCE/state/nonce): the transaction
//! between the redirect out and the callback. The provider's own half — its URLs and the
//! code→identity exchange — is `evconcierge_auth::oauth::OAuthProvider`.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::web::{now_secs, random_token};

/// The OAuth handshake (PKCE/state/nonce) lives at most this long between authorize and callback.
pub const OAUTH_TX_TTL: i64 = 600;
/// Hard cap on in-flight OAuth txns. The unauthenticated login route feeds this map,
/// so an evict-on-write past the TTL isn't enough on its own — a flood inside one TTL
/// window could still grow it. The cap bounds memory regardless; at capacity the oldest
/// entry is dropped (that abandoned login simply has to restart). Upstream rate-limiting
/// is the first line of defense; this is defense-in-depth.
const MAX_OAUTH_TXNS: usize = 10_000;

/// A fresh PKCE verifier/challenge plus anti-forgery state and nonce.
pub struct Challenge {
	pub state: String,
	pub nonce: String,
	pub code_verifier: String,
	pub code_challenge: String,
}

impl Challenge {
	pub fn new() -> Self {
		let code_verifier = random_token(32);
		let code_challenge = {
			use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
			URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
		};
		Self {
			state: random_token(16),
			nonce: random_token(16),
			code_verifier,
			code_challenge,
		}
	}
}

/// Keep a post-login redirect target same-origin to defeat open-redirects.
pub fn safe_return_to(raw: Option<&str>) -> String {
	let Some(raw) = raw else { return "/".to_string() };
	if !raw.starts_with('/') {
		return "/".to_string();
	}
	// Reject protocol-relative ("//evil", "/\evil") and any backslash.
	let second = raw.as_bytes().get(1).copied();
	if second == Some(b'/') || second == Some(b'\\') || raw.contains('\\') {
		return "/".to_string();
	}
	raw.to_string()
}

/// One in-flight OAuth login transaction, bound to the `ev_oauth_tx` cookie.
#[derive(Clone)]
pub struct OAuthTx {
	/// The provider the browser was sent to; its callback must be the one answering.
	pub provider: &'static str,
	pub state: String,
	pub nonce: String,
	pub code_verifier: String,
	pub return_to: String,
	created_at: i64,
}

/// The OAuth transaction store. In-process map (single-instance/dev), keyed by the
/// HttpOnly `ev_oauth_tx` cookie so only the browser that started the flow can complete it.
pub struct OAuthTxStore {
	txns: Mutex<HashMap<String, OAuthTx>>,
}

impl OAuthTxStore {
	pub fn new() -> Self {
		Self { txns: Mutex::new(HashMap::new()) }
	}

	/// Store a transaction, returning its id (the `ev_oauth_tx` cookie value). Evicts on
	/// write: abandoned logins never replay their cookie, so `take` never frees them — drop
	/// every expired entry here, and if the cap is still hit, drop the oldest.
	pub async fn put(&self, provider: &'static str, state: String, nonce: String, code_verifier: String, return_to: String) -> String {
		let id = random_token(32);
		let now = now_secs();
		let tx = OAuthTx {
			provider,
			state,
			nonce,
			code_verifier,
			return_to,
			created_at: now,
		};
		let mut txns = self.txns.lock().await;
		txns.retain(|_, t| now - t.created_at <= OAUTH_TX_TTL);
		if txns.len() >= MAX_OAUTH_TXNS
			&& let Some(oldest) = txns.iter().min_by_key(|(_, t)| t.created_at).map(|(k, _)| k.clone())
		{
			txns.remove(&oldest);
		}
		txns.insert(id.clone(), tx);
		id
	}

	/// Read + consume the transaction for `id`, if present and unexpired.
	pub async fn take(&self, id: &str) -> Option<OAuthTx> {
		let tx = self.txns.lock().await.remove(id)?;
		(now_secs() - tx.created_at <= OAUTH_TX_TTL).then_some(tx)
	}
}
