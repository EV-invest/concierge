//! The browser-facing half of the Google OAuth handshake (PKCE/state/nonce),
//! ported from the cabinet BFF — the confidential code→token exchange stays in
//! `evconcierge_auth::service` (called in-process by the callback route).

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::web::{now_secs, random_token};

const AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const SCOPE: &str = "openid email profile";
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

/// Build the Google authorize URL to redirect the browser to.
pub fn authorize_url(client_id: &str, redirect_uri: &str, state: &str, nonce: &str, code_challenge: &str) -> String {
	let query = form_urlencoded::Serializer::new(String::new())
		.append_pair("client_id", client_id)
		.append_pair("redirect_uri", redirect_uri)
		.append_pair("response_type", "code")
		.append_pair("scope", SCOPE)
		.append_pair("state", state)
		.append_pair("nonce", nonce)
		.append_pair("code_challenge", code_challenge)
		.append_pair("code_challenge_method", "S256")
		.append_pair("access_type", "online")
		.append_pair("prompt", "select_account")
		.finish();
	format!("{AUTHORIZE_ENDPOINT}?{query}")
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
	pub async fn put(&self, state: String, nonce: String, code_verifier: String, return_to: String) -> String {
		let id = random_token(32);
		let now = now_secs();
		let tx = OAuthTx {
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
