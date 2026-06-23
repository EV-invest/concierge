//! JWKS public-key cache and local token verification.
//!
//! A [`JwksCache`] holds the concierge auth service's current signing public keys
//! (by `kid`). [`verify_token`] validates a token entirely against this cache — no
//! network call on the hot path — under an explicit [`VerifyPolicy`] (issuer +
//! accepted audiences + accepted token types), with the signing algorithm pinned
//! to EdDSA (never `none`, never HS*, never a header-chosen algorithm).
//!
//! Scaffold: the verification body is a stub returning
//! [`AuthError::NotConfigured`] until the real signer/JWKS pipeline lands.

use std::collections::HashMap;

use jsonwebtoken::DecodingKey;

use crate::{AuthError, Claims, claims::TokenType};

/// Cached JWKS public keys, indexed by `kid`.
#[derive(Default)]
pub struct JwksCache {
	keys: HashMap<String, DecodingKey>,
}

impl JwksCache {
	pub fn new() -> Self {
		Self::default()
	}

	/// Look up a decoding key by `kid`.
	pub fn get(&self, kid: &str) -> Option<&DecodingKey> {
		self.keys.get(kid)
	}

	/// Insert/replace a decoding key.
	pub fn insert(&mut self, kid: String, key: DecodingKey) {
		self.keys.insert(kid, key);
	}

	/// Replace the entire key set atomically (used by a JWKS refresh).
	pub fn replace(&mut self, keys: HashMap<String, DecodingKey>) {
		self.keys = keys;
	}

	pub fn is_empty(&self) -> bool {
		self.keys.is_empty()
	}
}

/// What a token must satisfy beyond a valid signature: the expected issuer, the
/// set of acceptable audiences, and the set of acceptable token types.
///
/// The audiences are a **set** on purpose. A downstream service pins exactly one
/// (`[svc-audience]`); the plane's own in-process verifier accepts the several
/// audiences it itself mints, so one verify core serves both.
#[derive(Clone, Debug)]
pub struct VerifyPolicy {
	pub issuer: String,
	pub audiences: Vec<String>,
	pub allowed_types: Vec<TokenType>,
}

/// Verify an access/service token against cached JWKS keys, returning its [`Claims`].
///
/// Stateless: no round trip, no token storage. Scaffold stub — the real
/// implementation selects the key by `kid`, pins the algorithm to EdDSA, then
/// validates the signature, `exp`, `iss`, `aud`, and `typ`.
pub fn verify_token(_token: &str, _cache: &JwksCache, _policy: &VerifyPolicy) -> Result<Claims, AuthError> {
	Err(AuthError::NotConfigured)
}
