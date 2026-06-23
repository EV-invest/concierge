//! Downstream token verifier — what *other* service repos use.
//!
//! Holds the concierge plane's JWKS in a cache and verifies access/service tokens
//! entirely locally (no per-request round trip, no per-service token storage). The
//! cache is refreshed from the plane's `Jwks` gRPC RPC on construction and again on
//! an unknown-`kid` miss, so a key rotation heals without a restart. Plug it into
//! [`grpc_auth_layer`](crate::interceptor::grpc_auth_layer) to authorize inbound
//! gRPC, or call [`Verifier::verify`] directly.
//!
//! Scaffold: an [`Verifier::unconfigured`] holds an empty cache and every verify
//! answers [`AuthError::NotConfigured`] — the JWKS refresh pipeline is not wired.

use std::sync::Arc;

use crate::{AuthError, Claims, interceptor::Authenticate};

/// A cheaply-cloneable handle for local token verification.
#[derive(Clone)]
pub struct Verifier {
	#[allow(dead_code)]
	inner: Arc<Inner>,
}

impl Verifier {
	/// Build a verifier with an empty cache and no upstream wiring. In this scaffold
	/// every verify answers [`AuthError::NotConfigured`].
	pub fn unconfigured() -> Self {
		Self { inner: Arc::new(Inner {}) }
	}

	/// Verify a bearer token. Scaffold stub — returns [`AuthError::NotConfigured`].
	pub async fn verify(&self, _token: &str) -> Result<Claims, AuthError> {
		Err(AuthError::NotConfigured)
	}
}

struct Inner {}

impl Authenticate for Verifier {
	async fn authenticate(&self, token: String) -> Result<Claims, AuthError> {
		self.verify(&token).await
	}
}
