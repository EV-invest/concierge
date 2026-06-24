//! Auth configuration — the issuing side ([`AuthConfig`], host-only) and the
//! downstream verifying side ([`VerifierConfig`]).
//!
//! Both read from the environment so the same binary runs unconfigured in local
//! dev and CI: with no signing key, the auth service mints nothing and authorizes
//! nothing (it answers [`AuthError::NotConfigured`](crate::AuthError)), exactly
//! like the rest of the scaffold's no-op-until-configured seams.

use std::env;

use anyhow::Context;

use crate::claims::TokenType;

/// This plane's identity token, asserted to appear in every configured issuer and
/// audience at boot. The two planes read the SAME `AUTH_*` env-var names and are kept
/// disjoint only by their default strings; if concierge is ever launched from a shared
/// environment that overrides those defaults to banking values, a banking token would
/// be byte-for-byte valid here. This boot check refuses such a config so the collision
/// can never fail open. Defense-in-depth — the two planes MUST never share an `AUTH_*`
/// environment in the first place.
const PLANE: &str = "concierge";

fn assert_plane(field: &str, value: &str) -> anyhow::Result<()> {
	anyhow::ensure!(
		value.contains(PLANE),
		"auth config {field} {value:?} does not carry this plane's identity ({PLANE:?}) — refusing to start with a cross-plane (or shared-environment) auth config"
	);
	Ok(())
}

/// Configuration for the auth **service** (the token-issuing side). Construct with
/// [`AuthConfig::from_env`] in the composition root.
#[derive(Clone, Debug)]
pub struct AuthConfig {
	/// Issuer (`iss`) stamped on every minted token and required by verifiers.
	pub issuer: String,
	/// Audience for client access tokens (the concierge plane).
	pub client_audience: String,
	/// Audience for inter-service tokens.
	pub service_audience: String,
	/// Access-token TTL (seconds). Short by design (5–15 min).
	pub access_ttl_secs: u64,
	/// Refresh-token TTL (seconds).
	pub refresh_ttl_secs: u64,
	/// Service-token TTL (seconds).
	pub service_ttl_secs: u64,
	/// Signing/verification key material. `None` ⇒ auth disabled (dev/CI).
	pub signing: Option<SigningConfig>,
	/// Google OAuth2 client credentials. `None` ⇒ the `Exchange` route is disabled.
	pub google: Option<GoogleConfig>,
}

impl AuthConfig {
	pub fn from_env() -> anyhow::Result<Self> {
		let signing = match (env::var("AUTH_SIGNING_KEY_PEM").ok(), env::var("AUTH_SIGNING_KID").ok(), env::var("AUTH_JWKS_JSON").ok()) {
			(Some(pem), Some(kid), Some(jwks)) if !pem.is_empty() && !kid.is_empty() && !jwks.is_empty() => Some(SigningConfig {
				signing_key_pem: pem,
				kid,
				jwks_json: jwks,
			}),
			_ => None,
		};
		let google = match (
			env::var("GOOGLE_CLIENT_ID").ok().filter(|s| !s.is_empty()),
			env::var("GOOGLE_CLIENT_SECRET").ok().filter(|s| !s.is_empty()),
		) {
			(Some(client_id), Some(client_secret)) => Some(GoogleConfig { client_id, client_secret }),
			_ => None,
		};
		let config = Self {
			issuer: env::var("AUTH_ISSUER").unwrap_or_else(|_| "https://auth.concierge.ev".to_string()),
			client_audience: env::var("AUTH_CLIENT_AUDIENCE").unwrap_or_else(|_| "concierge".to_string()),
			service_audience: env::var("AUTH_SERVICE_AUDIENCE").unwrap_or_else(|_| "concierge-services".to_string()),
			access_ttl_secs: parse_secs("AUTH_ACCESS_TTL_SECS", 900)?,
			refresh_ttl_secs: parse_secs("AUTH_REFRESH_TTL_SECS", 2_592_000)?,
			service_ttl_secs: parse_secs("AUTH_SERVICE_TTL_SECS", 300)?,
			signing,
			google,
		};
		config.assert_plane()?;
		Ok(config)
	}

	/// Refuse an issuing config whose issuer or either audience does not carry this
	/// plane's identity — so concierge can never mint (or verify) under banking's
	/// issuer/audience even if launched from a shared environment that overrides the
	/// per-binary defaults.
	pub fn assert_plane(&self) -> anyhow::Result<()> {
		assert_plane("AUTH_ISSUER", &self.issuer)?;
		assert_plane("AUTH_CLIENT_AUDIENCE", &self.client_audience)?;
		assert_plane("AUTH_SERVICE_AUDIENCE", &self.service_audience)
	}
}

/// The plane's own signing key plus the public JWKS it publishes and verifies against.
#[derive(Clone, Debug)]
pub struct SigningConfig {
	/// Ed25519 private key, PKCS#8 PEM (`AUTH_SIGNING_KEY_PEM`).
	pub signing_key_pem: String,
	/// Key id stamped in the JWT header and matched on verify (`AUTH_SIGNING_KID`).
	pub kid: String,
	/// Public JWKS as a JSON `{"keys":[...]}` (`AUTH_JWKS_JSON`) — served by the
	/// `Jwks` RPC and parsed into the verification key ring. Includes the active
	/// `kid` and any retired-but-still-valid keys (make-before-break rotation).
	pub jwks_json: String,
}

/// Google OAuth2 confidential-client credentials.
#[derive(Clone, Debug)]
pub struct GoogleConfig {
	pub client_id: String,
	pub client_secret: String,
}

/// Configuration a **downstream service** uses to build a [`Verifier`](crate::verifier::Verifier).
#[derive(Clone, Debug)]
pub struct VerifierConfig {
	/// Expected issuer (`iss`).
	pub issuer: String,
	/// Accepted audiences — a SET, not a single value, so the plane's own in-process
	/// verifier can accept the variety of audiences it itself issues.
	pub audiences: Vec<String>,
	/// Accepted token types (e.g. `[Access]` for a user-facing service).
	pub allowed_types: Vec<TokenType>,
	/// gRPC address of the concierge auth service, dialed to refresh the JWKS cache.
	pub jwks_grpc_endpoint: String,
}

impl VerifierConfig {
	pub fn from_env() -> anyhow::Result<Self> {
		let config = Self {
			issuer: env::var("AUTH_ISSUER").unwrap_or_else(|_| "https://auth.concierge.ev".to_string()),
			audiences: split_csv(&env::var("AUTH_CLIENT_AUDIENCE").unwrap_or_else(|_| "concierge".to_string())),
			allowed_types: vec![TokenType::Access],
			jwks_grpc_endpoint: env::var("AUTH_JWKS_GRPC_ENDPOINT").context("AUTH_JWKS_GRPC_ENDPOINT must be set for a downstream verifier")?,
		};
		config.assert_plane()?;
		Ok(config)
	}

	/// Refuse a verifier whose expected issuer or any accepted audience does not carry
	/// this plane's identity — so a downstream concierge service can never be pointed at
	/// banking's issuer/audience and accept banking tokens. Callers that build a
	/// [`VerifierConfig`] by hand (not via [`from_env`](Self::from_env)) MUST invoke this
	/// at boot to get the same guard.
	pub fn assert_plane(&self) -> anyhow::Result<()> {
		assert_plane("issuer", &self.issuer)?;
		for audience in &self.audiences {
			assert_plane("audience", audience)?;
		}
		Ok(())
	}
}

fn parse_secs(key: &str, default: u64) -> anyhow::Result<u64> {
	match env::var(key) {
		Ok(v) if !v.is_empty() => v.parse().with_context(|| format!("{key} must be a positive integer (seconds)")),
		_ => Ok(default),
	}
}

fn split_csv(raw: &str) -> Vec<String> {
	raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn issuing(issuer: &str, client_audience: &str, service_audience: &str) -> AuthConfig {
		AuthConfig {
			issuer: issuer.into(),
			client_audience: client_audience.into(),
			service_audience: service_audience.into(),
			access_ttl_secs: 900,
			refresh_ttl_secs: 2_592_000,
			service_ttl_secs: 300,
			signing: None,
			google: None,
		}
	}

	#[test]
	fn default_concierge_config_passes_plane_check() {
		issuing("https://auth.concierge.ev", "concierge", "concierge-services")
			.assert_plane()
			.expect("concierge defaults carry the plane identity");
	}

	#[test]
	fn banking_issuer_is_rejected() {
		let err = issuing("https://auth.banking.ev", "concierge", "concierge-services")
			.assert_plane()
			.expect_err("a banking issuer must be refused");
		assert!(err.to_string().contains("AUTH_ISSUER"), "error should name the offending field: {err}");
	}

	#[test]
	fn banking_audience_is_rejected() {
		assert!(
			issuing("https://auth.concierge.ev", "banking-core", "concierge-services").assert_plane().is_err(),
			"a banking client audience must be refused"
		);
		assert!(
			issuing("https://auth.concierge.ev", "concierge", "banking-services").assert_plane().is_err(),
			"a banking service audience must be refused"
		);
	}

	#[test]
	fn verifier_rejects_cross_plane_audience() {
		let cfg = VerifierConfig {
			issuer: "https://auth.concierge.ev".into(),
			audiences: vec!["banking-core".into()],
			allowed_types: vec![TokenType::Access],
			jwks_grpc_endpoint: "http://127.0.0.1:50062".into(),
		};
		assert!(cfg.assert_plane().is_err(), "a verifier pointed at a banking audience must be refused");
	}

	// Drives the real boot path: a banking-prefixed issuer in the environment must fail
	// `from_env` at startup. Serialized via a mutex + env restore because it mutates the
	// process environment (unsafe in edition 2024) shared by all tests in this binary.
	#[test]
	fn from_env_rejects_banking_issuer_at_boot() {
		static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
		let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
		let prior = env::var("AUTH_ISSUER").ok();
		unsafe { env::set_var("AUTH_ISSUER", "https://auth.banking.ev") };
		let result = AuthConfig::from_env();
		match prior {
			Some(v) => unsafe { env::set_var("AUTH_ISSUER", v) },
			None => unsafe { env::remove_var("AUTH_ISSUER") },
		}
		assert!(result.is_err(), "from_env must reject a banking issuer for the concierge plane");
	}
}
