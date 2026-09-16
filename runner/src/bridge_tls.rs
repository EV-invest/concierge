//! `bridge_tls` — the TLS listener the money plane's bridge client dials.
//!
//! Phase 2 of EV-invest/banking#199. Until this listener exists, the only proof banking
//! has that a lifecycle event came from concierge is the bearer token banking itself
//! presents; nothing on the wire proves who ANSWERED. A batch of forged
//! `UserLifecycleEvent`s from whatever answers to the name `concierge` rewrites a KYC
//! tier or an operator role on the money plane. Server TLS with a CA banking pins
//! (`BRIDGE_TLS_CA_PEM_FILE` on its side) closes that direction; the optional client CA
//! turns the seam into mTLS, so the token stops being the only thing that proves the
//! caller too.
//!
//! WHY a second port and not TLS on `BIND`: 55670 has three cleartext callers that would
//! all have to move in one release — the in-process JWKS verifier
//! (`AUTH_JWKS_GRPC_ENDPOINT`), the cabinet BFF (`CONCIERGE_GRPC_ADDR`, a tonic client
//! with no TLS) and the gRPC-Web browser path (`accept_http1`). This listener serves
//! ONLY the two seams banking reaches through `CONCIERGE_BRIDGE_ADDR` — `UserEvents`
//! and `MailRelayService` — so the two planes can move one seam at a time.
//!
//! The rule is all-or-nothing and fails CLOSED: a bind with no key material, key
//! material with no bind, a client CA with no listener, or a path that does not read
//! are each a boot refusal with the variable named, never a listener quietly not
//! started. A deployment that looks TLS-configured and is not is exactly the state
//! nobody would check.

use std::net::SocketAddr;

use color_eyre::eyre::{Context, Result, bail};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use crate::config::AppConfig;

/// The four `BRIDGE_TLS_*` variables as read, before any file is touched.
#[derive(Debug, Clone, Copy, Default)]
pub struct Settings<'a> {
	pub bind: Option<SocketAddr>,
	pub cert_pem_file: Option<&'a str>,
	pub key_pem_file: Option<&'a str>,
	pub client_ca_pem_file: Option<&'a str>,
}

impl<'a> From<&'a AppConfig> for Settings<'a> {
	fn from(config: &'a AppConfig) -> Self {
		Self {
			bind: config.bridge_tls_bind,
			cert_pem_file: config.bridge_tls_cert_pem_file.as_deref(),
			key_pem_file: config.bridge_tls_key_pem_file.as_deref(),
			client_ca_pem_file: config.bridge_tls_client_ca_pem_file.as_deref(),
		}
	}
}

/// A listener whose variables agree with each other. Paths only — nothing read yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files {
	pub bind: SocketAddr,
	pub cert_pem_file: String,
	pub key_pem_file: String,
	pub client_ca_pem_file: Option<String>,
}

/// Decide whether a TLS listener is configured, and refuse a half-configured one.
///
/// `Ok(None)` is the ONLY silent outcome, and it needs all four variables unset.
pub fn configure(settings: Settings<'_>) -> Result<Option<Files>> {
	let Settings {
		bind,
		cert_pem_file,
		key_pem_file,
		client_ca_pem_file,
	} = settings;
	let Some(bind) = bind else {
		for (var, value) in [
			("BRIDGE_TLS_CERT_PEM_FILE", cert_pem_file),
			("BRIDGE_TLS_KEY_PEM_FILE", key_pem_file),
			("BRIDGE_TLS_CLIENT_CA_PEM_FILE", client_ca_pem_file),
		] {
			if value.is_some() {
				bail!(
					"{var} is set but BRIDGE_TLS_BIND is not: set BRIDGE_TLS_BIND to serve the bridge over TLS, or unset {var} — a listener that is half-configured is refused rather than skipped"
				);
			}
		}
		return Ok(None);
	};
	let missing = match (cert_pem_file, key_pem_file) {
		(Some(cert_pem_file), Some(key_pem_file)) =>
			return Ok(Some(Files {
				bind,
				cert_pem_file: cert_pem_file.to_string(),
				key_pem_file: key_pem_file.to_string(),
				client_ca_pem_file: client_ca_pem_file.map(str::to_string),
			})),
		(None, None) => "BRIDGE_TLS_CERT_PEM_FILE and BRIDGE_TLS_KEY_PEM_FILE are",
		(None, Some(_)) => "BRIDGE_TLS_CERT_PEM_FILE is",
		(Some(_), None) => "BRIDGE_TLS_KEY_PEM_FILE is",
	};
	bail!("BRIDGE_TLS_BIND={bind} but {missing} not set: the bridge listener cannot terminate TLS without its certificate and key")
}

/// Loaded key material for the listener.
///
/// No `Debug`: the private key is inside `identity`, and tonic's `Identity` derives
/// `Debug` over the raw bytes.
#[derive(Clone)]
pub struct Listener {
	pub bind: SocketAddr,
	identity: Identity,
	client_ca: Option<Certificate>,
}

impl Files {
	/// Read the PEM files. An unreadable path is a boot refusal naming the variable —
	/// the mounted-Secret layout puts every key at `/etc/settings/<KEY>`, and a typo
	/// there must not become a listener that is up and trusting nothing.
	pub fn load(&self) -> Result<Listener> {
		let cert = read_pem("BRIDGE_TLS_CERT_PEM_FILE", &self.cert_pem_file)?;
		let key = read_pem("BRIDGE_TLS_KEY_PEM_FILE", &self.key_pem_file)?;
		let client_ca = self.client_ca_pem_file.as_deref().map(|path| read_pem("BRIDGE_TLS_CLIENT_CA_PEM_FILE", path)).transpose()?;
		Ok(Listener {
			bind: self.bind,
			identity: Identity::from_pem(cert, key),
			client_ca: client_ca.map(Certificate::from_pem),
		})
	}
}

impl Listener {
	/// Whether callers must present a certificate signed by the configured client CA.
	pub fn is_mutual(&self) -> bool {
		self.client_ca.is_some()
	}

	/// The tonic server-side TLS config: this identity, plus a REQUIRED client cert
	/// when a client CA is set (never `client_auth_optional` — optional mTLS is
	/// cleartext-grade proof with extra steps).
	pub fn tls_config(&self) -> ServerTlsConfig {
		let config = ServerTlsConfig::new().identity(self.identity.clone());
		match &self.client_ca {
			Some(ca) => config.client_ca_root(ca.clone()),
			None => config,
		}
	}
}

/// Name the process-level rustls crypto provider, once, before any TLS config is built.
///
/// This binary links BOTH rustls providers — `ring` through sqlx and lettre,
/// `aws-lc-rs` through reqwest — and with two on the table rustls refuses to pick:
/// tonic's `ServerConfig::builder()` (and the client side's, under test) panics with
/// "could not automatically determine the process-level CryptoProvider" the first time
/// it runs. sqlx, lettre and reqwest each pass a provider explicitly, so nothing else
/// in the process ever settles the default. `ring` to match `tonic/tls-ring`. Idempotent:
/// a second call (tests share a process) finds it already installed and is a no-op.
pub fn install_crypto_provider() {
	// `Err` here means a provider is already installed, which is the outcome wanted.
	let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Validate the variables and read the files in one step, for the composition root.
pub fn from_config(config: &AppConfig) -> Result<Option<Listener>> {
	configure(Settings::from(config))?.as_ref().map(Files::load).transpose()
}

fn read_pem(var: &str, path: &str) -> Result<String> {
	let pem = std::fs::read_to_string(path).with_context(|| format!("failed to read {var} at {path}"))?;
	if pem.trim().is_empty() {
		bail!("{var} at {path} is empty");
	}
	Ok(pem)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bind() -> SocketAddr {
		"0.0.0.0:55672".parse().unwrap()
	}

	#[test]
	fn nothing_set_means_no_listener() {
		assert_eq!(configure(Settings::default()).unwrap(), None);
	}

	#[test]
	fn a_bind_without_key_material_is_refused_and_names_what_is_missing() {
		let err = configure(Settings {
			bind: Some(bind()),
			..Settings::default()
		})
		.unwrap_err();
		assert!(err.to_string().contains("BRIDGE_TLS_CERT_PEM_FILE and BRIDGE_TLS_KEY_PEM_FILE"), "{err}");

		let err = configure(Settings {
			bind: Some(bind()),
			cert_pem_file: Some("/etc/settings/BRIDGE_TLS_CERT_PEM"),
			..Settings::default()
		})
		.unwrap_err();
		assert!(err.to_string().contains("BRIDGE_TLS_KEY_PEM_FILE is not set"), "{err}");

		let err = configure(Settings {
			bind: Some(bind()),
			key_pem_file: Some("/etc/settings/BRIDGE_TLS_KEY_PEM"),
			..Settings::default()
		})
		.unwrap_err();
		assert!(err.to_string().contains("BRIDGE_TLS_CERT_PEM_FILE is not set"), "{err}");
	}

	#[test]
	fn key_material_or_a_client_ca_without_a_bind_is_refused() {
		for (label, settings) in [
			(
				"cert",
				Settings {
					cert_pem_file: Some("cert.pem"),
					..Settings::default()
				},
			),
			(
				"key",
				Settings {
					key_pem_file: Some("key.pem"),
					..Settings::default()
				},
			),
			(
				"client ca",
				Settings {
					client_ca_pem_file: Some("ca.pem"),
					..Settings::default()
				},
			),
		] {
			let err = configure(settings).expect_err(label);
			assert!(err.to_string().contains("BRIDGE_TLS_BIND is not"), "{label}: {err}");
		}
	}

	#[test]
	fn a_complete_configuration_keeps_every_path() {
		let files = configure(Settings {
			bind: Some(bind()),
			cert_pem_file: Some("cert.pem"),
			key_pem_file: Some("key.pem"),
			client_ca_pem_file: Some("ca.pem"),
		})
		.unwrap()
		.expect("configured");
		assert_eq!(
			files,
			Files {
				bind: bind(),
				cert_pem_file: "cert.pem".into(),
				key_pem_file: "key.pem".into(),
				client_ca_pem_file: Some("ca.pem".into()),
			}
		);
	}

	#[test]
	fn a_missing_file_fails_the_boot_and_names_the_variable() {
		let files = Files {
			bind: bind(),
			cert_pem_file: "/nonexistent/BRIDGE_TLS_CERT_PEM".into(),
			key_pem_file: "/nonexistent/BRIDGE_TLS_KEY_PEM".into(),
			client_ca_pem_file: None,
		};
		let Err(err) = files.load() else {
			panic!("a path that does not exist must not load");
		};
		let text = format!("{err:#}");
		assert!(text.contains("BRIDGE_TLS_CERT_PEM_FILE at /nonexistent/BRIDGE_TLS_CERT_PEM"), "{text}");
	}
}
