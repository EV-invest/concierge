//! The auth service — the user/session issuance surface, mounted by the runner.
//!
//! Owns the signing keys, JWKS, Google client, and refresh store; serves the
//! issuance gRPC routes (`Exchange`/`Refresh`/`Logout`/`ListSessions`/
//! `RevokeSession`/`Jwks`). It provisions users in-process over the [`Provisioner`]
//! channel (auth → directory); the runner builds the channel, hands auth the
//! [`Provisioner`] half, and gives the receiver to the directory module (A1c).
//!
//! Unconfigured (no `AUTH_SIGNING_KEY_PEM`) it runs inert: issuance answers
//! [`AuthError::NotConfigured`], so the plane still boots locally with no signing key.

use std::sync::Arc;

use evconcierge_contracts::concierge::v1::{
	ExchangeRequest, JwksRequest, JwksResponse, ListSessionsRequest, ListSessionsResponse, LogoutRequest, LogoutResponse, RefreshRequest, RevokeSessionRequest, RevokeSessionResponse,
	Session, TokenResponse, UserSummary, auth_service_server::AuthService as AuthServiceRpc,
};
use tonic::{Request, Response, Status};

use crate::{
	AuthError,
	config::AuthConfig,
	google::GoogleOauth,
	management::{IssuedRefresh, RefreshStore, SessionBounds},
	provisioner::{ProvisionedUser, Provisioner},
	signer::{Signer, load_jwks},
};

/// The concierge plane's auth issuance service, mounted as a tonic server by the
/// runner. Cheaply cloneable (the engine is behind an `Arc`).
#[derive(Clone)]
pub struct AuthService {
	engine: Arc<AuthEngine>,
}

impl AuthService {
	/// Build the service from config and the [`Provisioner`] handle into the directory.
	/// With no signing key configured, every issuance route answers `NotConfigured`.
	pub async fn try_new(config: AuthConfig, provisioner: Provisioner) -> anyhow::Result<Self> {
		let (signer, jwks) = match &config.signing {
			Some(signing) => {
				let signer = Signer::try_new(signing, &config).map_err(|e| anyhow::anyhow!("auth signer init failed: {e}"))?;
				// The keyring is only the runner's inbound-verify concern (via the
				// Verifier over the Jwks RPC); issuance publishes the wire JWKs and mints.
				let (_keyring, jwks) = load_jwks(signing).map_err(|e| anyhow::anyhow!("auth jwks load failed: {e}"))?;
				(Some(signer), jwks)
			}
			None => (None, Vec::new()),
		};
		let google = config.google.as_ref().map(GoogleOauth::new);
		Ok(Self {
			engine: Arc::new(AuthEngine {
				signer,
				google,
				refresh: RefreshStore::from_env().await?,
				provisioner,
				jwks,
				session_bounds: SessionBounds {
					ttl_secs: config.refresh_ttl_secs,
					max_session_secs: config.max_session_secs,
					idle_timeout_secs: config.idle_timeout_secs,
				},
			}),
		})
	}

	/// Build an inert service: every route answers `unimplemented`/`NotConfigured`.
	/// Used only where a signing key and directory channel are not available (a bare
	/// boot before composition wires them).
	pub fn unconfigured() -> Self {
		let (provisioner, rx) = crate::provisioner::provisioner_channel();
		// Drop the receiver: any provision attempt then reports `Unavailable`, and with
		// no signer issuance short-circuits at `NotConfigured` before reaching it.
		drop(rx);
		Self {
			engine: Arc::new(AuthEngine {
				signer: None,
				google: None,
				refresh: RefreshStore::in_process(),
				provisioner,
				jwks: Vec::new(),
				session_bounds: SessionBounds {
					ttl_secs: 0,
					max_session_secs: 0,
					idle_timeout_secs: 0,
				},
			}),
		}
	}
}

struct AuthEngine {
	signer: Option<Signer>,
	google: Option<GoogleOauth>,
	refresh: RefreshStore,
	provisioner: Provisioner,
	jwks: Vec<evconcierge_contracts::concierge::v1::Jwk>,
	session_bounds: SessionBounds,
}

fn token_response(access_token: String, access_exp: u64, refresh: IssuedRefresh, summary: &ProvisionedUser) -> TokenResponse {
	TokenResponse {
		access_token,
		access_expires_at: access_exp as i64,
		refresh_token: refresh.token,
		refresh_expires_at: refresh.expires_at as i64,
		user: Some(UserSummary {
			user_id: summary.user_id.clone(),
			email: summary.email.clone(),
			status: summary.status.clone(),
			token_version: summary.token_version,
		}),
	}
}

#[tonic::async_trait]
impl AuthServiceRpc for AuthService {
	async fn exchange(&self, request: Request<ExchangeRequest>) -> Result<Response<TokenResponse>, Status> {
		let engine = &self.engine;
		let signer = engine.signer.as_ref().ok_or(AuthError::NotConfigured)?;
		let google = engine.google.as_ref().ok_or(AuthError::NotConfigured)?;
		let req = request.into_inner();

		let identity = google.exchange_code(&req.auth_code, &req.code_verifier, &req.redirect_uri, &req.nonce).await?;
		// Policy: an unverified Google email may sign in (the account is keyed by the
		// stable `sub`, and `email_verified` is persisted and surfaced end-to-end so
		// nothing is silently trusted); the directory never downgrades an already-verified
		// stored email to an unverified one.
		let summary = engine.provisioner.provision(identity.subject, identity.email, identity.email_verified).await?;
		if summary.is_disabled() {
			return Err(Status::permission_denied("user is disabled"));
		}

		let (access_token, access_exp) = signer.mint_access(&summary.user_id, summary.token_version)?;
		let refresh = engine
			.refresh
			.issue(&summary.user_id, summary.token_version, engine.session_bounds, req.user_agent, req.ip)
			.await?;
		Ok(Response::new(token_response(access_token, access_exp, refresh, &summary)))
	}

	async fn refresh(&self, request: Request<RefreshRequest>) -> Result<Response<TokenResponse>, Status> {
		let engine = &self.engine;
		let signer = engine.signer.as_ref().ok_or(AuthError::NotConfigured)?;
		let req = request.into_inner();

		let rotated = engine.refresh.rotate(&req.refresh_token, engine.session_bounds).await?;
		let summary = engine.provisioner.lookup(rotated.user_id.clone()).await?;
		if summary.is_disabled() {
			engine.refresh.revoke_user(&summary.user_id).await?;
			return Err(Status::permission_denied("user is disabled"));
		}
		// A "revoke all" since this family was issued bumps the authoritative
		// token_version in Postgres; refuse to mint and drop the family.
		if summary.token_version > rotated.token_version_snapshot {
			engine.refresh.revoke_user(&summary.user_id).await?;
			return Err(Status::unauthenticated("tokens revoked"));
		}

		let (access_token, access_exp) = signer.mint_access(&summary.user_id, summary.token_version)?;
		Ok(Response::new(token_response(access_token, access_exp, rotated.refresh, &summary)))
	}

	async fn logout(&self, request: Request<LogoutRequest>) -> Result<Response<LogoutResponse>, Status> {
		let engine = &self.engine;
		let req = request.into_inner();
		if req.revoke_all {
			if let Some(user_id) = engine.refresh.user_of(&req.refresh_token).await? {
				// Durable half: bump the authoritative token_version in the control plane.
				// Best-effort — dropping the refresh families below already ends every
				// session and access tokens expire within the short TTL, so a transient
				// control-plane blip must not fail the logout.
				if let Err(err) = engine.provisioner.revoke_all(user_id.clone()).await {
					crate::telemetry::report(&err);
				}
				engine.refresh.revoke_user(&user_id).await?;
			}
		} else {
			engine.refresh.revoke(&req.refresh_token).await?;
		}
		Ok(Response::new(LogoutResponse {}))
	}

	async fn list_sessions(&self, request: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
		let engine = &self.engine;
		let req = request.into_inner();
		let Some(user_id) = engine.refresh.user_of(&req.refresh_token).await? else {
			return Err(AuthError::InvalidToken.into());
		};
		let current_id = engine.refresh.family_id_of(&req.refresh_token).await?;
		let sessions = engine
			.refresh
			.list_for_user(&user_id)
			.await?
			.into_iter()
			.map(|s| Session {
				current: current_id.as_deref() == Some(s.id.as_str()),
				id: s.id,
				user_agent: s.user_agent,
				ip: s.ip,
				created_at: s.created_at as i64,
				last_seen: s.last_seen as i64,
			})
			.collect();
		Ok(Response::new(ListSessionsResponse { sessions }))
	}

	async fn revoke_session(&self, request: Request<RevokeSessionRequest>) -> Result<Response<RevokeSessionResponse>, Status> {
		let engine = &self.engine;
		let req = request.into_inner();
		let Some(user_id) = engine.refresh.user_of(&req.refresh_token).await? else {
			return Err(AuthError::InvalidToken.into());
		};
		engine.refresh.revoke_by_id(&user_id, &req.session_id).await?;
		Ok(Response::new(RevokeSessionResponse {}))
	}

	async fn jwks(&self, _request: Request<JwksRequest>) -> Result<Response<JwksResponse>, Status> {
		Ok(Response::new(JwksResponse { keys: self.engine.jwks.clone() }))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		claims::TokenType,
		config::SigningConfig,
		jwks::{VerifyPolicy, verify_token},
		provisioner::provisioner_channel,
	};

	// Same throwaway Ed25519 keypair as the signer tests.
	const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKolOSMXwE+tafZkX+jkKYJbmJ066f4E12wAwTIkKps6\n-----END PRIVATE KEY-----\n";
	const TEST_JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";

	async fn configured() -> AuthService {
		let config = AuthConfig {
			issuer: "https://auth.test".into(),
			client_audience: "concierge".into(),
			service_audience: "concierge-services".into(),
			access_ttl_secs: 900,
			refresh_ttl_secs: 3600,
			max_session_secs: 7_776_000,
			idle_timeout_secs: 0,
			service_ttl_secs: 300,
			signing: Some(SigningConfig {
				signing_key_pem: TEST_PEM.into(),
				kid: "test-kid".into(),
				jwks_json: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_JWK_X}","kid":"test-kid","alg":"EdDSA","use":"sig"}}]}}"#),
			}),
			google: None,
		};
		let (provisioner, _rx) = provisioner_channel();
		AuthService::try_new(config, provisioner).await.unwrap()
	}

	// Jwks publishes the configured public key so a downstream verifier can verify a
	// token this service minted: an end-to-end mint→publish→verify round trip that also
	// pins the access token's aud + typ separation.
	#[tokio::test]
	async fn jwks_publishes_a_verifiable_signing_key() {
		let service = configured().await;
		let response = service.jwks(Request::new(JwksRequest {})).await.unwrap().into_inner();
		assert_eq!(response.keys.len(), 1);
		assert_eq!(response.keys[0].kid, "test-kid");

		let signer = service.engine.signer.as_ref().unwrap();
		let (token, _) = signer.mint_access("00000000-0000-0000-0000-000000000001", 3).unwrap();
		let (cache, _) = load_jwks(
			&AuthConfig {
				issuer: "https://auth.test".into(),
				client_audience: "concierge".into(),
				service_audience: "concierge-services".into(),
				access_ttl_secs: 900,
				refresh_ttl_secs: 3600,
				max_session_secs: 7_776_000,
				idle_timeout_secs: 0,
				service_ttl_secs: 300,
				signing: Some(SigningConfig {
					signing_key_pem: TEST_PEM.into(),
					kid: "test-kid".into(),
					jwks_json: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_JWK_X}","kid":"test-kid","alg":"EdDSA","use":"sig"}}]}}"#),
				}),
				google: None,
			}
			.signing
			.unwrap(),
		)
		.unwrap();

		let access_policy = VerifyPolicy {
			issuer: "https://auth.test".into(),
			audiences: vec!["concierge".into()],
			allowed_types: vec![TokenType::Access],
		};
		let claims = verify_token(&token, &cache, &access_policy).unwrap();
		assert_eq!(claims.token_version, 3);

		// A service-only policy rejects this access token — the typ separation holds
		// through the published key path too.
		let service_policy = VerifyPolicy {
			issuer: "https://auth.test".into(),
			audiences: vec!["concierge-services".into()],
			allowed_types: vec![TokenType::Service],
		};
		assert!(verify_token(&token, &cache, &service_policy).is_err());
	}

	// An unconfigured service must not mint: Exchange short-circuits at NotConfigured
	// (mapped to UNAVAILABLE) rather than touching the dropped provisioner channel.
	#[tokio::test]
	async fn unconfigured_exchange_is_not_configured() {
		let service = AuthService::unconfigured();
		let status = service
			.exchange(Request::new(ExchangeRequest {
				auth_code: "x".into(),
				code_verifier: "y".into(),
				redirect_uri: "z".into(),
				nonce: "n".into(),
				user_agent: String::new(),
				ip: String::new(),
			}))
			.await
			.unwrap_err();
		assert_eq!(status.code(), tonic::Code::Unavailable);
	}

	// Refresh rotation + reuse detection runs through the real service surface (the
	// in-process refresh store), independent of the directory: a rotated-out refresh
	// token replayed against Refresh fails. Exercises the management hardening end to
	// end via the AuthService, with no DB and no signer needed for the rotation itself.
	#[tokio::test]
	async fn refresh_reuse_is_detected_through_the_service() {
		let service = configured().await;
		let engine = &service.engine;
		// Open a family directly via the store (provisioning is the directory's job).
		let issued = engine.refresh.issue("user-1", 0, engine.session_bounds, String::new(), String::new()).await.unwrap();
		let rotated = engine.refresh.rotate(&issued.token, engine.session_bounds).await.unwrap();
		assert_eq!(rotated.user_id, "user-1");
		// Replaying the original (now rotated-out) token is reuse → family revoked.
		assert!(engine.refresh.rotate(&issued.token, engine.session_bounds).await.is_err());
		assert!(engine.refresh.rotate(&rotated.refresh.token, engine.session_bounds).await.is_err());
	}
}
