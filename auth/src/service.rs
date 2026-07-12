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
	management::{IssuedRefresh, RefreshInspect, RefreshStore, SessionBounds},
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
	pub async fn try_new(config: AuthConfig, provisioner: Provisioner) -> color_eyre::Result<Self> {
		let (signer, jwks) = match &config.signing {
			Some(signing) => {
				let signer = Signer::try_new(signing, &config).map_err(|e| color_eyre::eyre::eyre!("auth signer init failed: {e}"))?;
				// The keyring is only the runner's inbound-verify concern (via the
				// Verifier over the Jwks RPC); issuance publishes the wire JWKs and mints.
				let (_keyring, jwks) = load_jwks(signing).map_err(|e| color_eyre::eyre::eyre!("auth jwks load failed: {e}"))?;
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
			role: summary.role.clone(),
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

		// `exchange` is served on the public, un-wrapped server — outside the reporting
		// interceptor — so operational failures must be reported here or never.
		let identity = google
			.exchange_code(&req.auth_code, &req.code_verifier, &req.redirect_uri, &req.nonce)
			.await
			.inspect_err(crate::telemetry::report_unexpected)?;
		// Policy: an unverified Google email may sign in (the account is keyed by the
		// stable `sub`, and `email_verified` is persisted and surfaced end-to-end so
		// nothing is silently trusted); the directory never downgrades an already-verified
		// stored email to an unverified one.
		let summary = engine
			.provisioner
			.provision(identity.subject, identity.email, identity.email_verified)
			.await
			.inspect_err(crate::telemetry::report_unexpected)?;
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

		// Classify the presented handle WITHOUT rotating it, and run the fallible directory
		// lookup BEFORE the irreversible rotation. Rotating first would advance `prev`, so a
		// transient lookup failure would make the client's retry (with the same, now
		// rotated-out token) trip reuse detection and revoke the whole family. Reuse
		// detection is preserved: a replayed rotated-out secret is caught here as `Reuse`
		// and revokes the family, exactly as the destructive rotate would.
		let user_id = match engine.refresh.inspect(&req.refresh_token, engine.session_bounds).await? {
			RefreshInspect::Current { user_id } => user_id,
			RefreshInspect::Reuse { user_id } => {
				engine.refresh.revoke_user(&user_id).await?;
				return Err(AuthError::InvalidToken.into());
			}
			RefreshInspect::Invalid => return Err(AuthError::InvalidToken.into()),
		};

		// Same un-wrapped public server as `exchange`: a directory outage here must
		// alert too, not just render UNAVAILABLE.
		let summary = engine.provisioner.lookup(user_id).await.inspect_err(crate::telemetry::report_unexpected)?;
		if summary.is_disabled() {
			engine.refresh.revoke_user(&summary.user_id).await?;
			return Err(Status::permission_denied("user is disabled"));
		}

		// The fallible checks passed — commit the (irreversible) rotation now.
		let rotated = engine.refresh.rotate(&req.refresh_token, engine.session_bounds).await?;
		// A "revoke all" since this family was issued bumps the authoritative token_version
		// in Postgres; refuse to mint and drop the family. (A pure comparison, so running it
		// after the rotation is safe — the family is dropped on mismatch regardless.)
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
		// Authorize on the full credential (the secret), not the family-id prefix, so a
		// leaked/rotated-out token cannot force-logout a victim.
		let RefreshInspect::Current { user_id, .. } = engine.refresh.inspect(&req.refresh_token, engine.session_bounds).await? else {
			return Err(AuthError::InvalidToken.into());
		};
		if req.revoke_all {
			// Durable half: bump the authoritative token_version in the control plane.
			// Best-effort — dropping the refresh families below already ends every
			// session and access tokens expire within the short TTL, so a transient
			// control-plane blip must not fail the logout.
			if let Err(err) = engine.provisioner.revoke_all(user_id.clone()).await {
				crate::telemetry::report(&err);
			}
			engine.refresh.revoke_user(&user_id).await?;
		} else {
			engine.refresh.revoke(&req.refresh_token).await?;
		}
		Ok(Response::new(LogoutResponse {}))
	}

	async fn list_sessions(&self, request: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
		let engine = &self.engine;
		let req = request.into_inner();
		// Authorize on the secret, not the family-id prefix — else a leaked handle would
		// disclose every session's device/IP metadata for the family.
		let RefreshInspect::Current { user_id, .. } = engine.refresh.inspect(&req.refresh_token, engine.session_bounds).await? else {
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
		// Authorize on the secret, not the family-id prefix — else a leaked handle could
		// revoke any of the victim's sessions (targeted DoS).
		let RefreshInspect::Current { user_id, .. } = engine.refresh.inspect(&req.refresh_token, engine.session_bounds).await? else {
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
		provisioner::{ProvisionCommand, provisioner_channel},
	};

	// Same throwaway Ed25519 keypair as the signer tests.
	const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKolOSMXwE+tafZkX+jkKYJbmJ066f4E12wAwTIkKps6\n-----END PRIVATE KEY-----\n";
	const TEST_JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";

	fn test_config() -> AuthConfig {
		AuthConfig {
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
	}

	async fn configured() -> AuthService {
		let (provisioner, _rx) = provisioner_channel();
		AuthService::try_new(test_config(), provisioner).await.unwrap()
	}

	/// A configured service whose directory half is a stub loop answering every
	/// provisioning command with `respond`'s result — so refresh's post-lookup
	/// branches (disabled user, token_version bump, successful mint) are drivable
	/// through the RPC handler without Postgres.
	async fn configured_with_directory<F>(mut respond: F) -> AuthService
	where
		F: FnMut(ProvisionCommand) -> Result<ProvisionedUser, AuthError> + Send + 'static, {
		let (provisioner, mut rx) = provisioner_channel();
		tokio::spawn(async move {
			while let Some(req) = rx.recv().await {
				let _ = req.respond_to.send(respond(req.command));
			}
		});
		AuthService::try_new(test_config(), provisioner).await.unwrap()
	}

	// Distinct user ids per test: with `REDIS_URL` set the refresh store is one shared
	// Redis, and these tests revoke whole families — a shared id would let parallel
	// tests revoke each other's.
	fn active_user(user_id: &str, token_version: u64) -> ProvisionedUser {
		ProvisionedUser {
			user_id: user_id.into(),
			email: "user@test".into(),
			status: "active".into(),
			token_version,
			role: "investor".into(),
		}
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
		let (cache, _) = load_jwks(&test_config().signing.unwrap()).unwrap();

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

	// Reuse detection through the Refresh RPC itself: replaying a rotated-out handle
	// answers Unauthenticated AND revokes the whole family — the sibling CURRENT
	// token dies with it. (The reuse branch precedes the directory lookup, so the
	// dropped provisioner receiver is never reached.)
	#[tokio::test]
	async fn refresh_rpc_revokes_the_family_on_reuse() {
		let service = configured().await;
		let engine = &service.engine;
		// Open a family directly via the store (provisioning is the directory's job).
		let issued = engine.refresh.issue("user-reuse", 0, engine.session_bounds, String::new(), String::new()).await.unwrap();
		let rotated = engine.refresh.rotate(&issued.token, engine.session_bounds).await.unwrap();

		let status = service.refresh(Request::new(RefreshRequest { refresh_token: issued.token })).await.unwrap_err();
		assert_eq!(status.code(), tonic::Code::Unauthenticated);
		assert!(matches!(
			engine.refresh.inspect(&rotated.refresh.token, engine.session_bounds).await.unwrap(),
			RefreshInspect::Invalid
		));
	}

	// The inspect→lookup→rotate ordering invariant: a transient directory failure must
	// NOT advance the family, or the client's legitimate retry (same token) would trip
	// reuse detection and revoke every session. The retry must instead mint — which
	// also pins the token_version comparison as strict (an equal version passes).
	#[tokio::test]
	async fn refresh_rpc_survives_a_transient_directory_failure() {
		let mut fail_once = true;
		let service = configured_with_directory(move |_| {
			if std::mem::take(&mut fail_once) {
				Err(AuthError::Unavailable)
			} else {
				Ok(active_user("user-retry", 0))
			}
		})
		.await;
		let engine = &service.engine;
		let issued = engine.refresh.issue("user-retry", 0, engine.session_bounds, String::new(), String::new()).await.unwrap();

		let status = service
			.refresh(Request::new(RefreshRequest {
				refresh_token: issued.token.clone(),
			}))
			.await
			.unwrap_err();
		assert_eq!(status.code(), tonic::Code::Unavailable);
		// Not rotated: the same handle is still the family's CURRENT secret.
		assert!(matches!(engine.refresh.inspect(&issued.token, engine.session_bounds).await.unwrap(), RefreshInspect::Current { user_id } if user_id == "user-retry"));

		let response = service
			.refresh(Request::new(RefreshRequest {
				refresh_token: issued.token.clone(),
			}))
			.await
			.unwrap()
			.into_inner();
		assert!(!response.access_token.is_empty());
		assert_eq!(response.user.unwrap().user_id, "user-retry");
		// The retry rotated the family: the presented handle is now spent.
		assert!(matches!(
			engine.refresh.inspect(&issued.token, engine.session_bounds).await.unwrap(),
			RefreshInspect::Reuse { .. }
		));
	}

	// An operator "revoke all" (authoritative token_version bump) beats a refresh
	// token minted under the old version: Unauthenticated, and the family is dropped
	// so no handle from it — including the one just rotated in — survives.
	#[tokio::test]
	async fn refresh_rpc_drops_the_family_after_a_token_version_bump() {
		let service = configured_with_directory(|_| Ok(active_user("user-bump", 1))).await;
		let engine = &service.engine;
		let issued = engine.refresh.issue("user-bump", 0, engine.session_bounds, String::new(), String::new()).await.unwrap();

		let status = service
			.refresh(Request::new(RefreshRequest {
				refresh_token: issued.token.clone(),
			}))
			.await
			.unwrap_err();
		assert_eq!(status.code(), tonic::Code::Unauthenticated);
		assert_eq!(status.message(), "tokens revoked");
		// Invalid, not Reuse: the family is gone entirely, not merely rotated past.
		assert!(matches!(engine.refresh.inspect(&issued.token, engine.session_bounds).await.unwrap(), RefreshInspect::Invalid));
	}

	// A user disabled since sign-in cannot refresh: PermissionDenied, and the whole
	// family is revoked.
	#[tokio::test]
	async fn refresh_rpc_revokes_the_family_of_a_disabled_user() {
		let service = configured_with_directory(|_| {
			Ok(ProvisionedUser {
				status: "disabled".into(),
				..active_user("user-disabled", 0)
			})
		})
		.await;
		let engine = &service.engine;
		let issued = engine.refresh.issue("user-disabled", 0, engine.session_bounds, String::new(), String::new()).await.unwrap();

		let status = service
			.refresh(Request::new(RefreshRequest {
				refresh_token: issued.token.clone(),
			}))
			.await
			.unwrap_err();
		assert_eq!(status.code(), tonic::Code::PermissionDenied);
		assert!(matches!(engine.refresh.inspect(&issued.token, engine.session_bounds).await.unwrap(), RefreshInspect::Invalid));
	}
}
