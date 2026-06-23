//! The auth service — the user/session issuance surface, mounted by the runner.
//!
//! Owns (will own) the signing keys, JWKS, Google client, and refresh store; serves
//! the issuance gRPC routes (`Exchange`/`Refresh`/`Logout`/`ListSessions`/
//! `RevokeSession`/`Jwks`). The runner mounts it as
//! `AuthServiceServer::new(AuthService::unconfigured())`.
//!
//! Scaffold: [`AuthService::unconfigured`] runs inert — every route answers
//! `unimplemented`, so the plane still boots locally with no signing key.

use evconcierge_contracts::concierge::v1::{
	ExchangeRequest, JwksRequest, JwksResponse, ListSessionsRequest, ListSessionsResponse, LogoutRequest, LogoutResponse, RefreshRequest, RevokeSessionRequest, RevokeSessionResponse,
	TokenResponse, auth_service_server::AuthService as AuthServiceRpc,
};
use tonic::{Request, Response, Status};

/// The concierge plane's auth issuance service.
pub struct AuthService {}

impl AuthService {
	/// Build an inert service: every route answers `unimplemented` until the signer,
	/// JWKS, Google client, and refresh store are wired.
	pub fn unconfigured() -> Self {
		Self {}
	}
}

#[tonic::async_trait]
impl AuthServiceRpc for AuthService {
	async fn exchange(&self, _request: Request<ExchangeRequest>) -> Result<Response<TokenResponse>, Status> {
		Err(Status::unimplemented("Exchange is not implemented"))
	}

	async fn refresh(&self, _request: Request<RefreshRequest>) -> Result<Response<TokenResponse>, Status> {
		Err(Status::unimplemented("Refresh is not implemented"))
	}

	async fn logout(&self, _request: Request<LogoutRequest>) -> Result<Response<LogoutResponse>, Status> {
		Err(Status::unimplemented("Logout is not implemented"))
	}

	async fn list_sessions(&self, _request: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
		Err(Status::unimplemented("ListSessions is not implemented"))
	}

	async fn revoke_session(&self, _request: Request<RevokeSessionRequest>) -> Result<Response<RevokeSessionResponse>, Status> {
		Err(Status::unimplemented("RevokeSession is not implemented"))
	}

	async fn jwks(&self, _request: Request<JwksRequest>) -> Result<Response<JwksResponse>, Status> {
		Err(Status::unimplemented("Jwks is not implemented"))
	}
}
