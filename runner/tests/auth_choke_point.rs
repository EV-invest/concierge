//! The composition-root auth choke point (FB-25 / CON-SECFAULT-01, CON-ARCHCOMM-04).
//!
//! Mirrors the runner's mount: every non-public service is wrapped in
//! `grpc_auth_layer(Verifier::unconfigured())`, which fails closed before any handler
//! gets a body. We assert the structural choke point, not handler logic:
//!
//! - A `UserDirectory` RPC returns `UNAVAILABLE` (auth not configured) — it is stopped
//!   at the layer and never reaches the `unimplemented` handler, which would answer
//!   `UNIMPLEMENTED`.
//! - `Health` stays public: it is mounted unwrapped and answers normally.
//!
//! No DB, no services — the layer fails closed entirely in-process.

use std::{net::TcpListener, time::Duration};

use evconcierge_auth::{Verifier, grpc_auth_layer};
use evconcierge_contracts::concierge::v1::{
	CheckRequest, CheckResponse, DisableUserRequest, DisableUserResponse, GetMeRequest, ReinstateUserRequest, ReinstateUserResponse, RevokeTokensRequest, RevokeTokensResponse,
	SetKycLevelRequest, SetKycLevelResponse, UpdateProfileRequest, UserProfile,
	health_service_client::HealthServiceClient,
	health_service_server::{HealthService, HealthServiceServer},
	user_directory_client::UserDirectoryClient,
	user_directory_server::{UserDirectory, UserDirectoryServer},
};
use tonic::{
	Code, Request, Response, Status,
	transport::{Channel, Server},
};
use tower::Layer;

#[derive(Default)]
struct Health;

#[tonic::async_trait]
impl HealthService for Health {
	async fn check(&self, _request: Request<CheckRequest>) -> Result<Response<CheckResponse>, Status> {
		Ok(Response::new(CheckResponse { status: "ok".to_string() }))
	}
}

#[derive(Default)]
struct Directory;

#[tonic::async_trait]
impl UserDirectory for Directory {
	async fn get_me(&self, _request: Request<GetMeRequest>) -> Result<Response<UserProfile>, Status> {
		Err(Status::unimplemented("UserDirectory.GetMe is not implemented"))
	}

	async fn update_profile(&self, _request: Request<UpdateProfileRequest>) -> Result<Response<UserProfile>, Status> {
		Err(Status::unimplemented("UserDirectory.UpdateProfile is not implemented"))
	}

	async fn revoke_tokens(&self, _request: Request<RevokeTokensRequest>) -> Result<Response<RevokeTokensResponse>, Status> {
		Err(Status::unimplemented("UserDirectory.RevokeTokens is not implemented"))
	}

	async fn disable_user(&self, _request: Request<DisableUserRequest>) -> Result<Response<DisableUserResponse>, Status> {
		Err(Status::unimplemented("UserDirectory.DisableUser is not implemented"))
	}

	async fn reinstate_user(&self, _request: Request<ReinstateUserRequest>) -> Result<Response<ReinstateUserResponse>, Status> {
		Err(Status::unimplemented("UserDirectory.ReinstateUser is not implemented"))
	}

	async fn set_kyc_level(&self, _request: Request<SetKycLevelRequest>) -> Result<Response<SetKycLevelResponse>, Status> {
		Err(Status::unimplemented("UserDirectory.SetKycLevel is not implemented"))
	}
}

/// Boot the composition mirroring `main::run`: `UserDirectory` behind the fail-closed
/// auth layer, `Health` left public. Returns a channel to the bound ephemeral port.
async fn boot() -> Channel {
	// Pick a free port via a throwaway listener, then let tonic bind it. The
	// retry-connect loop below absorbs the brief unbound window.
	let addr = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port").local_addr().expect("local addr");

	let auth = grpc_auth_layer(Verifier::unconfigured());
	tokio::spawn(async move {
		Server::builder()
			.add_service(HealthServiceServer::new(Health))
			.add_service(auth.layer(UserDirectoryServer::new(Directory)))
			.serve(addr)
			.await
			.expect("server")
	});

	let endpoint = format!("http://{addr}");
	// Retry-connect: the spawned server may not be listening on the first dial.
	for _ in 0..50 {
		if let Ok(channel) = Channel::from_shared(endpoint.clone()).unwrap().connect().await {
			return channel;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	panic!("server never became reachable");
}

#[tokio::test]
async fn user_directory_fails_closed_before_the_handler() {
	let channel = boot().await;
	let mut client = UserDirectoryClient::new(channel);

	// Present a bearer token so the layer reaches the verifier (not the no-token
	// short-circuit). The unconfigured verifier answers NotConfigured → UNAVAILABLE.
	let mut request = Request::new(GetMeRequest {});
	request.metadata_mut().insert("authorization", "Bearer dummy".parse().unwrap());
	let status = client.get_me(request).await.expect_err("auth layer must reject");

	// The fail-closed layer answers UNAVAILABLE (Verifier::unconfigured). If the layer
	// were missing the request would reach the stub and answer UNIMPLEMENTED instead.
	assert_eq!(status.code(), Code::Unavailable, "expected the auth layer to short-circuit, got {status:?}");
	assert_ne!(status.code(), Code::Unimplemented, "the request must not reach the unauthenticated handler");
}

#[tokio::test]
async fn user_directory_rejects_a_tokenless_request() {
	let channel = boot().await;
	let mut client = UserDirectoryClient::new(channel);

	// No bearer token at all: the layer short-circuits with UNAUTHENTICATED, still well
	// before the unimplemented handler.
	let status = client.get_me(GetMeRequest {}).await.expect_err("auth layer must reject");
	assert_eq!(status.code(), Code::Unauthenticated, "expected the auth layer to reject, got {status:?}");
	assert_ne!(status.code(), Code::Unimplemented, "the request must not reach the unauthenticated handler");
}

#[tokio::test]
async fn health_stays_public() {
	let channel = boot().await;
	let mut client = HealthServiceClient::new(channel);

	let response = client.check(CheckRequest {}).await.expect("health is unauthenticated");
	assert_eq!(response.into_inner().status, "ok");
}
