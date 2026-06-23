use evconcierge_contracts::concierge::v1::{
	DisableUserRequest, DisableUserResponse, GetMeRequest, RevokeTokensRequest, RevokeTokensResponse, UpdateProfileRequest, UserProfile, user_directory_server::UserDirectory,
};
use tonic::{Request, Response, Status};

/// The user directory/profile module of the identity plane. Scaffold: every rpc is
/// a stub until the application layer (profile store, admin authz) lands.
#[derive(Default)]
pub struct Directory;

impl Directory {
	pub fn new() -> Self {
		Self
	}
}

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
}
