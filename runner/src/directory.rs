//! `directory` module — the identity plane's user/profile control surface.
//!
//! Two faces over one Postgres-backed [`PgUsers`] repository:
//!
//! - The [`UserDirectory`] gRPC service: `GetMe`/`UpdateProfile` (self-service on the
//!   caller's own `sub`) and `RevokeTokens`/`DisableUser`/`ReinstateUser`/`SetKycLevel`
//!   (admin allowlist). Every RPC is authorized from the verified [`Claims`] the inbound
//!   auth layer injected. The admin mutations emit the matching cross-plane lifecycle
//!   event (SESSIONS_REVOKED/SUSPENDED/REINSTATED/KYC_CHANGED) the money plane pulls.
//! - [`run_provisioner`]: the receiving end of the auth → directory [`Provisioner`]
//!   channel. The auth task verifies a Google identity, then asks the directory (over
//!   the in-process channel, never the wire) to upsert/look up/revoke the matching user.
//!   This is the only place the auth crate's primitive DTOs become domain value objects,
//!   so `domain` never depends on `evconcierge_auth` and vice-versa.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::{
	error::DomainError,
	users::{AuthSubject, Email, ProfileFields, User, UserId},
};
use evconcierge_auth::{AuthError, Claims, ProvisionCommand, ProvisionRequest, ProvisionedUser, claims_of};
use evconcierge_contracts::concierge::v1::{
	DisableUserRequest, DisableUserResponse, GetMeRequest, ReinstateUserRequest, ReinstateUserResponse, RevokeTokensRequest, RevokeTokensResponse, SetKycLevelRequest, SetKycLevelResponse,
	UpdateProfileRequest, UserProfile, user_directory_server::UserDirectory,
};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::infrastructure::users::PgUsers;

/// The user directory/profile service, backed by Postgres. Cheaply cloneable (the repo
/// and allowlist are behind `Arc`s). `admins` is the config allowlist of canonical user
/// ids permitted to call the admin RPCs.
#[derive(Clone)]
pub struct Directory {
	users: Arc<PgUsers>,
	admins: Arc<[String]>,
}

impl Directory {
	pub fn new(users: Arc<PgUsers>, admins: Arc<[String]>) -> Self {
		Self { users, admins }
	}

	fn is_admin(&self, subject: &str) -> bool {
		self.admins.iter().any(|s| s == subject)
	}
}

/// The authenticated caller's own user id (from the access-token `sub`). A self-service
/// RPC acts *as a user*, so only a `typ=access` token qualifies — a service token is
/// rejected here regardless of whether its `sub` parses as a UUID.
fn caller_id<T>(request: &Request<T>) -> Result<UserId, Status> {
	let claims = claims_of(request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
	if !claims.is_access() {
		return Err(Status::permission_denied("access token required"));
	}
	parse_user_id(&claims.sub)
}

/// Gate an RPC on the admin allowlist. Only a human access token can be an admin — a
/// service token (distinct `typ`) never qualifies, even if its `sub` matched.
fn require_admin<T>(directory: &Directory, request: &Request<T>) -> Result<(), Status> {
	let claims: &Claims = claims_of(request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
	if claims.is_access() && directory.is_admin(&claims.sub) {
		Ok(())
	} else {
		Err(Status::permission_denied("admin only"))
	}
}

fn parse_user_id(raw: &str) -> Result<UserId, Status> {
	Uuid::parse_str(raw).map(UserId::from_raw).map_err(|_| Status::unauthenticated("subject is not a user id"))
}

fn optional(raw: &str) -> Option<String> {
	if raw.is_empty() { None } else { Some(raw.to_owned()) }
}

/// Map a domain error to a gRPC status without leaking control-plane internals.
fn map_err(err: DomainError) -> Status {
	match err {
		DomainError::NotFound { .. } => Status::not_found(err.to_string()),
		DomainError::Validation(_) => Status::invalid_argument(err.to_string()),
		DomainError::Forbidden(_) => Status::permission_denied(err.to_string()),
		DomainError::Conflict(_) => Status::already_exists(err.to_string()),
		DomainError::Repository(_) => Status::unavailable("internal error"),
	}
}

#[tonic::async_trait]
impl UserDirectory for Directory {
	async fn get_me(&self, request: Request<GetMeRequest>) -> Result<Response<UserProfile>, Status> {
		let id = caller_id(&request)?;
		let user = self.users.find_by_id(id).await.map_err(map_err)?.ok_or_else(|| Status::not_found("user"))?;
		Ok(Response::new(user_to_proto(&user)))
	}

	async fn update_profile(&self, request: Request<UpdateProfileRequest>) -> Result<Response<UserProfile>, Status> {
		let id = caller_id(&request)?;
		let req = request.into_inner();
		let user = self
			.users
			.update_profile(
				id,
				ProfileFields {
					legal_name: optional(&req.legal_name),
					preferred_name: optional(&req.preferred_name),
					phone: optional(&req.phone),
					date_of_birth: optional(&req.date_of_birth),
					nationality: optional(&req.nationality),
					tax_residence: optional(&req.tax_residence),
					residential_address: optional(&req.residential_address),
					language: optional(&req.language),
					base_currency: optional(&req.base_currency),
					timezone: optional(&req.timezone),
				},
			)
			.await
			.map_err(map_err)?;
		Ok(Response::new(user_to_proto(&user)))
	}

	async fn revoke_tokens(&self, request: Request<RevokeTokensRequest>) -> Result<Response<RevokeTokensResponse>, Status> {
		require_admin(self, &request)?;
		let target = parse_user_id(&request.get_ref().user_id)?;
		let user = self.users.revoke_tokens(target).await.map_err(map_err)?;
		Ok(Response::new(RevokeTokensResponse {
			token_version: user.token_version(),
		}))
	}

	async fn disable_user(&self, request: Request<DisableUserRequest>) -> Result<Response<DisableUserResponse>, Status> {
		require_admin(self, &request)?;
		let target = parse_user_id(&request.get_ref().user_id)?;
		self.users.disable_user(target).await.map_err(map_err)?;
		Ok(Response::new(DisableUserResponse {}))
	}

	async fn reinstate_user(&self, request: Request<ReinstateUserRequest>) -> Result<Response<ReinstateUserResponse>, Status> {
		require_admin(self, &request)?;
		let target = parse_user_id(&request.get_ref().user_id)?;
		self.users.enable_user(target).await.map_err(map_err)?;
		Ok(Response::new(ReinstateUserResponse {}))
	}

	async fn set_kyc_level(&self, request: Request<SetKycLevelRequest>) -> Result<Response<SetKycLevelResponse>, Status> {
		require_admin(self, &request)?;
		let req = request.into_inner();
		let target = parse_user_id(&req.user_id)?;
		let user = self.users.set_kyc_level(target, req.kyc_level).await.map_err(map_err)?;
		Ok(Response::new(SetKycLevelResponse { kyc_level: user.kyc_level() }))
	}
}

fn user_to_proto(user: &User) -> UserProfile {
	UserProfile {
		user_id: user.id().to_string(),
		email: user.email().as_str().to_owned(),
		email_verified: user.email_verified(),
		status: user.status().as_str().to_owned(),
		token_version: user.token_version(),
		legal_name: user.legal_name().unwrap_or_default().to_owned(),
		preferred_name: user.preferred_name().unwrap_or_default().to_owned(),
		phone: user.phone().unwrap_or_default().to_owned(),
		date_of_birth: user.date_of_birth().unwrap_or_default().to_owned(),
		nationality: user.nationality().unwrap_or_default().to_owned(),
		tax_residence: user.tax_residence().unwrap_or_default().to_owned(),
		residential_address: user.residential_address().unwrap_or_default().to_owned(),
		language: user.language().unwrap_or_default().to_owned(),
		base_currency: user.base_currency().unwrap_or_default().to_owned(),
		timezone: user.timezone().unwrap_or_default().to_owned(),
	}
}

/// Drain provisioning requests from the auth task until the channel closes — the
/// receiving end of the [`Provisioner`](evconcierge_auth::Provisioner) channel.
pub async fn run_provisioner(mut rx: mpsc::Receiver<ProvisionRequest>, users: Arc<PgUsers>) {
	while let Some(request) = rx.recv().await {
		let result = handle(users.as_ref(), request.command).await;
		// The auth task may have given up; a dropped responder is not our problem.
		let _ = request.respond_to.send(result);
	}
}

async fn handle(users: &PgUsers, command: ProvisionCommand) -> Result<ProvisionedUser, AuthError> {
	match command {
		ProvisionCommand::Provision {
			auth_subject,
			email,
			email_verified,
		} => {
			let subject = AuthSubject::parse(&auth_subject).map_err(invalid_identity)?;
			let email = Email::parse(&email).map_err(invalid_identity)?;
			let user = users.provision(subject, email, email_verified).await.map_err(to_auth)?;
			Ok(summary(&user))
		}
		ProvisionCommand::Lookup { user_id } => {
			let id = parse_id(&user_id)?;
			let user = users.find_by_id(id).await.map_err(to_auth)?.ok_or_else(|| AuthError::Provider("unknown user".into()))?;
			Ok(summary(&user))
		}
		ProvisionCommand::RevokeAll { user_id } => {
			let id = parse_id(&user_id)?;
			let user = users.revoke_tokens(id).await.map_err(to_auth)?;
			Ok(summary(&user))
		}
	}
}

fn summary(user: &User) -> ProvisionedUser {
	ProvisionedUser {
		user_id: user.id().to_string(),
		email: user.email().as_str().to_owned(),
		status: user.status().as_str().to_owned(),
		token_version: user.token_version(),
	}
}

fn parse_id(raw: &str) -> Result<UserId, AuthError> {
	Uuid::parse_str(raw).map(UserId::from_raw).map_err(|_| AuthError::Provider("invalid user id".into()))
}

fn invalid_identity(_: DomainError) -> AuthError {
	AuthError::Provider("invalid identity from provider".into())
}

fn to_auth(err: DomainError) -> AuthError {
	match err {
		// A control-plane failure is operational (maps to gRPC UNAVAILABLE upstream).
		DomainError::Repository(_) => AuthError::Unavailable,
		other => AuthError::Provider(other.to_string()),
	}
}
