//! `platform` module — the platform/cabinet control surface (the admin console's
//! "Cabinet" screen).
//!
//! Maintenance mode, the announcement banner, and feature flags. The read is open to
//! ANY authenticated principal — the config is user-facing by nature (the cabinet
//! shows the announcement/maintenance banner and evaluates flags for every signed-in
//! user), so `GetPlatformConfig` only requires the verified claims the auth layer
//! injected. Writes require `PlatformManage` (admin+) via the shared [`crate::authz`]
//! gate. Every mutating RPC returns the full config so the caller re-renders from one
//! authoritative snapshot.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::authz::Permission;
use evconcierge_auth::claims_of;
use evconcierge_contracts::concierge::v1::{
	FeatureFlag, GetPlatformConfigRequest, PlatformConfig, SetAnnouncementRequest, SetFeatureFlagRequest, SetMaintenanceModeRequest,
	platform_service_server::PlatformService as PlatformServiceRpc,
};
use tonic::{Request, Response, Status};

use crate::{
	ports::{PlatformConfigRepository, UserDirectoryRepository},
	support::domain_to_status,
};

/// The platform-config service. Cheaply cloneable (repos + allowlist behind `Arc`s).
/// Holds the user repo + admin allowlist only to reuse the shared authz gate.
#[derive(Clone)]
pub struct Platform {
	users: Arc<dyn UserDirectoryRepository>,
	admins: Arc<[String]>,
	config: Arc<dyn PlatformConfigRepository>,
}

impl Platform {
	pub fn new(users: Arc<dyn UserDirectoryRepository>, admins: Arc<[String]>, config: Arc<dyn PlatformConfigRepository>) -> Self {
		Self { users, admins, config }
	}

	/// Read the whole config into its wire shape (one authoritative snapshot).
	async fn snapshot(&self) -> Result<PlatformConfig, Status> {
		let cfg = self.config.config().await.map_err(domain_to_status)?;
		let flags = self.config.flags().await.map_err(domain_to_status)?;
		Ok(PlatformConfig {
			maintenance_mode: cfg.maintenance_mode,
			announcement_title: cfg.announcement_title,
			announcement_body: cfg.announcement_body,
			announcement_active: cfg.announcement_active,
			flags: flags
				.into_iter()
				.map(|f| FeatureFlag {
					key: f.key,
					description: f.description,
					enabled: f.enabled,
					rollout: f.rollout as u32,
				})
				.collect(),
		})
	}
}

#[tonic::async_trait]
impl PlatformServiceRpc for Platform {
	async fn get_platform_config(&self, request: Request<GetPlatformConfigRequest>) -> Result<Response<PlatformConfig>, Status> {
		// User-facing read: any authenticated principal may see the config. The auth
		// layer already verified the token — require its claims (defense in depth against
		// an unwrapped mount), but no role.
		claims_of(&request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		Ok(Response::new(self.snapshot().await?))
	}

	async fn set_maintenance_mode(&self, request: Request<SetMaintenanceModeRequest>) -> Result<Response<PlatformConfig>, Status> {
		crate::authz::require_permission(self.users.as_ref(), &self.admins, &request, Permission::PlatformManage).await?;
		self.config.set_maintenance(request.get_ref().enabled).await.map_err(domain_to_status)?;
		Ok(Response::new(self.snapshot().await?))
	}

	async fn set_announcement(&self, request: Request<SetAnnouncementRequest>) -> Result<Response<PlatformConfig>, Status> {
		crate::authz::require_permission(self.users.as_ref(), &self.admins, &request, Permission::PlatformManage).await?;
		let req = request.into_inner();
		self.config.set_announcement(&req.title, &req.body, req.active).await.map_err(domain_to_status)?;
		Ok(Response::new(self.snapshot().await?))
	}

	async fn set_feature_flag(&self, request: Request<SetFeatureFlagRequest>) -> Result<Response<PlatformConfig>, Status> {
		crate::authz::require_permission(self.users.as_ref(), &self.admins, &request, Permission::PlatformManage).await?;
		let req = request.into_inner();
		if req.key.trim().is_empty() {
			return Err(Status::invalid_argument("flag key required"));
		}
		// Validate BEFORE the `as i32` narrowing: a rollout ≥ 2^31 would wrap negative
		// and silently clamp to 0 instead of being rejected.
		if req.rollout > 100 {
			return Err(Status::invalid_argument("rollout must be between 0 and 100"));
		}
		self.config
			.upsert_flag(&req.key, &req.description, req.enabled, req.rollout as i32)
			.await
			.map_err(domain_to_status)?;
		Ok(Response::new(self.snapshot().await?))
	}
}
