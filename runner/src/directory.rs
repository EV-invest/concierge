//! `directory` module — the identity plane's user/profile control surface.
//!
//! Two faces over one [`UserDirectoryRepository`] port (Postgres-backed in
//! production):
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
//! Every role this module RETURNS — provisioner summaries (the issued session's
//! `UserSummary`), `GetMe`/`GetUser`, `ListUsers` — is the caller's/target's role as
//! [`crate::authz::BreakGlass`] resolves it, and every one of them is returned WITH the
//! `role_is_break_glass` flag naming which of the two sources it came from. That
//! pairing is the point: an elevated role that did not announce itself is what let the
//! console draw three owners while the consilium counted zero.
//!
//! OWNERSHIP IS NOT A ROLE EDIT. `SetRole` refuses to grant or strip `Role::Owner` —
//! unconditionally, including on a fund with no owners at all — and it refuses from
//! INSIDE the write transaction, so no consilium can commit between the check and the
//! write. Both directions go through the consilium in [`crate::governance`], and the
//! very first seats through the genesis seed ([`crate::genesis`]); those two are the
//! only writers of `owner` there are. Without that refusal every control there is
//! decorative: one owner could mint four sock puppets and then carry a payout quorum
//! legitimately, with every snapshot and re-validation working exactly as designed —
//! and while the registry is empty an emergency-elevated operator could do it before
//! the fund had even started.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::{
	authz::{Permission, Role},
	error::DomainError,
	governance::MAX_REASON_CHARS,
	users::{AuthSubject, Email, MAX_KYC_LEVEL, ProfileFields, Suspension, User, UserId, UserStatus},
};
use evconcierge_auth::{AuthError, ProvisionCommand, ProvisionRequest, ProvisionedUser};
use evconcierge_contracts::concierge::v1::{
	AdminUserSummary, DisableUserRequest, DisableUserResponse, GetMeRequest, GetUserRequest, HoldUserRequest, HoldUserResponse, ListUsersRequest, ListUsersResponse, ReinstateUserRequest,
	ReinstateUserResponse, RevokeTokensRequest, RevokeTokensResponse, SetKycLevelRequest, SetKycLevelResponse, SetRoleRequest, SetRoleResponse, UpdateProfileRequest, UserProfile,
	user_directory_server::UserDirectory,
};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	authz::{BreakGlass, EffectiveRole, Elevation},
	governance::audit_of,
	infrastructure::users::{AdminAction, AdminUserRow, Reinstatement},
	notification::now_secs,
	ports::{RoleChange, UserDirectoryRepository},
	support::domain_to_status,
};

/// The user directory/profile service, backed by the [`UserDirectoryRepository`]
/// port. Cheaply cloneable (the repo and the emergency-access rule are behind `Arc`s).
#[derive(Clone)]
pub struct Directory {
	users: Arc<dyn UserDirectoryRepository>,
	break_glass: Arc<BreakGlass>,
}

impl Directory {
	pub fn new(users: Arc<dyn UserDirectoryRepository>, break_glass: Arc<BreakGlass>) -> Self {
		Self { users, break_glass }
	}

	/// The authenticated caller's own user id (from the access-token `sub`), gated on live
	/// revocation state via the shared [`crate::authz::caller_gate`]: a self-service RPC
	/// acts *as a user*, so only a `typ=access` token qualifies, and a suspended or
	/// revoked user cannot keep reading/editing their profile for the remaining
	/// access-token TTL (the stateless verifier can't see status/revocation).
	async fn active_caller_id<T>(&self, request: &Request<T>) -> Result<UserId, Status> {
		let caller = crate::authz::caller_gate(self.users.as_ref(), request).await?;
		let id = caller.id.ok_or_else(|| Status::unauthenticated("subject is not a user id"))?;
		caller.record.ok_or_else(|| Status::not_found("user"))?;
		Ok(id)
	}

	/// The role the plane reports for `user`, together with whether it came from
	/// emergency access — so a profile/admin read shows the same authority the RBAC gate
	/// grants AND says where it came from.
	async fn effective_role_of(&self, user: &User) -> EffectiveRole {
		self.elevation().await.role_of(user.role(), &user.id().to_string())
	}

	/// The break-glass rule frozen for this request. Taken once and applied to every row
	/// a handler reports, never once per row.
	async fn elevation(&self) -> Elevation<'_> {
		self.break_glass.snapshot(self.users.as_ref()).await
	}

	/// WHO is acting, for the audit row — resolved from the verified `sub` after the
	/// permission gate has already passed.
	///
	/// An audit log whose actor column can be empty for an ordinary console action is a
	/// log that answers "who did this" with a shrug, so a caller whose `sub` is not a user
	/// id is refused rather than recorded as nobody. Emergency access does not change
	/// this: a break-glass operator has a real user id and it is theirs that belongs here.
	async fn acting_operator<T>(&self, request: &Request<T>) -> Result<UserId, Status> {
		let caller = crate::authz::caller_gate(self.users.as_ref(), request).await?;
		caller.id.ok_or_else(|| Status::unauthenticated("subject is not a user id"))
	}
}

/// Drain provisioning requests from the auth task until the channel closes — the
/// receiving end of the [`Provisioner`](evconcierge_auth::Provisioner) channel.
/// The summaries returned here become the issued session's `UserSummary` (Exchange AND
/// Refresh), so they carry the same authority the RBAC gate grants and the same flag
/// saying whether it is the register's or the environment's.
pub async fn run_provisioner(mut rx: mpsc::Receiver<ProvisionRequest>, users: Arc<dyn UserDirectoryRepository>, break_glass: Arc<BreakGlass>) {
	while let Some(request) = rx.recv().await {
		let result = handle(users.as_ref(), request.command, break_glass.as_ref()).await;
		// The auth task may have given up; a dropped responder is not our problem.
		let _ = request.respond_to.send(result);
	}
}

/// A hold the aggregate would not place. Its policy refusals — the account is already
/// held, or was until recently, or holds a seat the actor may not touch — come back as
/// `FAILED_PRECONDITION` rather than the
/// `PERMISSION_DENIED` a `Forbidden` maps to by default, because the BFF folds
/// `PERMISSION_DENIED` into an opaque 404 and the whole point of these messages is that
/// the operator reads which proposal to open instead.
fn hold_refusal(err: DomainError) -> Status {
	match err {
		DomainError::Forbidden(why) => Status::failed_precondition(why),
		other => domain_to_status(other),
	}
}

/// Gate an RPC on a required [`Permission`] via the shared [`crate::authz`] matrix.
async fn require_permission<T>(directory: &Directory, request: &Request<T>, permission: Permission) -> Result<(), Status> {
	crate::authz::require_permission(directory.users.as_ref(), &directory.break_glass, request, permission).await
}

/// Parse an admin-supplied target `user_id` request field. The caller is already
/// authorized (`require_permission`), so a malformed value is bad input —
/// `INVALID_ARGUMENT` — never an auth failure; `UNAUTHENTICATED` is reserved for
/// the caller's own `sub` in [`Directory::active_caller_id`].
fn parse_target_id(raw: &str) -> Result<UserId, Status> {
	Uuid::parse_str(raw).map(UserId::from_raw).map_err(|_| Status::invalid_argument("user_id is not a valid UUID"))
}

fn optional(raw: &str) -> Option<String> {
	if raw.is_empty() { None } else { Some(raw.to_owned()) }
}

/// A reason the caller MUST give, bounded by the same limit the consilium's is.
///
/// Required where the action stops somebody's money: the owners asked to ratify a hold
/// are reading this sentence, and a freeze with no stated cause cannot be reviewed
/// afterwards by anyone, including the operator who made it.
fn require_reason(raw: &str) -> Result<String, Status> {
	let reason = raw.trim();
	if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
		return Err(Status::invalid_argument(format!("reason must be 1-{MAX_REASON_CHARS} characters")));
	}
	Ok(reason.to_owned())
}

#[tonic::async_trait]
impl UserDirectory for Directory {
	async fn get_me(&self, request: Request<GetMeRequest>) -> Result<Response<UserProfile>, Status> {
		let id = self.active_caller_id(&request).await?;
		let user = self.users.find_by_id(id).await.map_err(domain_to_status)?.ok_or_else(|| Status::not_found("user"))?;
		Ok(Response::new(user_to_proto(&user, self.effective_role_of(&user).await)))
	}

	async fn update_profile(&self, request: Request<UpdateProfileRequest>) -> Result<Response<UserProfile>, Status> {
		let id = self.active_caller_id(&request).await?;
		let req = request.into_inner();
		// Parse before touching the store: a bad field is INVALID_ARGUMENT with the
		// field named, and never opens a write transaction.
		let fields = ProfileFields::parse(ProfileFields {
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
		})
		.map_err(domain_to_status)?;
		let user = self.users.update_profile(id, fields).await.map_err(domain_to_status)?;
		Ok(Response::new(user_to_proto(&user, self.effective_role_of(&user).await)))
	}

	async fn revoke_tokens(&self, request: Request<RevokeTokensRequest>) -> Result<Response<RevokeTokensResponse>, Status> {
		require_permission(self, &request, Permission::UserRevoke).await?;
		let actor = self.acting_operator(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let target = parse_target_id(&req.user_id)?;
		let action = AdminAction::by(actor, "tokens_revoked", &audit).with_reason(&req.reason);
		let user = self.users.revoke_tokens(target, &action, now_secs()).await.map_err(domain_to_status)?;
		Ok(Response::new(RevokeTokensResponse {
			token_version: user.token_version(),
		}))
	}

	/// REFUSES, always, naming the two verbs this one used to be at once.
	///
	/// It was the emergency brake — the frozen flag the money plane re-reads when it
	/// dispatches, so it stops a withdrawal that is already queued — and it was also a
	/// permanent judgement on an account, made by one person, recorded nowhere. Those want
	/// opposite treatments. The brake must stay instant, so it survives as
	/// [`Self::hold_user`] with a deadline attached; the judgement must not be one
	/// person's to make, so it survives as a proposal. There is no correct thing for this
	/// RPC to guess, so it asks.
	async fn disable_user(&self, request: Request<DisableUserRequest>) -> Result<Response<DisableUserResponse>, Status> {
		// Still gated, so the refusal never becomes a way for an unauthorized caller to
		// probe which user ids exist.
		require_permission(self, &request, Permission::UserSuspend).await?;
		Err(Status::failed_precondition(
			"DisableUser is retired because it meant two different things: use UserDirectory.HoldUser to freeze \
			 this account now (it lapses in 24h unless ratified), or GovernanceService.OpenUserSuspension to \
			 make it permanent, which every other owner votes on",
		))
	}

	/// The emergency brake, and the reason suspension could not simply become a quorum.
	///
	/// A hold is instant and one operator's to reach for, because the thing it stops —
	/// money already in the queue — cannot wait for a quorum by mail, and a broadcast made
	/// while the owners were deciding is irreversible. What makes that safe to hand to one
	/// person is that it undoes itself: the hold lapses in
	/// [`domain::users::HOLD_TTL_SECS`] unless the owners ratify it, so one actor can stop
	/// money temporarily and never permanently.
	async fn hold_user(&self, request: Request<HoldUserRequest>) -> Result<Response<HoldUserResponse>, Status> {
		require_permission(self, &request, Permission::UserSuspend).await?;
		let caller = crate::authz::caller_gate(self.users.as_ref(), &request).await?;
		let actor = caller.id.ok_or_else(|| Status::unauthenticated("subject is not a user id"))?;
		// The PERSISTED role, never the elevated one — the same choice the mail relay
		// makes: emergency access authorizes an operator, it does not seat them, and
		// holding a seat is a seated owner's call.
		let actor_role = caller.record.map_or(Role::Investor, |record| record.role);
		let audit = audit_of(&request);
		let req = request.into_inner();
		let target = parse_target_id(&req.user_id)?;
		if target == actor {
			// Not a safety rule so much as a coherence one: a hold on yourself ends your
			// session, and with it your ability to explain, lift or ratify it. The verb for
			// stepping back is the owners' proposal, not the emergency brake.
			return Err(Status::failed_precondition(
				"a hold cannot be placed on your own account; ask the owners through GovernanceService.OpenUserSuspension",
			));
		}
		let reason = require_reason(&req.reason)?;
		let action = AdminAction::by(actor, "held", &audit).with_reason(&reason);
		let user = self.users.hold_user(target, &action, actor_role, now_secs()).await.map_err(hold_refusal)?;
		Ok(Response::new(HoldUserResponse {
			hold_expires_at: user.suspension().and_then(Suspension::hold_expires_at).unwrap_or_default(),
		}))
	}

	/// One act for a hold, refused for the owners' verdict.
	///
	/// Without the second half the suspension consilium would be decorative: the owners
	/// vote to freeze an account and any one admin presses this button. The decision is
	/// taken inside the write transaction, not here, for the same TOCTOU reason
	/// [`Self::set_role`] takes its own there.
	async fn reinstate_user(&self, request: Request<ReinstateUserRequest>) -> Result<Response<ReinstateUserResponse>, Status> {
		require_permission(self, &request, Permission::UserSuspend).await?;
		let actor = self.acting_operator(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let target = parse_target_id(&req.user_id)?;
		let action = AdminAction::by(actor, "reinstated", &audit).with_reason(&req.reason);
		match self.users.reinstate_outside_governance(target, &action, now_secs()).await.map_err(domain_to_status)? {
			Reinstatement::Applied(_) => Ok(Response::new(ReinstateUserResponse {})),
			Reinstatement::GovernanceHeld => Err(Status::failed_precondition(
				"this suspension is the owner consilium's verdict; lifting it goes through \
				 GovernanceService.OpenUserReinstatement, which the other owners vote on",
			)),
		}
	}

	/// The human path to a KYC level — the only one that may move it DOWN, and the only
	/// one that reaches tier 3.
	///
	/// Refused on your own account. `KycManage` is held by `Admin` as well as `Owner`
	/// (`domain::authz`), and tier 1 is the floor for withdrawals on the MONEY plane —
	/// so without this an operator could lift their own money gate in a plane where they
	/// hold no permissions at all, and nothing in either plane would show it as anything
	/// but a routine verification (#47). The neighbouring verbs already read this way:
	/// [`Self::hold_user`] refuses its own actor, and `SetRole` refuses both directions
	/// of ownership, with `domain::authz` calling the matrix a separation of duties.
	///
	/// A `PermissionDenied` and not the `FailedPrecondition` the hold uses, because the
	/// two refusals say different things. A hold on yourself is incoherent — it ends the
	/// session you would need to lift it — and could be re-asked in another shape. This
	/// one is a permission the caller does not have over this target and will not have;
	/// another operator has it.
	///
	/// Raising your OWN level is still perfectly possible, through the front door every
	/// other user goes through: `/kyc/start`, a document and a vendor.
	async fn set_kyc_level(&self, request: Request<SetKycLevelRequest>) -> Result<Response<SetKycLevelResponse>, Status> {
		require_permission(self, &request, Permission::KycManage).await?;
		let actor = self.acting_operator(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let target = parse_target_id(&req.user_id)?;
		if target == actor {
			return Err(Status::permission_denied(
				"a KYC level cannot be set on your own account; ask another holder of KycManage, or verify through /kyc/start like any other user",
			));
		}
		// The aggregate and the `users_kyc_level_range` CHECK both refuse this too — the
		// range is theirs, not this handler's. Rejecting here as well only saves the
		// round trip to a row we already know we will not write.
		if req.kyc_level > MAX_KYC_LEVEL {
			return Err(Status::invalid_argument(format!("kyc_level must be between 0 and {MAX_KYC_LEVEL}")));
		}
		let action = AdminAction::by(actor, "kyc_level_set", &audit).with_reason(&req.reason);
		let user = self.users.set_kyc_level(target, req.kyc_level, &action, now_secs()).await.map_err(domain_to_status)?;
		Ok(Response::new(SetKycLevelResponse { kyc_level: user.kyc_level() }))
	}

	async fn list_users(&self, request: Request<ListUsersRequest>) -> Result<Response<ListUsersResponse>, Status> {
		require_permission(self, &request, Permission::UserRead).await?;
		let req = request.into_inner();
		let limit = if req.limit == 0 { 50 } else { (req.limit as i64).clamp(1, 200) };
		// Truncate rather than reject: the free-text query is a filter, not stored data.
		let query: String = req.query.trim().chars().take(200).collect();
		// Empty string = no filter; anything else must be a known enum value.
		if !req.role.is_empty() {
			Role::parse(&req.role).map_err(domain_to_status)?;
		}
		if !req.status.is_empty() {
			UserStatus::parse(&req.status).map_err(domain_to_status)?;
		}
		let (rows, total) = self.users.list(&query, &req.role, &req.status, limit, req.offset as i64).await.map_err(domain_to_status)?;
		// One snapshot for the whole page: the rule is the same for every row, and asking
		// per row would be a control-plane read per user listed.
		let elevation = self.elevation().await;
		Ok(Response::new(ListUsersResponse {
			users: rows
				.into_iter()
				.map(|row| {
					let (role, break_glass) = match Role::parse(&row.role) {
						Ok(persisted) => {
							let resolved = elevation.role_of(persisted, &row.id.to_string());
							(resolved.role.as_str().to_owned(), resolved.break_glass)
						}
						// A corrupt stored role must not fail the whole list — surface it verbatim, and
						// never elevate a value we could not parse.
						Err(_) => (row.role.clone(), false),
					};
					summary_to_proto(row, role, break_glass)
				})
				.collect(),
			total: total as u64,
		}))
	}

	async fn get_user(&self, request: Request<GetUserRequest>) -> Result<Response<UserProfile>, Status> {
		require_permission(self, &request, Permission::UserRead).await?;
		let id = parse_target_id(&request.get_ref().user_id)?;
		let user = self.users.find_by_id(id).await.map_err(domain_to_status)?.ok_or_else(|| Status::not_found("user"))?;
		Ok(Response::new(user_to_proto(&user, self.effective_role_of(&user).await)))
	}

	/// OWNERSHIP IS NOT A ROLE EDIT — refused in both directions, UNCONDITIONALLY, with
	/// no carve-out for an empty registry.
	///
	/// Granting is the dangerous direction. If one owner can mint another they can mint
	/// four, and a payout consilium of seven with a threshold of four is then carried by
	/// the puppets alone — legitimately, with the roster snapshot and every re-validation
	/// behaving exactly as designed. Snapshotting cannot close it, because the stuffing
	/// happens before the proposal is opened. Stripping is refused for the mirror reason:
	/// a bare demotion would be an expulsion with no consilium, no floor check and no
	/// audit trail. Re-setting the role someone already holds stays a no-op, so a console
	/// re-submitting an unchanged form does not trip over this.
	///
	/// There used to be a bootstrap carve-out seating the second owner directly while the
	/// roster was smaller than two. It is gone, and deliberately: emergency access
	/// ([`crate::authz::BreakGlass`]) is live in exactly that state, so the carve-out
	/// would have handed an environment-listed operator the power to build a whole roster
	/// of their own. The first seats come from [`crate::genesis`], at boot, with no
	/// request behind them.
	///
	/// The decision itself lives INSIDE the write transaction
	/// ([`UserDirectoryRepository::set_role_outside_ownership`]) rather than here. Read
	/// separately it was a TOCTOU window: an admission committing between the check and
	/// the write would let a demotion sail past both branches and then strip the seat the
	/// consilium had just granted — no floor, no audit, and this module's "exactly two
	/// writers of `owner`" invariant briefly false.
	async fn set_role(&self, request: Request<SetRoleRequest>) -> Result<Response<SetRoleResponse>, Status> {
		require_permission(self, &request, Permission::RoleGrant).await?;
		let actor = self.acting_operator(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let target = parse_target_id(&req.user_id)?;
		let role = Role::parse(&req.role).map_err(domain_to_status)?;
		let action = AdminAction::by(actor, "role_set", &audit).with_reason(&req.reason);
		match self.users.set_role_outside_ownership(target, role, &action, now_secs()).await.map_err(domain_to_status)? {
			RoleChange::Applied(user) => Ok(Response::new(SetRoleResponse {
				role: user.role().as_str().to_owned(),
			})),
			RoleChange::WouldGrantOwnership => Err(Status::failed_precondition(
				"granting ownership goes through GovernanceService.OpenOwnerAdmission, which every other owner must agree to — one owner may not mint another",
			)),
			RoleChange::WouldTakeOwnership => Err(Status::failed_precondition(
				"taking ownership away goes through GovernanceService.OpenOwnerRemoval, or ResignOwnership for your own seat",
			)),
			RoleChange::WouldGrantAdmin => Err(Status::failed_precondition(
				"granting the admin role goes through GovernanceService.OpenAdminAdmission, which the other owners vote on — \
				 an operator who can appoint operators can appoint accomplices. Taking the role away is still one act",
			)),
		}
	}
}

fn user_to_proto(user: &User, resolved: EffectiveRole) -> UserProfile {
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
		kyc_level: user.kyc_level(),
		role: resolved.role.as_str().to_owned(),
		role_is_break_glass: resolved.break_glass,
		suspended_by: user.suspension().map(Suspension::as_str).unwrap_or_default().to_owned(),
		hold_expires_at: user.suspension().and_then(Suspension::hold_expires_at).unwrap_or_default(),
	}
}

/// Map an operator-console list row (a lightweight SQL projection) to its wire shape;
/// `role` is the pre-resolved role (or the raw stored string on a corrupt row).
fn summary_to_proto(row: AdminUserRow, role: String, role_is_break_glass: bool) -> AdminUserSummary {
	AdminUserSummary {
		user_id: row.id.to_string(),
		email: row.email.unwrap_or_default(),
		status: row.status,
		kyc_level: row.kyc_level as u32,
		role,
		token_version: row.token_version as u64,
		created_at: row.created_at,
		role_is_break_glass,
		suspended_by: row.suspended_by.unwrap_or_default(),
		hold_expires_at: row.hold_expires_at.unwrap_or_default(),
	}
}

async fn handle(users: &dyn UserDirectoryRepository, command: ProvisionCommand, break_glass: &BreakGlass) -> Result<ProvisionedUser, AuthError> {
	let user = match command {
		ProvisionCommand::Provision {
			auth_subject,
			email,
			email_verified,
		} => {
			let subject = AuthSubject::parse(&auth_subject).map_err(invalid_identity)?;
			let email = Email::parse(&email).map_err(invalid_identity)?;
			users.provision(subject, email, email_verified).await.map_err(to_auth)?
		}
		ProvisionCommand::Lookup { user_id } => {
			let id = parse_id(&user_id)?;
			users.find_by_id(id).await.map_err(to_auth)?.ok_or_else(|| AuthError::Directory("unknown user".into()))?
		}
		ProvisionCommand::RevokeAll { user_id } => {
			let id = parse_id(&user_id)?;
			// The user acting on themselves ("sign out everywhere"), not an operator —
			// recorded with its own verb so the log never reads as though somebody's
			// sessions had been revoked FOR them.
			let action = AdminAction {
				actor: Some(id),
				action: "tokens_revoked_by_self",
				..AdminAction::default()
			};
			users.revoke_tokens(id, &action, now_secs()).await.map_err(to_auth)?
		}
	};
	let resolved = break_glass.snapshot(users).await.role_of(user.role(), &user.id().to_string());
	Ok(summary(&user, resolved))
}

fn summary(user: &User, resolved: EffectiveRole) -> ProvisionedUser {
	ProvisionedUser {
		user_id: user.id().to_string(),
		email: user.email().as_str().to_owned(),
		status: user.status().as_str().to_owned(),
		token_version: user.token_version(),
		role: resolved.role.as_str().to_owned(),
		role_is_break_glass: resolved.break_glass,
	}
}

fn parse_id(raw: &str) -> Result<UserId, AuthError> {
	Uuid::parse_str(raw).map(UserId::from_raw).map_err(|_| AuthError::Directory("invalid user id".into()))
}

fn invalid_identity(_: DomainError) -> AuthError {
	AuthError::Provider("invalid identity from provider".into())
}

fn to_auth(err: DomainError) -> AuthError {
	match err {
		// A control-plane failure is operational (maps to gRPC UNAVAILABLE upstream).
		DomainError::Repository(_) => AuthError::Unavailable,
		// A directory outcome (NotFound/Conflict/Validation) is first-party — never
		// rendered as "identity provider rejected the request" (Google is not to blame
		// for a directory miss).
		other => AuthError::Directory(other.to_string()),
	}
}
