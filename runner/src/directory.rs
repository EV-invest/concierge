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
//! Grants (`GrantPermission`/`RevokePermission`/`ListGrants`) are the one surface here
//! not gated by a single seat permission: the holder of an alias the tenant lets delegate
//! acts on part of one namespace without holding any seat. The adapter decides who may,
//! inside the write transaction.
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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use domain::{
	authz::{Iam, Kyc, Role, Roles, Users},
	error::DomainError,
	governance::MAX_REASON_CHARS,
	iam::{self, Target},
	users::{Email, MAX_KYC_LEVEL, ProfileFields, Suspension, User, UserId, UserStatus},
};
use evconcierge_auth::{AuthError, ProvisionCommand, ProvisionRequest, ProvisionedUser, claims_of};
use evconcierge_contracts::concierge::v1::{
	AdminUserSummary, DisableUserRequest, DisableUserResponse, GetMeRequest, GetUserRequest, GrantHolder, GrantPermissionRequest, GrantPermissionResponse, HoldUserRequest, HoldUserResponse,
	ListGrantsRequest, ListGrantsResponse, ListUsersRequest, ListUsersResponse, PermissionGrant, ReinstateUserRequest, ReinstateUserResponse, RevokePermissionRequest,
	RevokePermissionResponse, RevokeTokensRequest, RevokeTokensResponse, SetKycLevelRequest, SetKycLevelResponse, SetRoleRequest, SetRoleResponse, UpdateProfileRequest, UserProfile,
	grant_permission_request, revoke_permission_request, user_directory_server::UserDirectory,
};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	authz::{BreakGlass, EffectiveRole, Elevation},
	governance::audit_of,
	infrastructure::users::{AdminAction, AdminUserRow, Reinstatement},
	notification::{RateLimiter, now_secs},
	ports::{GrantActor, GrantAuthority, GrantOutcome, GrantRecord, GrantRepository, GrantSubject, RevokeOutcome, RoleChange, UngrantableAddress, UserDirectoryRepository},
	support::domain_to_status,
};

/// Grant writes (`GrantPermission` + `RevokePermission`, one budget) a delegate may make
/// per [`GRANT_WRITE_RATE_WINDOW`]. The defaults of
/// `GRANT_WRITE_RATE_LIMIT`/`GRANT_WRITE_RATE_WINDOW_SECS`; `main` wires the configured
/// values through [`Directory::with_grant_write_limiter`].
pub const GRANT_WRITE_RATE_LIMIT: u32 = 20;
pub const GRANT_WRITE_RATE_WINDOW: Duration = Duration::from_secs(60 * 60);

/// The one answer a delegate gets for an address that cannot be granted, whatever the
/// reason (see [`GrantOutcome::Ungrantable`]).
const UNGRANTABLE_ADDRESS: &str = "this address cannot be granted access";

/// The user directory/profile service, backed by the [`UserDirectoryRepository`]
/// port. Cheaply cloneable (the repo and the emergency-access rule are behind `Arc`s).
#[derive(Clone)]
pub struct Directory {
	users: Arc<dyn UserDirectoryRepository>,
	grants: Arc<dyn GrantRepository>,
	break_glass: Arc<BreakGlass>,
	/// Per-actor budget for grant writes by anyone short of a granting seat. Every attempt
	/// spends it, refusals included: the probing it bounds is made of refusals.
	grant_writes: Arc<RateLimiter>,
}

impl Directory {
	pub fn new(users: Arc<dyn UserDirectoryRepository>, grants: Arc<dyn GrantRepository>, break_glass: Arc<BreakGlass>) -> Self {
		Self {
			users,
			grants,
			break_glass,
			grant_writes: Arc::new(RateLimiter::new(GRANT_WRITE_RATE_WINDOW, GRANT_WRITE_RATE_LIMIT)),
		}
	}

	/// Replace the grant-write budget (the configured one, in `main`).
	pub fn with_grant_write_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
		self.grant_writes = limiter;
		self
	}

	/// Spend one unit of a delegate's budget, or refuse. A granting seat is not counted:
	/// it can already read every account through `ListUsers`, so a ceiling on it would
	/// bound no oracle and only get in the way of bulk onboarding. The gate's role decides
	/// — the write re-checks authority, but a stale seat there costs at most an unmetered
	/// refusal.
	fn charge_grant_write(&self, actor: &GrantActor, verb: &'static str) -> Result<(), Status> {
		if actor.role.may(Iam::Grant) || self.grant_writes.check(&actor.id.to_string()) {
			return Ok(());
		}
		tracing::warn!(actor = %actor.id, verb, "grant write rate limit exceeded");
		Err(Status::resource_exhausted("too many grant changes; try again later"))
	}

	/// The caller as a grant actor: their id and the seat the RBAC gate resolves for them.
	/// Deliberately NOT a permission check — a delegate holds no seat permission, so
	/// whether they may act is the repository's call, made from their grants inside the
	/// transaction.
	async fn grant_actor<T>(&self, request: &Request<T>) -> Result<GrantActor, Status> {
		let resolved = crate::authz::caller_role(self.users.as_ref(), &self.break_glass, request).await?;
		let id = self.acting_operator(request).await?;
		Ok(GrantActor {
			id,
			role: resolved.role,
			elevated: resolved.break_glass,
		})
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

	/// What `user` may do, concrete. A relying party (`audience`) reads its own tenant's
	/// namespace and nothing else; a first-party session reads the seat and every tenant.
	async fn permissions_of(&self, user: UserId, seat: Role, audience: Option<&str>) -> Result<Vec<String>, DomainError> {
		let mut held: BTreeSet<String> = BTreeSet::new();
		let tenants = match audience {
			Some(audience) => {
				let namespace = self
					.grants
					.audience_namespace(audience)
					.await?
					.ok_or_else(|| DomainError::Repository(format!("relying party `{audience}` has no tenant")))?;
				self.grants.catalog(&namespace).await?.into_iter().collect()
			}
			None => {
				held.extend(seat.permissions().iter().map(|p| (*p).to_owned()));
				self.grants.catalogs().await?
			}
		};
		let targets = self.grants.targets_of(user).await?;
		for tenant in &tenants {
			let ours: Vec<Target> = targets.iter().filter(|t| t.namespace() == tenant.namespace).cloned().collect();
			held.extend(iam::resolve(seat, tenant.granting_seats_hold_all, &ours, &tenant.catalog).into_iter().map(str::to_owned));
		}
		Ok(held.into_iter().collect())
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
/// `FAILED_PRECONDITION` rather than the `PERMISSION_DENIED` a `Forbidden` maps to by
/// default, because they are not statements about the caller's authority: the same
/// operator, asked again after the live hold lapses or after the owners have voted, gets
/// through. `PERMISSION_DENIED` would say "not you, ever", and these messages exist to
/// say "not yet, and here is the proposal to open".
///
/// This used to be argued from the console instead — that the BFF folded
/// `PERMISSION_DENIED` into an opaque 404, so the message would be lost. It does not:
/// banking's cabinet BFF lists `PermissionDenied` as client-safe and relays the message
/// verbatim under a 403 (`cabinet/backend/src/error.rs`, pinned by its own test). The
/// argument above does not depend on that, and [`UserDirectory::set_kyc_level`] relies
/// on the relay being real.
fn hold_refusal(err: DomainError) -> Status {
	match err {
		DomainError::Forbidden(why) => Status::failed_precondition(why),
		other => domain_to_status(other),
	}
}

/// Gate an RPC on a seat permission via the shared [`crate::authz`] gate.
async fn require_permission<T>(directory: &Directory, request: &Request<T>, permission: impl concierge_iam::Permission) -> Result<(), Status> {
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

/// A request's `oneof subject`, parsed. Both request types carry the same pair.
fn parse_subject(user_id: Option<&str>, email: Option<&str>) -> Result<GrantSubject, Status> {
	match (user_id, email) {
		(Some(raw), _) => parse_target_id(raw).map(GrantSubject::Id),
		(None, Some(raw)) => Email::parse(raw).map(GrantSubject::Email).map_err(domain_to_status),
		(None, None) => Err(Status::invalid_argument("subject is required: user_id or email")),
	}
}

/// A refused grant write, logged: someone probing the edge of their delegation is the
/// signal worth keeping. Ids and the target — never the address they typed.
fn grant_denied(actor: &GrantActor, verb: &'static str, target: &str) -> Status {
	tracing::warn!(actor = %actor.id, verb, target, "grant refused");
	Status::permission_denied("grants are made by a seat holding iam:tenants:grant, or by an alias's holder for exactly the aliases it delegates, naming the user by email")
}

/// A delegate's grant to an address that cannot be granted, logged with the reason they
/// are not told. Ids, target and the category — never the address.
fn ungrantable(actor: &GrantActor, target: &str, why: UngrantableAddress) -> Status {
	tracing::warn!(actor = %actor.id, target, outcome = why.as_str(), "grant to an ungrantable address");
	Status::failed_precondition(UNGRANTABLE_ADDRESS)
}

#[tonic::async_trait]
impl UserDirectory for Directory {
	async fn get_me(&self, request: Request<GetMeRequest>) -> Result<Response<UserProfile>, Status> {
		// Read before `active_caller_id` borrows the request: whether a relying party (a
		// backend on another origin) is asking, rather than the user's own session, and
		// which one.
		let relying_party = request
			.extensions()
			.get::<evconcierge_auth::RestrictedCaller>()
			.map(|_| claims_of(&request).map(|claims| claims.aud.clone()).ok_or_else(|| Status::unauthenticated("missing claims")))
			.transpose()?;
		let id = self.active_caller_id(&request).await?;
		let user = self.users.find_by_id(id).await.map_err(domain_to_status)?.ok_or_else(|| Status::not_found("user"))?;
		let resolved = self.effective_role_of(&user).await;
		let mut profile = user_to_proto(&user, resolved);
		profile.permissions = self.permissions_of(id, resolved.role, relying_party.as_deref()).await.map_err(domain_to_status)?;
		Ok(Response::new(if relying_party.is_some() { for_relying_party(profile) } else { profile }))
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
		require_permission(self, &request, Users::Revoke).await?;
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
		require_permission(self, &request, Users::Suspend).await?;
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
		require_permission(self, &request, Users::Suspend).await?;
		let caller = crate::authz::caller_gate(self.users.as_ref(), &request).await?;
		let actor = caller.id.ok_or_else(|| Status::unauthenticated("subject is not a user id"))?;
		// The actor's role is NOT taken from `caller` here: the repository reads the
		// PERSISTED one — never the elevated one, the same choice the mail relay makes,
		// since emergency access authorizes an operator but does not seat them — inside
		// the transaction that holds the target, so a demotion committed between this
		// gate and that lock is seen rather than sailed past.
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
		let user = self.users.hold_user(target, &action, actor, now_secs()).await.map_err(hold_refusal)?;
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
		require_permission(self, &request, Users::Suspend).await?;
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
	/// What this does NOT buy: a person who holds `KycManage` can still provision a second
	/// account through the ordinary sign-in and verify THAT one by hand, which is the same
	/// money gate reached one step sideways. Comparing two ids cannot see who controls an
	/// account; #51 is where that is being answered, with a digest of the verified document
	/// so two accounts cleared on one identity are detectable at all. This refusal closes
	/// the direct route and is not a substitute for it.
	///
	/// Your OWN level still moves — through the front door every other user goes through,
	/// `/kyc/start` with a document and a vendor — but only as far as that door reaches.
	/// It ends at [`crate::ports::PROVIDER_MAX_TIER`], which is 1: tier 2 and 3 on your
	/// own account, and any downgrade of it, are now another `KycManage` holder's to make.
	/// That is the separation of duties being bought here, and it has a cost worth naming:
	/// where exactly one operator is seated and `DIDIT_*` is unset — a combination
	/// `main.rs` supports, and one in which both KYC routes answer 503 — that person has
	/// no path to any level on their own account. Seating a second holder is the way out.
	async fn set_kyc_level(&self, request: Request<SetKycLevelRequest>) -> Result<Response<SetKycLevelResponse>, Status> {
		require_permission(self, &request, Kyc::Manage).await?;
		let actor = self.acting_operator(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let target = parse_target_id(&req.user_id)?;
		if target == actor {
			// The only trace this attempt leaves. The refusal returns before any
			// repository call, so — correctly — it writes no `admin_action` row; but an
			// operator repeatedly reaching for their own money gate is exactly the signal
			// a separation of duties is supposed to surface, and without this line it
			// reaches neither the log nor Sentry.
			tracing::warn!(actor = %actor, requested = req.kyc_level, "SetKycLevel refused: the caller targeted their own account");
			return Err(Status::permission_denied(
				"a KYC level cannot be set on your own account; another holder of KycManage sets it, or \
				 verify through /kyc/start like any other user, which reaches tier 1",
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
		require_permission(self, &request, Users::Read).await?;
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
		require_permission(self, &request, Users::Read).await?;
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
		require_permission(self, &request, Roles::Grant).await?;
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

	async fn grant_permission(&self, request: Request<GrantPermissionRequest>) -> Result<Response<GrantPermissionResponse>, Status> {
		let actor = self.grant_actor(&request).await?;
		self.charge_grant_write(&actor, "grant")?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let subject = match &req.subject {
			Some(grant_permission_request::Subject::UserId(raw)) => parse_subject(Some(raw), None),
			Some(grant_permission_request::Subject::Email(raw)) => parse_subject(None, Some(raw)),
			None => parse_subject(None, None),
		}?;
		let target = parse_grant_target(&req.target)?;
		let action = AdminAction::by(actor.id, "permission_granted", &audit).with_reason(&req.reason);
		match self.grants.grant(&subject, &target, &actor, &action, now_secs()).await.map_err(domain_to_status)? {
			GrantOutcome::Granted(grant) => Ok(Response::new(GrantPermissionResponse {
				grant: Some(permission_grant_to_proto(grant, false)),
			})),
			GrantOutcome::Denied => Err(grant_denied(&actor, "grant", target.as_str())),
			// The rule `HoldUser` and `SetKycLevel` carry: nobody acts on their own account.
			GrantOutcome::ToSelf => Err(Status::permission_denied("nobody grants to their own account")),
			GrantOutcome::UnknownTenant => Err(Status::invalid_argument(format!("no tenant owns the `{}` namespace", target.namespace()))),
			GrantOutcome::UndefinedTarget => Err(Status::invalid_argument(format!("the tenant's catalog defines nothing `{}` names", target.as_str()))),
			// FAILED_PRECONDITION, as for a hold: a state that can change (reinstate the
			// account), not a statement about the caller's authority.
			GrantOutcome::TargetDisabled => Err(Status::failed_precondition("the account is disabled; reinstate it before granting it access")),
			GrantOutcome::AmbiguousEmail => Err(Status::failed_precondition("this email belongs to more than one account; grant by user_id")),
			GrantOutcome::Ungrantable(why) => Err(ungrantable(&actor, target.as_str(), why)),
		}
	}

	async fn revoke_permission(&self, request: Request<RevokePermissionRequest>) -> Result<Response<RevokePermissionResponse>, Status> {
		let actor = self.grant_actor(&request).await?;
		self.charge_grant_write(&actor, "revoke")?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let subject = match &req.subject {
			Some(revoke_permission_request::Subject::UserId(raw)) => parse_subject(Some(raw), None),
			Some(revoke_permission_request::Subject::Email(raw)) => parse_subject(None, Some(raw)),
			None => parse_subject(None, None),
		}?;
		let target = parse_grant_target(&req.target)?;
		let action = AdminAction::by(actor.id, "permission_revoked", &audit).with_reason(&req.reason);
		match self.grants.revoke(&subject, &target, &actor, &action, now_secs()).await.map_err(domain_to_status)? {
			RevokeOutcome::Revoked => Ok(Response::new(RevokePermissionResponse {})),
			RevokeOutcome::NotHeld => Err(Status::not_found("the user holds no active grant of this target")),
			RevokeOutcome::Denied => Err(grant_denied(&actor, "revoke", target.as_str())),
		}
	}

	async fn list_grants(&self, request: Request<ListGrantsRequest>) -> Result<Response<ListGrantsResponse>, Status> {
		let actor = self.grant_actor(&request).await?;
		let namespace = request.into_inner().namespace;
		// Names are a seat's to see. A delegate gets addresses and grants: anything that says
		// who an address belongs to would turn a grant-then-list into an identity lookup
		// (banking#447).
		let names = match self.grants.authority(&actor, &namespace).await.map_err(domain_to_status)? {
			GrantAuthority::Seat => true,
			GrantAuthority::Delegate => false,
			GrantAuthority::None => return Err(grant_denied(&actor, "list", &namespace)),
		};
		let holders = self
			.grants
			.holders(&namespace)
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found("no tenant owns this namespace"))?;
		let catalog = self.grants.catalog(&namespace).await.map_err(domain_to_status)?;
		let holders = holders
			.into_iter()
			.map(|holder| {
				let target = parse_grant_target(&holder.grant.target)?;
				let orphaned = catalog.as_ref().is_none_or(|tenant| target.grants(&tenant.catalog).is_empty());
				Ok(GrantHolder {
					grant: Some(permission_grant_to_proto(holder.grant, orphaned)),
					email: holder.email.unwrap_or_default(),
					legal_name: holder.legal_name.filter(|_| names).unwrap_or_default(),
					preferred_name: holder.preferred_name.filter(|_| names).unwrap_or_default(),
				})
			})
			.collect::<Result<_, Status>>()?;
		Ok(Response::new(ListGrantsResponse { holders }))
	}
}

fn permission_grant_to_proto(grant: GrantRecord, orphaned: bool) -> PermissionGrant {
	PermissionGrant {
		id: grant.id,
		user_id: grant.user_id.to_string(),
		target: grant.target,
		granted_by: grant.granted_by.to_string(),
		granted_at: grant.granted_at,
		reason: grant.reason.unwrap_or_default(),
		orphaned,
	}
}

fn parse_grant_target(raw: &str) -> Result<Target, Status> {
	Target::parse(raw).map_err(domain_to_status)
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
		permissions: Vec::new(),
	}
}

/// The profile a relying party receives: who the user is and what they may open, and
/// nothing an identity document says about them. An ALLOWLIST, so a field added to
/// `UserProfile` later stays out until somebody decides a client should see it.
fn for_relying_party(profile: UserProfile) -> UserProfile {
	UserProfile {
		user_id: profile.user_id,
		email: profile.email,
		email_verified: profile.email_verified,
		status: profile.status,
		preferred_name: profile.preferred_name,
		role: profile.role,
		role_is_break_glass: profile.role_is_break_glass,
		permissions: profile.permissions,
		..UserProfile::default()
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
