//! `governance` module — the ownership plane's three gRPC faces.
//!
//! [`Governance`] is the signed-in consilium surface, mounted BEHIND the user auth
//! layer and gated on [`Permission::RoleGrant`] — the existing Owner-only cell of the
//! RBAC matrix, because taking a seat away is precisely a role change. No new
//! permission and no second gate: the matrix stays defined in one place.
//!
//! [`RemovalApproval`] is what the TARGET reaches from their mailbox, mounted OUTSIDE
//! the auth layer like `AuthService`: the emailed token is the credential and the
//! person holding it may not be signed in. The read is side-effect free because mail
//! scanners issue automatic requests for every URL in a message; answering needs the
//! secret code from the same message, which turns a scanned link into a deliberate act.
//! Unknown, expired, spent, burned and wrong-state tokens produce ONE identical
//! response, so a caller cannot tell which they hit.
//!
//! [`MailRelay`] is the one seam the MONEY plane pushes to, mounted outside the auth
//! layer and authenticated by the shared service secret exactly as the lifecycle bridge
//! is. The payload is TYPED, never rendered markup, and the recipient's address is
//! resolved HERE from the identity record — a compromised money plane must not be able
//! to redirect a governance mail or put arbitrary HTML in an owner's inbox. WHO may
//! receive one is decided per KIND: the consilium kinds — the payouts, a payment
//! approval, a fee policy approval — go to a seated owner; a payment consent and a fee
//! policy notice go to the one person they are about and to nobody else. Every kind also
//! requires the resolved address to be VERIFIED: an approval carries a link and the code
//! that arms it, a notice reveals a holding, and an address nobody has proved belongs to
//! the person hands that to whoever holds the mailbox.
//!
//! WHAT CROSSES THE WIRE ON THE LIVE FEED. A revision, never a tally. The client
//! refetches the authoritative snapshot when the number moves, so a stale or replayed
//! frame can never render a wrong count. The stream ALSO re-reads Postgres on an
//! interval, so a replica that never sees the in-process broadcast still converges.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::{
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
	time::Duration,
};

use domain::{
	authz::{Permission, Role},
	governance::{
		AdmissionId, AdmissionVote as DomainAdmissionVote, PAYOUT_MIN_OWNERS, ProposalState, ProposalVote as DomainProposalVote, RemovalId, RemovalState, UserProposalId, UserProposalKind,
		Vote,
	},
	users::{Email, User, UserId},
};
use evconcierge_contracts::concierge::v1::{
	AdmissionPeer as AdmissionPeerMsg, AdmissionVote, CancelOwnerAdmissionRequest, CancelOwnerRemovalRequest, CancelUserProposalRequest, FeeTerms as FeeTermsMsg, GetOwnerAdmissionRequest,
	GetOwnerRemovalRequest, GetRemovalInvitationRequest, GetUserProposalRequest, GovernanceMailKind, GovernanceTick, ListOwnerAdmissionsRequest, ListOwnerRemovalsRequest, ListOwnersRequest,
	ListUserProposalsRequest, OpenAdminAdmissionRequest, OpenOwnerAdmissionRequest, OpenOwnerRemovalRequest, OpenUserReinstatementRequest, OpenUserSuspensionRequest, Owner,
	OwnerAdmission as OwnerAdmissionMsg, OwnerAdmissionList, OwnerAdmissionState, OwnerList, OwnerRemoval as OwnerRemovalMsg, OwnerRemovalInvitation, OwnerRemovalList, OwnerRemovalState,
	ProposalVote as ProposalVoteMsg, RemovalPeer, RemovalVote, ResignOwnershipRequest, SendGovernanceMailRequest, SendGovernanceMailResponse, SubmitAdmissionVoteRequest,
	SubmitPeerVoteRequest, SubmitSelfDecisionRequest, SubmitSelfDecisionResponse, SubmitUserProposalVoteRequest, UserProposal as UserProposalMsg, UserProposalKind as UserProposalKindMsg,
	UserProposalList, UserProposalPeer as UserProposalPeerMsg, UserProposalState, WatchGovernanceRequest, governance_service_server::GovernanceService,
	mail_relay_service_server::MailRelayService, owner_removal_approval_service_server::OwnerRemovalApprovalService,
};
use tokio::sync::{broadcast, mpsc};
use tonic::{Request, Response, Status, codegen::tokio_stream::Stream};
use uuid::Uuid;

use crate::{
	authz::BreakGlass,
	infrastructure::{
		email::templates::{fmt_ts, pct_change},
		governance::{AdmissionRecord, Audit, InvitationRecord, RemovalRecord, SelfDecision, UserProposalRecord},
	},
	notification::{RateLimiter, now_secs},
	ports::{GovernanceRepository, NotificationRepository, UserDirectoryRepository},
	support::{authenticate_service, domain_to_status},
};

/// The ONE answer an unknown, expired, spent, burned or wrong-state token gets.
const INVITATION_MISSING: &str = "invitation not found";
/// How often the live feed re-reads the revision from Postgres. Correctness never
/// depends on the in-process broadcast reaching every replica; this is what guarantees
/// a second instance converges.
const FEED_POLL: Duration = Duration::from_secs(5);
/// Keepalive, so a client can tell a live stream from a wedged one.
const FEED_HEARTBEAT: Duration = Duration::from_secs(20);
/// Buffered ticks per subscriber. A slow client is disconnected rather than served
/// stale frames — it can always refetch.
const FEED_BUFFER: usize = 8;
const DEFAULT_REMOVAL_PAGE: u32 = 25;
const MAX_REMOVAL_PAGE: u32 = 200;

/// The signed-in consilium surface. Cheaply cloneable (everything behind `Arc`s).
#[derive(Clone)]
pub struct Governance {
	users: Arc<dyn UserDirectoryRepository>,
	break_glass: Arc<BreakGlass>,
	governance: Arc<dyn GovernanceRepository>,
	revisions: broadcast::Sender<u64>,
}

impl Governance {
	pub fn new(users: Arc<dyn UserDirectoryRepository>, break_glass: Arc<BreakGlass>, governance: Arc<dyn GovernanceRepository>, revisions: broadcast::Sender<u64>) -> Self {
		Self {
			users,
			break_glass,
			governance,
			revisions,
		}
	}

	/// Owner-only, through the shared RBAC gate, with the live-record check that denies
	/// a suspended or token-revoked principal even while their access token still
	/// verifies.
	async fn require_owner<T>(&self, request: &Request<T>) -> Result<(), Status> {
		crate::authz::require_permission(self.users.as_ref(), &self.break_glass, request, Permission::RoleGrant).await
	}

	/// The roster as the wire shows it. Deliberately NOT reached by re-entering
	/// `list_owners`: a synthetic `Request` carries no verified claims, so the gate
	/// would reject the very caller it had already authorized.
	async fn owner_list(&self) -> Result<OwnerList, Status> {
		let owners = self.governance.owners().await.map_err(domain_to_status)?;
		Ok(OwnerList {
			// PAYOUT_MIN_OWNERS, deliberately NOT the removal floor. Two owners is a legal
			// roster that simply cannot authorize a payout — a warning to surface, not a
			// rule that blocks anything.
			below_payout_floor: owners.len() < PAYOUT_MIN_OWNERS,
			items: owners
				.into_iter()
				.map(|owner| Owner {
					user_id: owner.id.to_string(),
					email: owner.email.unwrap_or_default(),
					display_name: owner.display_name.unwrap_or_default(),
					owner_since: owner.owner_since,
				})
				.collect(),
		})
	}

	/// The three `Open*` RPCs differ only in the kind they mint. They stay three RPCs
	/// rather than one taking a kind so that a refusal elsewhere can name the exact verb
	/// an operator needs — `SetRole` telling them "OpenAdminAdmission" is a usable
	/// instruction, "OpenUserProposal with kind=ADMIN_ADMISSION" is a puzzle — and so the
	/// three can be permissioned apart later without a wire change.
	async fn open_proposal(&self, kind: UserProposalKind, user_id: &str, reason: &str, initiator: UserId) -> Result<Response<UserProposalMsg>, Status> {
		let subject = parse_user_id(user_id, "user_id")?;
		let record = self.governance.open_user_proposal(kind, subject, initiator, reason, now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(proposal_to_proto(&record)))
	}

	/// The authenticated owner acting, as their full identity record — governance needs
	/// the caller's own address, not only their id.
	async fn acting_owner<T>(&self, request: &Request<T>) -> Result<User, Status> {
		self.require_owner(request).await?;
		let gate = crate::authz::caller_gate(self.users.as_ref(), request).await?;
		let id = gate.id.ok_or_else(|| Status::unauthenticated("subject is not a user id"))?;
		self.users.find_by_id(id).await.map_err(domain_to_status)?.ok_or_else(|| Status::not_found("user"))
	}
}

/// Publish the committed revision to this process's subscribers. Best-effort by
/// design: the stream's own Postgres poll is what makes the feed correct, so a send
/// with no listeners (or a dropped one) is not an error.
async fn announce(repo: &dyn GovernanceRepository, revisions: &broadcast::Sender<u64>) {
	match repo.revision().await {
		Ok(revision) => {
			let _ = revisions.send(revision);
		}
		Err(err) => tracing::warn!(%err, "governance revision could not be read for the live feed"),
	}
}

/// The transport facts an answer arrived with. `SubmitSelfDecision` carries them
/// explicitly because the BFF, not the browser, is this server's peer.
pub(crate) fn audit_of<T>(request: &Request<T>) -> Audit {
	Audit {
		client_ip: request.remote_addr().map(|addr| addr.ip().to_string()).unwrap_or_default(),
		user_agent: request.metadata().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned(),
	}
}

fn parse_user_id(raw: &str, field: &str) -> Result<UserId, Status> {
	Uuid::parse_str(raw)
		.map(UserId::from_raw)
		.map_err(|_| Status::invalid_argument(format!("{field} is not a valid UUID")))
}

fn parse_removal_id(raw: &str) -> Result<RemovalId, Status> {
	Uuid::parse_str(raw)
		.map(RemovalId::from_raw)
		.map_err(|_| Status::invalid_argument("removal_id is not a valid UUID"))
}

fn vote_from_proto(raw: i32) -> Result<Vote, Status> {
	match RemovalVote::try_from(raw) {
		Ok(RemovalVote::Remove) => Ok(Vote::Remove),
		Ok(RemovalVote::Keep) => Ok(Vote::Keep),
		_ => Err(Status::invalid_argument("vote must be REMOVE or KEEP")),
	}
}

fn vote_to_proto(vote: Vote) -> RemovalVote {
	match vote {
		Vote::Pending => RemovalVote::Pending,
		Vote::Remove => RemovalVote::Remove,
		Vote::Keep => RemovalVote::Keep,
	}
}

fn state_to_proto(state: RemovalState) -> OwnerRemovalState {
	match state {
		RemovalState::Open => OwnerRemovalState::Open,
		RemovalState::Executed => OwnerRemovalState::Executed,
		RemovalState::Rejected => OwnerRemovalState::Rejected,
		RemovalState::Expired => OwnerRemovalState::Expired,
		RemovalState::Cancelled => OwnerRemovalState::Cancelled,
		RemovalState::Void => OwnerRemovalState::Void,
	}
}

fn parse_admission_id(raw: &str) -> Result<AdmissionId, Status> {
	Uuid::parse_str(raw)
		.map(AdmissionId::from_raw)
		.map_err(|_| Status::invalid_argument("admission_id is not a valid UUID"))
}

fn admission_vote_from_proto(raw: i32) -> Result<DomainAdmissionVote, Status> {
	match AdmissionVote::try_from(raw) {
		Ok(AdmissionVote::Admit) => Ok(DomainAdmissionVote::Admit),
		Ok(AdmissionVote::Reject) => Ok(DomainAdmissionVote::Reject),
		_ => Err(Status::invalid_argument("vote must be ADMIT or REJECT")),
	}
}

fn admission_vote_to_proto(vote: DomainAdmissionVote) -> AdmissionVote {
	match vote {
		DomainAdmissionVote::Pending => AdmissionVote::Pending,
		DomainAdmissionVote::Admit => AdmissionVote::Admit,
		DomainAdmissionVote::Reject => AdmissionVote::Reject,
	}
}

fn parse_proposal_id(raw: &str) -> Result<UserProposalId, Status> {
	Uuid::parse_str(raw)
		.map(UserProposalId::from_raw)
		.map_err(|_| Status::invalid_argument("proposal_id is not a valid UUID"))
}

fn proposal_vote_from_proto(raw: i32) -> Result<DomainProposalVote, Status> {
	match ProposalVoteMsg::try_from(raw) {
		Ok(ProposalVoteMsg::For) => Ok(DomainProposalVote::For),
		Ok(ProposalVoteMsg::Against) => Ok(DomainProposalVote::Against),
		_ => Err(Status::invalid_argument("vote must be FOR or AGAINST")),
	}
}

fn proposal_vote_to_proto(vote: DomainProposalVote) -> ProposalVoteMsg {
	match vote {
		DomainProposalVote::Pending => ProposalVoteMsg::Pending,
		DomainProposalVote::For => ProposalVoteMsg::For,
		DomainProposalVote::Against => ProposalVoteMsg::Against,
	}
}

/// UNSPECIFIED means "every kind" on a list, so it is `None` rather than a rejection; an
/// unknown number is a client sending a kind this build does not have and IS a rejection,
/// because silently listing everything would answer a question nobody asked.
fn proposal_kind_from_proto(raw: i32) -> Result<Option<UserProposalKind>, Status> {
	match UserProposalKindMsg::try_from(raw) {
		Ok(UserProposalKindMsg::Unspecified) => Ok(None),
		Ok(UserProposalKindMsg::Suspension) => Ok(Some(UserProposalKind::Suspension)),
		Ok(UserProposalKindMsg::Reinstatement) => Ok(Some(UserProposalKind::Reinstatement)),
		Ok(UserProposalKindMsg::AdminAdmission) => Ok(Some(UserProposalKind::AdminAdmission)),
		Err(_) => Err(Status::invalid_argument("unknown user proposal kind")),
	}
}

fn proposal_kind_to_proto(kind: UserProposalKind) -> UserProposalKindMsg {
	match kind {
		UserProposalKind::Suspension => UserProposalKindMsg::Suspension,
		UserProposalKind::Reinstatement => UserProposalKindMsg::Reinstatement,
		UserProposalKind::AdminAdmission => UserProposalKindMsg::AdminAdmission,
	}
}

fn proposal_state_to_proto(state: ProposalState) -> UserProposalState {
	match state {
		ProposalState::Open => UserProposalState::Open,
		ProposalState::Executed => UserProposalState::Executed,
		ProposalState::Rejected => UserProposalState::Rejected,
		ProposalState::Expired => UserProposalState::Expired,
		ProposalState::Cancelled => UserProposalState::Cancelled,
		ProposalState::Void => UserProposalState::Void,
	}
}

fn proposal_to_proto(record: &UserProposalRecord) -> UserProposalMsg {
	let proposal = &record.proposal;
	UserProposalMsg {
		id: proposal.id().to_string(),
		kind: proposal_kind_to_proto(proposal.kind()) as i32,
		state: proposal_state_to_proto(record.state) as i32,
		subject_user_id: proposal.subject().to_string(),
		subject_email: record.subject_email.clone(),
		initiator_user_id: proposal.initiator().to_string(),
		initiator_email: record.initiator_email.clone(),
		reason: proposal.reason().to_owned(),
		peers: proposal
			.peers()
			.iter()
			.zip(record.peer_emails.iter())
			.map(|(peer, email)| UserProposalPeerMsg {
				user_id: peer.user_id.to_string(),
				email: email.clone(),
				vote: proposal_vote_to_proto(peer.vote) as i32,
				voted_at: peer.voted_at,
			})
			.collect(),
		owner_count: proposal.owner_count(),
		threshold: proposal.threshold(),
		created_at: proposal.created_at(),
		expires_at: proposal.expires_at(),
		decided_at: proposal.decided_at(),
		void_reason: proposal.void_reason().to_owned(),
		version: proposal.version(),
	}
}

fn admission_state_to_proto(state: ProposalState) -> OwnerAdmissionState {
	match state {
		ProposalState::Open => OwnerAdmissionState::Open,
		ProposalState::Executed => OwnerAdmissionState::Executed,
		ProposalState::Rejected => OwnerAdmissionState::Rejected,
		ProposalState::Expired => OwnerAdmissionState::Expired,
		ProposalState::Cancelled => OwnerAdmissionState::Cancelled,
		ProposalState::Void => OwnerAdmissionState::Void,
	}
}

fn admission_to_proto(record: &AdmissionRecord) -> OwnerAdmissionMsg {
	let admission = &record.admission;
	OwnerAdmissionMsg {
		id: admission.id().to_string(),
		state: admission_state_to_proto(record.state) as i32,
		candidate_user_id: admission.candidate().to_string(),
		candidate_email: record.candidate_email.clone(),
		initiator_user_id: admission.initiator().to_string(),
		initiator_email: record.initiator_email.clone(),
		reason: admission.reason().to_owned(),
		peers: admission
			.peers()
			.iter()
			.zip(record.peer_emails.iter())
			.map(|(peer, email)| AdmissionPeerMsg {
				user_id: peer.user_id.to_string(),
				email: email.clone(),
				vote: admission_vote_to_proto(peer.vote) as i32,
				voted_at: peer.voted_at,
			})
			.collect(),
		owner_count: admission.owner_count(),
		created_at: admission.created_at(),
		expires_at: admission.expires_at(),
		decided_at: admission.decided_at(),
		void_reason: admission.void_reason().to_owned(),
		version: admission.version(),
	}
}

fn removal_to_proto(record: &RemovalRecord) -> OwnerRemovalMsg {
	let removal = &record.removal;
	OwnerRemovalMsg {
		id: removal.id().to_string(),
		state: state_to_proto(record.state) as i32,
		target_user_id: removal.target().to_string(),
		target_email: record.target_email.clone(),
		initiator_user_id: removal.initiator().to_string(),
		initiator_email: record.initiator_email.clone(),
		reason: removal.reason().to_owned(),
		peers: removal
			.peers()
			.iter()
			.zip(record.peer_emails.iter())
			.map(|(peer, email)| RemovalPeer {
				user_id: peer.user_id.to_string(),
				email: email.clone(),
				vote: vote_to_proto(peer.vote) as i32,
				voted_at: peer.voted_at,
			})
			.collect(),
		target_decision: vote_to_proto(removal.decision()) as i32,
		target_decided_at: removal.decided_as_target_at(),
		target_notified: removal.target_notified(),
		owner_count: removal.owner_count(),
		created_at: removal.created_at(),
		expires_at: removal.expires_at(),
		decided_at: removal.decided_at(),
		void_reason: removal.void_reason().to_owned(),
		version: removal.version(),
	}
}

fn invitation_to_proto(record: InvitationRecord) -> OwnerRemovalInvitation {
	OwnerRemovalInvitation {
		removal_id: record.removal_id.to_string(),
		state: state_to_proto(record.state) as i32,
		initiator_email: record.initiator_email,
		target_email: record.target_email,
		reason: record.reason,
		created_at: record.created_at,
		expires_at: record.expires_at,
		decision: vote_to_proto(record.decision) as i32,
		attempts_remaining: record.attempts_remaining,
	}
}

/// The live feed, as a stream tonic can serve. A plain `mpsc` receiver rather than a
/// wrapper type, so the module needs nothing beyond what tonic already brings.
pub struct TickStream {
	rx: mpsc::Receiver<Result<GovernanceTick, Status>>,
}

impl Stream for TickStream {
	type Item = Result<GovernanceTick, Status>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.rx.poll_recv(cx)
	}
}

fn tick(revision: u64, heartbeat: bool) -> GovernanceTick {
	GovernanceTick {
		revision,
		at: now_secs(),
		heartbeat,
	}
}

#[tonic::async_trait]
impl GovernanceService for Governance {
	type WatchGovernanceStream = TickStream;

	async fn list_owners(&self, request: Request<ListOwnersRequest>) -> Result<Response<OwnerList>, Status> {
		self.require_owner(&request).await?;
		Ok(Response::new(self.owner_list().await?))
	}

	async fn open_owner_removal(&self, request: Request<OpenOwnerRemovalRequest>) -> Result<Response<OwnerRemovalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let req = request.into_inner();
		let target = parse_user_id(&req.target_user_id, "target_user_id")?;
		let record = self.governance.open_removal(target, caller.id(), &req.reason, now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(removal_to_proto(&record)))
	}

	async fn cancel_owner_removal(&self, request: Request<CancelOwnerRemovalRequest>) -> Result<Response<OwnerRemovalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let id = parse_removal_id(&request.get_ref().removal_id)?;
		let record = self.governance.cancel_removal(id, caller.id(), now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(removal_to_proto(&record)))
	}

	/// The target and the initiator are refused here by the SNAPSHOTTED peer set not
	/// containing them, never by a check at this layer — there is deliberately no code
	/// path that could accept their vote.
	async fn submit_peer_vote(&self, request: Request<SubmitPeerVoteRequest>) -> Result<Response<OwnerRemovalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let id = parse_removal_id(&req.removal_id)?;
		let vote = vote_from_proto(req.vote)?;
		let record = self.governance.peer_vote(id, caller.id(), vote, now_secs(), &audit).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(removal_to_proto(&record)))
	}

	/// Propose GRANTING a seat. This RPC and the vote below are the ONLY way
	/// `Role::Owner` is ever granted: `UserDirectory.SetRole` refuses it outright, so a
	/// bad actor cannot mint the sock puppets that would carry a payout quorum.
	async fn open_owner_admission(&self, request: Request<OpenOwnerAdmissionRequest>) -> Result<Response<OwnerAdmissionMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let req = request.into_inner();
		let candidate = parse_user_id(&req.candidate_user_id, "candidate_user_id")?;
		let record = self.governance.open_admission(candidate, caller.id(), &req.reason, now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(admission_to_proto(&record)))
	}

	async fn cancel_owner_admission(&self, request: Request<CancelOwnerAdmissionRequest>) -> Result<Response<OwnerAdmissionMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let id = parse_admission_id(&request.get_ref().admission_id)?;
		let record = self.governance.cancel_admission(id, caller.id(), now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(admission_to_proto(&record)))
	}

	/// The initiator and the candidate are refused here by the SNAPSHOTTED voter set not
	/// containing them, never by a check at this layer.
	async fn submit_admission_vote(&self, request: Request<SubmitAdmissionVoteRequest>) -> Result<Response<OwnerAdmissionMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let id = parse_admission_id(&req.admission_id)?;
		let vote = admission_vote_from_proto(req.vote)?;
		let record = self.governance.admission_vote(id, caller.id(), vote, now_secs(), &audit).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(admission_to_proto(&record)))
	}

	async fn get_owner_admission(&self, request: Request<GetOwnerAdmissionRequest>) -> Result<Response<OwnerAdmissionMsg>, Status> {
		self.require_owner(&request).await?;
		let id = parse_admission_id(&request.get_ref().admission_id)?;
		let record = self
			.governance
			.find_admission(id, now_secs())
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found("owner admission not found"))?;
		Ok(Response::new(admission_to_proto(&record)))
	}

	async fn list_owner_admissions(&self, request: Request<ListOwnerAdmissionsRequest>) -> Result<Response<OwnerAdmissionList>, Status> {
		self.require_owner(&request).await?;
		let limit = match request.get_ref().limit {
			0 => DEFAULT_REMOVAL_PAGE,
			n => n.min(MAX_REMOVAL_PAGE),
		};
		let records = self.governance.list_admissions(i64::from(limit), now_secs()).await.map_err(domain_to_status)?;
		Ok(Response::new(OwnerAdmissionList {
			items: records.iter().map(admission_to_proto).collect(),
		}))
	}

	/// Make a hold permanent. The half of the retired `DisableUser` verb that is NOT an
	/// emergency: `UserDirectory.HoldUser` freezes the account now and lapses in 24h, and
	/// this is what makes it stay.
	async fn open_user_suspension(&self, request: Request<OpenUserSuspensionRequest>) -> Result<Response<UserProposalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let req = request.into_inner();
		self.open_proposal(UserProposalKind::Suspension, &req.user_id, &req.reason, caller.id()).await
	}

	/// Lift a suspension THE OWNERS imposed. It exists because `ReinstateUser` refuses
	/// those: without this RPC their verdict would be either permanent or reversible by
	/// any one admin, and both are wrong.
	async fn open_user_reinstatement(&self, request: Request<OpenUserReinstatementRequest>) -> Result<Response<UserProposalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let req = request.into_inner();
		self.open_proposal(UserProposalKind::Reinstatement, &req.user_id, &req.reason, caller.id()).await
	}

	/// Grant `Role::Admin`. `UserDirectory.SetRole` refuses that role in the granting
	/// direction and names this, the same refusal `owner` already gets and for a related
	/// reason: an operator who can appoint operators can appoint accomplices, and the
	/// admin seat carries every identity mutation except role granting.
	async fn open_admin_admission(&self, request: Request<OpenAdminAdmissionRequest>) -> Result<Response<UserProposalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let req = request.into_inner();
		self.open_proposal(UserProposalKind::AdminAdmission, &req.user_id, &req.reason, caller.id()).await
	}

	async fn cancel_user_proposal(&self, request: Request<CancelUserProposalRequest>) -> Result<Response<UserProposalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let id = parse_proposal_id(&request.get_ref().proposal_id)?;
		let record = self.governance.cancel_user_proposal(id, caller.id(), now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(proposal_to_proto(&record)))
	}

	/// The initiator is refused here by the SNAPSHOTTED voter set not containing them,
	/// never by a check at this layer. A vote that meets the threshold ALSO applies the
	/// verdict, inside the same transaction — see `GovernanceRepository::user_proposal_vote`.
	async fn submit_user_proposal_vote(&self, request: Request<SubmitUserProposalVoteRequest>) -> Result<Response<UserProposalMsg>, Status> {
		let caller = self.acting_owner(&request).await?;
		let audit = audit_of(&request);
		let req = request.into_inner();
		let id = parse_proposal_id(&req.proposal_id)?;
		let vote = proposal_vote_from_proto(req.vote)?;
		let record = self.governance.user_proposal_vote(id, caller.id(), vote, now_secs(), &audit).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(proposal_to_proto(&record)))
	}

	async fn get_user_proposal(&self, request: Request<GetUserProposalRequest>) -> Result<Response<UserProposalMsg>, Status> {
		self.require_owner(&request).await?;
		let id = parse_proposal_id(&request.get_ref().proposal_id)?;
		let record = self
			.governance
			.find_user_proposal(id, now_secs())
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found("user proposal not found"))?;
		Ok(Response::new(proposal_to_proto(&record)))
	}

	async fn list_user_proposals(&self, request: Request<ListUserProposalsRequest>) -> Result<Response<UserProposalList>, Status> {
		self.require_owner(&request).await?;
		let req = request.get_ref();
		let limit = match req.limit {
			0 => DEFAULT_REMOVAL_PAGE,
			n => n.min(MAX_REMOVAL_PAGE),
		};
		let kind = proposal_kind_from_proto(req.kind)?;
		let records = self.governance.list_user_proposals(kind, i64::from(limit), now_secs()).await.map_err(domain_to_status)?;
		Ok(Response::new(UserProposalList {
			items: records.iter().map(proposal_to_proto).collect(),
		}))
	}

	async fn resign_ownership(&self, request: Request<ResignOwnershipRequest>) -> Result<Response<OwnerList>, Status> {
		let caller = self.acting_owner(&request).await?;
		// Typed confirmation, so resigning cannot be a stray click. Normalized through
		// the same parser the identity record was stored with, so casing never matters.
		let confirm = Email::parse(&request.get_ref().confirm_email).map_err(|_| Status::invalid_argument("confirm_email must be your own address"))?;
		if confirm != *caller.email() {
			return Err(Status::invalid_argument("confirm_email must be your own address"));
		}
		self.governance.resign(caller.id(), now_secs()).await.map_err(domain_to_status)?;
		announce(self.governance.as_ref(), &self.revisions).await;
		Ok(Response::new(self.owner_list().await?))
	}

	async fn get_owner_removal(&self, request: Request<GetOwnerRemovalRequest>) -> Result<Response<OwnerRemovalMsg>, Status> {
		self.require_owner(&request).await?;
		let id = parse_removal_id(&request.get_ref().removal_id)?;
		let record = self
			.governance
			.find_removal(id, now_secs())
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found("owner removal not found"))?;
		Ok(Response::new(removal_to_proto(&record)))
	}

	async fn list_owner_removals(&self, request: Request<ListOwnerRemovalsRequest>) -> Result<Response<OwnerRemovalList>, Status> {
		self.require_owner(&request).await?;
		let limit = match request.get_ref().limit {
			0 => DEFAULT_REMOVAL_PAGE,
			n => n.min(MAX_REMOVAL_PAGE),
		};
		let records = self.governance.list_removals(i64::from(limit), now_secs()).await.map_err(domain_to_status)?;
		Ok(Response::new(OwnerRemovalList {
			items: records.iter().map(removal_to_proto).collect(),
		}))
	}

	async fn watch_governance(&self, request: Request<WatchGovernanceRequest>) -> Result<Response<Self::WatchGovernanceStream>, Status> {
		// Authorized at the handshake, exactly as every other RPC on this service.
		self.require_owner(&request).await?;
		let (tx, rx) = mpsc::channel(FEED_BUFFER);
		let repo = self.governance.clone();
		let mut broadcast_rx = self.revisions.subscribe();

		tokio::spawn(async move {
			let mut last = repo.revision().await.unwrap_or_default();
			if tx.send(Ok(tick(last, false))).await.is_err() {
				return;
			}
			let mut poll = tokio::time::interval(FEED_POLL);
			let mut beat = tokio::time::interval(FEED_HEARTBEAT);
			// Both fire immediately on creation; spend that first tick here so the
			// client is not sent three frames at once on connect.
			poll.tick().await;
			beat.tick().await;

			loop {
				let (revision, heartbeat) = tokio::select! {
					// The durable read. This — not the broadcast — is what makes the
					// feed correct when more than one replica is serving.
					_ = poll.tick() => match repo.revision().await {
						Ok(revision) => (revision, false),
						Err(err) => {
							tracing::warn!(%err, "governance revision poll failed");
							continue;
						}
					},
					// The broadcast is only an immediacy optimisation. A lagged
					// receiver is not an error: the next poll re-reads the truth.
					received = broadcast_rx.recv() => match received {
						Ok(revision) => (revision, false),
						Err(broadcast::error::RecvError::Lagged(_)) => continue,
						Err(broadcast::error::RecvError::Closed) => return,
					},
					_ = beat.tick() => (last, true),
				};

				// A tick carries a REVISION, never a tally, and never moves backwards.
				if !heartbeat && revision <= last {
					continue;
				}
				last = last.max(revision);
				if tx.send(Ok(tick(last, heartbeat))).await.is_err() {
					return;
				}
			}
		});

		Ok(Response::new(TickStream { rx }))
	}
}

/// The mailbox-side surface. Mounted OUTSIDE the user auth layer.
#[derive(Clone)]
pub struct RemovalApproval {
	governance: Arc<dyn GovernanceRepository>,
	revisions: broadcast::Sender<u64>,
}

impl RemovalApproval {
	pub fn new(governance: Arc<dyn GovernanceRepository>, revisions: broadcast::Sender<u64>) -> Self {
		Self { governance, revisions }
	}
}

#[tonic::async_trait]
impl OwnerRemovalApprovalService for RemovalApproval {
	/// STRICTLY side-effect free: no attempt is counted, no token is spent, nothing is
	/// written. Mail scanners issue automatic requests for every URL in a message, so a
	/// scanned link must be able to change nothing at all.
	async fn get_invitation(&self, request: Request<GetRemovalInvitationRequest>) -> Result<Response<OwnerRemovalInvitation>, Status> {
		let token = request.into_inner().token;
		let found = if token.is_empty() {
			None
		} else {
			self.governance.invitation(&token, now_secs()).await.map_err(domain_to_status)?
		};
		found
			.map(|record| Response::new(invitation_to_proto(record)))
			.ok_or_else(|| Status::not_found(INVITATION_MISSING))
	}

	async fn submit_self_decision(&self, request: Request<SubmitSelfDecisionRequest>) -> Result<Response<SubmitSelfDecisionResponse>, Status> {
		let transport = audit_of(&request);
		let req = request.into_inner();
		let vote = vote_from_proto(req.vote)?;
		// The BFF is this server's peer, so the browser's own facts are forwarded in the
		// body; the transport's view is the fallback when they are absent.
		let audit = Audit {
			client_ip: if req.client_ip.is_empty() { transport.client_ip } else { req.client_ip },
			user_agent: if req.user_agent.is_empty() { transport.user_agent } else { req.user_agent },
		};

		match self.governance.self_decision(&req.token, &req.code, vote, now_secs(), &audit).await.map_err(domain_to_status)? {
			SelfDecision::Unusable => Err(Status::not_found(INVITATION_MISSING)),
			// INVALID_ARGUMENT, deliberately not PERMISSION_DENIED: a mistyped character is
			// bad input, not a fact about who the caller is — the same owner retyping the
			// same code gets in. PERMISSION_DENIED would read as "this is not yours",
			// which is what makes an owner burn their remaining attempts and set off a
			// brute-force alert to every other owner. This is not an enumeration oracle: a
			// wrong code is only reachable by someone already holding a valid, live,
			// unspent token.
			//
			// The older wording argued this from the console — that the BFF folded
			// PermissionDenied into an opaque 404. It does not: banking's cabinet BFF
			// treats PermissionDenied as client-safe and relays the message under a 403.
			SelfDecision::WrongCode { attempts_remaining } => Err(Status::invalid_argument(format!("incorrect code — {attempts_remaining} attempts remain"))),
			SelfDecision::Decided(record) => {
				announce(self.governance.as_ref(), &self.revisions).await;
				Ok(Response::new(SubmitSelfDecisionResponse {
					invitation: Some(invitation_to_proto(*record)),
					decided: true,
				}))
			}
		}
	}
}

/// The money plane's one push seam into this plane's mailer.
#[derive(Clone)]
pub struct MailRelay {
	users: Arc<dyn UserDirectoryRepository>,
	governance: Arc<dyn GovernanceRepository>,
	/// The in-app inbox, for the one kind whose reader has no other surface to find it
	/// on — see [`CONSENT_TOPIC`].
	notifications: Arc<dyn NotificationRepository>,
	/// Per-RECIPIENT ceiling. The money plane is the one caller and is trusted enough
	/// to be here at all; what this bounds is how much branded security mail a
	/// compromised one can aim at a single person before an operator notices. In
	/// memory and per process, like the subscribe limiter, and for the same reason: the
	/// durable ceiling is the daily send budget.
	limiter: Arc<RateLimiter>,
	/// `None` ⇒ the relay is not configured and every call is rejected (fail closed).
	/// In production this is the SAME `BRIDGE_SERVICE_TOKEN` banking presents when it
	/// pulls the outbox: one trust relationship between the planes, one secret to rotate.
	token: Option<Arc<str>>,
	/// Origin every emailed link must sit under, without a trailing slash.
	approval_origin: String,
}

impl MailRelay {
	pub fn new(
		users: Arc<dyn UserDirectoryRepository>,
		governance: Arc<dyn GovernanceRepository>,
		notifications: Arc<dyn NotificationRepository>,
		limiter: Arc<RateLimiter>,
		token: Option<String>,
		approval_origin: String,
	) -> Self {
		Self {
			users,
			governance,
			notifications,
			limiter,
			token: token.filter(|t| !t.is_empty()).map(|t| Arc::from(t.as_str())),
			approval_origin: approval_origin.trim_end_matches('/').to_owned(),
		}
	}

	/// Pin the emailed link to our own origin.
	///
	/// The typed payload stops arbitrary MARKUP; it does not stop an arbitrary LINK, and
	/// a concierge-branded security mail carrying someone else's host is a phishing mail
	/// that this plane sent, to an address this plane resolved. A compromised money plane
	/// must not be able to do that.
	///
	/// The boundary is checked explicitly rather than by a bare `starts_with`, which
	/// would also accept `https://evinvest.ltd.attacker.example`.
	fn approval_link(&self, raw: &str) -> Result<String, Status> {
		let url = line(raw, 512, "approval_url")?;
		Self::check_origin(&self.approval_origin, &url)?;
		Ok(url)
	}

	/// The link rule alone, free of the ports, so it can be exercised directly.
	///
	/// The origin is a PREFIX check, and a prefix check says nothing about what follows.
	/// The text part of every mail prints the link bare on its own line, so a URL that
	/// passes the origin and then carries a space or a newline —
	/// `https://evinvest.ltd/x https://attacker.example` — puts a second, foreign link
	/// on that line, in a mail this plane signed. A URL has no business containing
	/// whitespace or anything outside printable ASCII (an encoded one never does), so
	/// the whole string is held to that before the origin is even looked at.
	fn check_origin(origin: &str, url: &str) -> Result<(), Status> {
		if url.chars().any(|c| c.is_whitespace() || !c.is_ascii_graphic()) {
			return Err(Status::invalid_argument("approval_url must not contain whitespace or non-printable characters"));
		}
		let refuse = || Status::invalid_argument("approval_url must be on this platform's public origin");
		let rest = url.strip_prefix(origin).filter(|rest| rest.is_empty() || rest.starts_with('/')).ok_or_else(refuse)?;
		// `//host` is protocol-relative and leaves our origin behind entirely.
		if rest.starts_with("//") {
			return Err(refuse());
		}
		Ok(())
	}
}

/// Cap a caller-supplied string at the width the renderer and the CHECK constraints
/// expect, rather than letting an over-long field fail deep in the queue.
fn bounded(value: &str, max: usize, field: &str) -> Result<String, Status> {
	if value.chars().count() > max {
		return Err(Status::invalid_argument(format!("{field} must be at most {max} characters")));
	}
	Ok(value.to_owned())
}

/// One line of caller-supplied text: bounded in BYTES, and free of control characters.
///
/// BYTES, because the limit exists to bound what is stored in `payload` and handed to the
/// transport, and 500 characters of four-byte code points is a two-kilobyte field. The
/// payout kinds keep counting characters via [`bounded`]: those are live contracts with
/// the money plane, and narrowing them here would start rejecting mail that is in flight.
///
/// CONTROL CHARACTERS are refused outright, for the reason [`MailRelay::check_origin`]
/// exists at all — the money plane is an untrusted caller, and every field it supplies is
/// attacker-controlled under the threat this relay is written against. A mail's TEXT part
/// is NOT escaped: it is a `Label: value` block assembled by `format!`, so a single
/// newline inside a value forges a line of that block, and the lines worth forging
/// (`Amount:`, `To:`) are exactly the facts the mail exists to show. The renderer folds
/// control characters as well; neither copy is redundant, because the renderer also
/// serves rows this function never saw.
fn line(value: &str, max_bytes: usize, field: &str) -> Result<String, Status> {
	if value.len() > max_bytes {
		return Err(Status::invalid_argument(format!("{field} must be at most {max_bytes} bytes")));
	}
	if value.chars().any(char::is_control) {
		return Err(Status::invalid_argument(format!("{field} must not contain control characters")));
	}
	Ok(value.to_owned())
}

/// [`line`], plus: the field must look like ONE address — an `@`, no whitespace.
///
/// It is rendered as "Requested by" and woven into a sentence of ours, so a value like
/// `EV Investment security — approve now` would read as our words with our authority.
/// Not `Email::parse`: that normalises, and what is shown must be what was sent.
fn address(value: &str, field: &str) -> Result<String, Status> {
	let value = line(value, 320, field)?;
	if !value.contains('@') || value.chars().any(char::is_whitespace) {
		return Err(Status::invalid_argument(format!("{field} must be an email address")));
	}
	Ok(value)
}

/// Refuse anything that a mail client or the cabinet would turn into a link. For the
/// fields the INBOX repeats: there they cannot be set apart as the money plane's text,
/// and a tappable `http://…` in the platform's own sentence is a phishing line.
///
/// Deliberately coarser than "contains a URL": the needles are `://`, `www.` and the
/// bare word `http` (which also covers `https`, `http:evil` and `HTTP evil.example`,
/// which a client may still linkify). The field this guards is an AMOUNT — a number
/// and a currency — so the false positives that coarseness buys are strings that had no
/// business in it anyway. A field that is free text gets [`no_url`] instead.
fn no_link(value: &str, field: &str) -> Result<String, Status> {
	without_needles(value, &["://", "www.", "http"], field)
}

/// [`no_link`] for a field that is FREE TEXT — a fund's name, which the money plane
/// spells as a product slug. Only the explicit shapes of a URL are refused: a scheme
/// (`://`) and `www.`. This does NOT catch a bare domain — Gmail, iOS Mail and Outlook
/// linkify `evil.example/login` on their own — and that gap is a deliberate trade-off,
/// not an oversight: a bare `http` with no scheme stays a word, and `httpfund` or
/// `lighthttp-arb` is a legal slug (banking#265). Refusing the word would not close the
/// gap; it would make every fee mail about such a fund undeliverable. Closing it takes a
/// `<label>.<tld>` heuristic that knows which dots a slug may carry — a follow-up.
fn no_url(value: &str, field: &str) -> Result<String, Status> {
	without_needles(value, &["://", "www."], field)
}

fn without_needles(value: &str, needles: &[&str], field: &str) -> Result<String, Status> {
	let lower = value.to_ascii_lowercase();
	if needles.iter().any(|needle| lower.contains(needle)) {
		return Err(Status::invalid_argument(format!("{field} must not contain a link")));
	}
	Ok(value.to_owned())
}

/// [`line`], plus: the field must actually say something.
fn required_line(value: &str, max_bytes: usize, field: &str) -> Result<String, Status> {
	if value.trim().is_empty() {
		return Err(Status::invalid_argument(format!("{field} is required")));
	}
	line(value, max_bytes, field)
}

/// The payment tiers the money plane may name.
///
/// A closed set rather than free text: this word is rendered at a person deciding whether
/// to release money, and a tier neither plane recognises means the two disagree about
/// what the payment IS — something to surface as a rejected call, not to print.
const PAYMENT_TIERS: [&str; 3] = ["internal", "service", "external"];

/// How a consilium can end, as the money plane spells it: its `ConsiliumState::as_str()`
/// upper-cased for every closed state (never OPEN — an outcome is announced only after a
/// transition), plus the burn notice's own word. A closed set for the same reason as
/// [`PAYMENT_TIERS`]: this word becomes the headline of the mail.
const OUTCOMES: [&str; 7] = ["APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "EXECUTED", "EXECUTION_FAILED", "TOKEN_BURNED"];

/// [`line`], plus: the word must be one of [`PAYMENT_TIERS`].
fn payment_tier(value: &str) -> Result<String, Status> {
	let tier = line(value, 16, "tier")?;
	if !PAYMENT_TIERS.contains(&tier.as_str()) {
		return Err(Status::invalid_argument("tier must be one of internal, service, external"));
	}
	Ok(tier)
}

/// What a management fee may be charged on, as the money plane's `ManagementBasis`
/// spells it. Closed for the reason [`PAYMENT_TIERS`] is.
const FEE_BASES: [&str; 2] = ["invested_capital", "market_value"];

/// How often a performance fee may crystallize, as the money plane's
/// `CrystallizationPeriod` spells it.
const CRYSTALLIZATIONS: [&str; 4] = ["monthly", "quarterly", "semi_annual", "annual"];

/// 100%, in basis points. A fee above it is not a fee anybody meant to propose.
const MAX_BPS: u32 = 10_000;

/// One set of fee terms, checked field by field and re-spelled as the payload the
/// renderer's `FeeTerms` deserialises. Numbers travel as numbers: the percentage a
/// person reads is made at render time, never taken from the money plane.
fn fee_terms(terms: &FeeTermsMsg, field: &str) -> Result<serde_json::Value, Status> {
	for (name, bps) in [
		("management_bps", terms.management_bps),
		("performance_bps", terms.performance_bps),
		("hurdle_bps", terms.hurdle_bps),
	] {
		if bps > MAX_BPS {
			return Err(Status::invalid_argument(format!("{field}.{name} must be at most {MAX_BPS}")));
		}
	}
	let basis = line(&terms.basis, 32, &format!("{field}.basis"))?;
	if !FEE_BASES.contains(&basis.as_str()) {
		return Err(Status::invalid_argument(format!("{field}.basis must be one of invested_capital, market_value")));
	}
	let crystallization = line(&terms.crystallization, 32, &format!("{field}.crystallization"))?;
	if !CRYSTALLIZATIONS.contains(&crystallization.as_str()) {
		return Err(Status::invalid_argument(format!(
			"{field}.crystallization must be one of monthly, quarterly, semi_annual, annual"
		)));
	}
	Ok(serde_json::json!({
		"management_bps": terms.management_bps,
		"performance_bps": terms.performance_bps,
		"hurdle_bps": terms.hurdle_bps,
		"basis": basis,
		"crystallization": crystallization,
	}))
}

/// The terms a fund charges NOW: absent is a real state (a fund with no policy charges
/// nothing), so it maps to JSON `null` rather than being refused.
fn current_fee_terms(terms: Option<&FeeTermsMsg>) -> Result<serde_json::Value, Status> {
	terms.map_or(Ok(serde_json::Value::Null), |t| fee_terms(t, "current"))
}

/// A CABINET-RELATIVE path, for the one emailed link the money plane does not get to
/// spell a host for. Where [`MailRelay::approval_link`] pins a URL to our origin, this
/// admits no origin at all: one leading `/`, printable ASCII, nothing that a browser or
/// a mail client would read as leaving the cabinet once it is hung off the cabinet's
/// origin. `//host` is protocol-relative and `/\host` is what browsers make of it, so
/// both are refused; the empty path means the cabinet's front page.
fn cabinet_path(raw: &str) -> Result<String, Status> {
	if raw.is_empty() {
		return Ok(String::new());
	}
	if raw.len() > 512 {
		return Err(Status::invalid_argument("link must be at most 512 bytes"));
	}
	if raw.chars().any(|c| c.is_whitespace() || !c.is_ascii_graphic()) {
		return Err(Status::invalid_argument("link must not contain whitespace or non-printable characters"));
	}
	let mut chars = raw.chars();
	if chars.next() != Some('/') || matches!(chars.next(), Some('/' | '\\')) {
		return Err(Status::invalid_argument("link must be a cabinet-relative path starting with a single '/'"));
	}
	Ok(raw.to_owned())
}

/// Where the in-app trace of a mail addressed by IDENTITY — a payment consent, a fee
/// policy notice — is filed.
///
/// The mail is the security channel and cannot be muted; this is what the subject finds
/// in the cabinet when that mail is late, filtered or lost. It is written REGARDLESS of
/// whether they follow the topic (`NotificationRepository::record`, not `emit`): nobody
/// subscribes to being asked about their own money, and there is no topic every user
/// follows by default — `upsert_subscriber` creates the subscriber row and nothing under
/// it, so an `emit` here would reach only the few who had opened their notification
/// settings. The topic still has to be a real one, so the inbox can filter on it and the
/// catalogue test below keeps it from drifting. A fee change is filed under money
/// movement too: it is a change to what leaves the investor's own account.
const SUBJECT_INBOX_TOPIC: &str = "account:money-movement";

/// Prefix on the inbox entry's dedupe key. The money plane chooses its own keys, and the
/// inbox is also written by this plane's own emitters; without a namespace a key the
/// money plane picked could collide with — and silently suppress — an entry of ours.
const INBOX_KEY_PREFIX: &str = "governance:";

/// What a mail addressed by identity leaves in the subject's inbox. The platform's own
/// words only — no link, no code (those live in the mail and nowhere else), and none of
/// the money plane's free text either: the operator's `reason` obviously, but also
/// `source` and `destination`, which an honest external destination can make look like
/// an address or a URL and which the inbox has no way to mark as somebody else's words.
/// One fact of theirs is repeated per kind — a consent's amount, a notice's fund name —
/// and that one is refused if it can carry a link.
struct InboxNotice {
	title: String,
	body: String,
}

/// Who a mail of a given kind may be addressed to, decided from the KIND before the
/// identity record is read. The address itself is resolved from that record either way;
/// this decides only whether the person it belongs to may be sent THIS mail.
enum Recipient {
	/// The consilium kinds — a payout or payment approval to cast, or the outcome of
	/// one — speak to a seated owner, so the recipient must hold a seat, at an address
	/// that has been verified. The payout kinds used to skip the second half (#64): an
	/// approval carries a link AND the code that arms it, so an address nobody has
	/// proved belongs to the owner hands their vote to whoever holds the mailbox, and
	/// there is no kind for which that is acceptable.
	FundOwner,
	/// A payment consent or a fee policy notice speaks to exactly one person: the one
	/// whose money moves, the one whose fund is repriced. Role decides nothing here, so
	/// the rule is identity — and the address must be verified, because an unverified
	/// one is one nobody has proved is theirs.
	Subject(UserId),
}

#[tonic::async_trait]
impl MailRelayService for MailRelay {
	async fn send_governance_mail(&self, request: Request<SendGovernanceMailRequest>) -> Result<Response<SendGovernanceMailResponse>, Status> {
		authenticate_service(self.token.as_ref(), &request, "mail relay")?;
		let req = request.into_inner();

		if req.dedupe_key.is_empty() || req.dedupe_key.chars().count() > 128 {
			return Err(Status::invalid_argument("dedupe_key must be 1-128 characters"));
		}
		let user_id = parse_user_id(&req.user_id, "user_id")?;
		// Keyed by the parsed id, so two spellings of one uuid share a bucket. PEEKED here
		// and SPENT only once a new mail is actually queued: the money plane's worker
		// retries every 30s and gives a mail up for good after ten attempts, so a budget
		// that every retry drained — the dedupe no-ops, the validation refusals — would
		// turn one busy hour into an approval mail lost forever.
		let budget_key = user_id.to_string();
		if !self.limiter.peek(&budget_key) {
			return Err(Status::resource_exhausted("too many governance mails for this recipient in the current window"));
		}

		let (kind, payload, recipient_rule, notice) = match GovernanceMailKind::try_from(req.kind) {
			Ok(GovernanceMailKind::PayoutApproval) => {
				let mail = req.payout_approval.ok_or_else(|| Status::invalid_argument("payout_approval is required for this kind"))?;
				let payload = serde_json::json!({
					"consilium_id": bounded(&mail.consilium_id, 64, "consilium_id")?,
					"initiator_email": address(&mail.initiator_email, "initiator_email")?,
					"network": bounded(&mail.network, 64, "network")?,
					"address": bounded(&mail.address, 128, "address")?,
					"amount": bounded(&mail.amount, 64, "amount")?,
					"memo": bounded(&mail.memo, 500, "memo")?,
					"payload_hash": bounded(&mail.payload_hash, 128, "payload_hash")?,
					"threshold": mail.threshold,
					"owner_count": mail.owner_count,
					"expires_at": mail.expires_at,
					"approval_url": self.approval_link(&mail.approval_url)?,
					"code": bounded(&mail.code, 64, "code")?,
				});
				("payout_approval", payload, Recipient::FundOwner, None)
			}
			// A burned approval token is an outcome the owners are told about, and the
			// outcome payload already carries everything that mail needs to say. The
			// payout fields keep `bounded` (a live contract); the payment tuple added
			// later is held to `line` like every other payment field, and the fee terms
			// added after that to the fee approval's rules, so the money plane learns one
			// rule per field across every kind that carries it.
			Ok(GovernanceMailKind::PayoutOutcome) | Ok(GovernanceMailKind::ApprovalTokenBurned) => {
				let mail = req.payout_outcome.ok_or_else(|| Status::invalid_argument("payout_outcome is required for this kind"))?;
				let outcome = bounded(&mail.outcome, 64, "outcome")?;
				if !OUTCOMES.contains(&outcome.as_str()) {
					return Err(Status::invalid_argument("outcome must be one of the consilium outcomes"));
				}
				// One subject per mail. The renderer switches on which description is filled,
				// so a payload naming two would describe a rail on a payment, or a price on a
				// transfer — and half a description would render a transfer with one end
				// missing, or new terms for no fund. A payload naming NONE is a payout with
				// an empty rail: a live contract, left as it is.
				let names_a_rail = !mail.network.is_empty() || !mail.address.is_empty();
				let names_a_payment = !mail.source.is_empty() || !mail.destination.is_empty() || !mail.tier.is_empty();
				let names_fee_terms = !mail.fund.is_empty() || mail.current.is_some() || mail.proposed.is_some();
				if [names_a_rail, names_a_payment, names_fee_terms].into_iter().filter(|named| *named).count() > 1 {
					return Err(Status::invalid_argument(
						"an outcome names either a rail (network, address), a payment (tier, source, destination), or fee terms (fund, proposed), not two",
					));
				}
				if names_a_payment && (mail.source.is_empty() || mail.destination.is_empty() || mail.tier.is_empty()) {
					return Err(Status::invalid_argument("a payment outcome needs tier, source and destination together"));
				}
				if names_fee_terms && (mail.fund.is_empty() || mail.proposed.is_none()) {
					return Err(Status::invalid_argument("a fee terms outcome needs fund and proposed together"));
				}
				let payload = serde_json::json!({
					"consilium_id": bounded(&mail.consilium_id, 64, "consilium_id")?,
					"outcome": outcome,
					"network": bounded(&mail.network, 64, "network")?,
					"address": bounded(&mail.address, 128, "address")?,
					"amount": bounded(&mail.amount, 64, "amount")?,
					"detail": bounded(&mail.detail, 500, "detail")?,
					// Empty for a payout; the burn notice over a payment or over fee terms
					// carries no reason.
					"tier": if mail.tier.is_empty() { String::new() } else { payment_tier(&mail.tier)? },
					"source": line(&mail.source, 160, "source")?,
					"destination": line(&mail.destination, 160, "destination")?,
					"reason": line(&mail.reason, 500, "reason")?,
					// Empty and null for a payout and for a payment. `fund` is what the mail is
					// about, so it must say something and, as in the fee approval, must not be
					// able to carry a link.
					"fund": if names_fee_terms { no_url(&required_line(&mail.fund, 160, "fund")?, "fund")? } else { String::new() },
					"current": current_fee_terms(mail.current.as_ref())?,
					"proposed": mail.proposed.as_ref().map_or(Ok(serde_json::Value::Null), |terms| fee_terms(terms, "proposed"))?,
				});
				("payout_outcome", payload, Recipient::FundOwner, None)
			}
			// The consilium asked about a PAYMENT of fund-owned money. Addressed like a
			// payout — to a seat — but described like a consent: two ends of a transfer in
			// words, and the operator's reason as theirs. Field rules are the consent's.
			Ok(GovernanceMailKind::PaymentApproval) => {
				let mail = req.payment_approval.ok_or_else(|| Status::invalid_argument("payment_approval is required for this kind"))?;
				let payload = serde_json::json!({
					"consilium_id": line(&mail.consilium_id, 64, "consilium_id")?,
					"payment_id": line(&mail.payment_id, 64, "payment_id")?,
					"initiator_email": address(&mail.initiator_email, "initiator_email")?,
					"tier": payment_tier(&mail.tier)?,
					"source": line(&mail.source, 160, "source")?,
					"destination": line(&mail.destination, 160, "destination")?,
					"amount": line(&mail.amount, 64, "amount")?,
					"reason": required_line(&mail.reason, 500, "reason")?,
					"payload_hash": line(&mail.payload_hash, 128, "payload_hash")?,
					"threshold": mail.threshold,
					"owner_count": mail.owner_count,
					"expires_at": mail.expires_at,
					"approval_url": self.approval_link(&mail.approval_url)?,
					"code": line(&mail.code, 64, "code")?,
				});
				("payment_approval", payload, Recipient::FundOwner, None)
			}
			// The one kind that is not addressed to the consilium. Every field is bounded in
			// bytes and refused if it carries a control character — see `line`.
			Ok(GovernanceMailKind::PaymentConsent) => {
				let mail = req.payment_consent.ok_or_else(|| Status::invalid_argument("payment_consent is required for this kind"))?;
				let tier = payment_tier(&mail.tier)?;
				// Read here and enforced against the RESOLVED record below, so the rule stays
				// "the recipient IS the subject" rather than "two request fields agree".
				let subject = parse_user_id(&mail.subject_user_id, "subject_user_id")?;
				// The inbox entry keeps its key under the CHECK on `notifications.dedupe_key`
				// only if the money plane's key leaves room for the prefix.
				if req.dedupe_key.chars().count() + INBOX_KEY_PREFIX.len() > 128 {
					return Err(Status::invalid_argument(format!(
						"dedupe_key must be at most {} characters for this kind",
						128 - INBOX_KEY_PREFIX.len()
					)));
				}
				let initiator_email = address(&mail.initiator_email, "initiator_email")?;
				// `amount` is the one payload field the inbox repeats, and the inbox cannot
				// mark it as somebody else's text — so it must not be able to carry a link.
				let amount = no_link(&line(&mail.amount, 64, "amount")?, "amount")?;
				let notice = InboxNotice {
					title: "A payment needs your consent".to_owned(),
					body: format!(
						"{initiator_email} has opened a payment of {amount}. What it is and where it goes, and the link to consent or refuse, are in the message sent to your email address."
					),
				};
				let payload = serde_json::json!({
					"payment_id": line(&mail.payment_id, 64, "payment_id")?,
					"initiator_email": initiator_email,
					"tier": tier,
					"source": line(&mail.source, 160, "source")?,
					"destination": line(&mail.destination, 160, "destination")?,
					"amount": amount,
					// An operator writes this and the subject reads it verbatim. REQUIRED: a
					// consent request nobody explained is one nobody can judge, and "approve
					// this because we say so" is the shape of the mail we do not want to send.
					"reason": required_line(&mail.reason, 500, "reason")?,
					"payload_hash": line(&mail.payload_hash, 128, "payload_hash")?,
					"expires_at": mail.expires_at,
					"approval_url": self.approval_link(&mail.approval_url)?,
					"code": line(&mail.code, 64, "code")?,
				});
				("payment_consent", payload, Recipient::Subject(subject), Some(notice))
			}
			// The consilium asked about a fund's FEE TERMS. Addressed like a payment
			// approval — a seat, a verified address — and it carries the same link and
			// code, so the same field rules and the same clearing of `code` once sent.
			Ok(GovernanceMailKind::FeePolicyApproval) => {
				let mail = req.fee_policy_approval.ok_or_else(|| Status::invalid_argument("fee_policy_approval is required for this kind"))?;
				let proposed = mail.proposed.as_ref().ok_or_else(|| Status::invalid_argument("proposed terms are required"))?;
				let payload = serde_json::json!({
					"consilium_id": line(&mail.consilium_id, 64, "consilium_id")?,
					"initiator_email": address(&mail.initiator_email, "initiator_email")?,
					// Same rule as the notice's `fund`, so the money plane learns ONE rule
					// for the field across every fee mail, not one per kind.
					"fund": no_url(&required_line(&mail.fund, 160, "fund")?, "fund")?,
					"current": current_fee_terms(mail.current.as_ref())?,
					"proposed": fee_terms(proposed, "proposed")?,
					"reason": required_line(&mail.reason, 500, "reason")?,
					"payload_hash": line(&mail.payload_hash, 128, "payload_hash")?,
					"threshold": mail.threshold,
					"owner_count": mail.owner_count,
					"expires_at": mail.expires_at,
					"approval_url": self.approval_link(&mail.approval_url)?,
					"code": line(&mail.code, 64, "code")?,
				});
				("fee_policy_approval", payload, Recipient::FundOwner, None)
			}
			// One investor told their fund's terms are changing. Addressed by identity like
			// a consent, traced in the inbox like a consent, and carrying no code at all.
			Ok(GovernanceMailKind::FeePolicyNotice) => {
				let mail = req.fee_policy_notice.ok_or_else(|| Status::invalid_argument("fee_policy_notice is required for this kind"))?;
				let proposed = mail.proposed.as_ref().ok_or_else(|| Status::invalid_argument("proposed terms are required"))?;
				let subject = parse_user_id(&mail.subject_user_id, "subject_user_id")?;
				if req.dedupe_key.chars().count() + INBOX_KEY_PREFIX.len() > 128 {
					return Err(Status::invalid_argument(format!(
						"dedupe_key must be at most {} characters for this kind",
						128 - INBOX_KEY_PREFIX.len()
					)));
				}
				// The fund's name is the one money-plane string the inbox repeats — a notice
				// that does not say WHICH fund says nothing — so, like the consent's amount,
				// it must not be able to carry a link.
				let fund = no_url(&required_line(&mail.fund, 160, "fund")?, "fund")?;
				// Numbers this plane formats, in the words the mail will use, so the trace
				// and the mail cannot disagree about the change.
				let notice = InboxNotice {
					title: format!("The fee terms of {fund} are changing"),
					body: format!(
						"New fee terms for {fund} take effect on {}: management fee {}, performance fee {}. The full terms, now and next, are in the message sent to your email address.",
						fmt_ts(mail.effective_at),
						pct_change(mail.current.as_ref().map(|c| c.management_bps), proposed.management_bps),
						pct_change(mail.current.as_ref().map(|c| c.performance_bps), proposed.performance_bps),
					),
				};
				let payload = serde_json::json!({
					"fund": fund,
					"current": current_fee_terms(mail.current.as_ref())?,
					"proposed": fee_terms(proposed, "proposed")?,
					"effective_at": mail.effective_at,
					"link": cabinet_path(&mail.link)?,
				});
				("fee_policy_notice", payload, Recipient::Subject(subject), Some(notice))
			}
			_ => return Err(Status::invalid_argument("kind must be a known governance mail kind")),
		};

		// The address comes from the IDENTITY RECORD, never from the request. This is
		// what stops a compromised money plane redirecting a governance mail.
		let recipient = self
			.users
			.find_by_id(user_id)
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found("recipient is not a user of this plane"))?;

		// The refusals name the kind in words, so an operator reading the money plane's
		// log sees which mail was refused and why.
		let noun = kind.replace('_', " ");
		match recipient_rule {
			// A consilium mail goes to a FUND OWNER and nobody else. Those kinds are
			// addressed to the consilium — an approval to cast, or the outcome of one — so
			// any other recipient means the money plane asked for a security mail to be
			// sent to someone with no standing in it. The PERSISTED role, never the elevated one:
			// emergency access authorizes an operator, it does not seat them, and it must
			// not turn them into a governance correspondent either.
			Recipient::FundOwner => {
				if recipient.role() != Role::Owner {
					return Err(Status::failed_precondition("a governance mail may only be addressed to a fund owner"));
				}
				if !recipient.email_verified() {
					return Err(Status::failed_precondition("a consilium mail may only be sent to a verified address"));
				}
			}
			Recipient::Subject(subject) => {
				// Consent is personal: it is only worth anything from the person whose money
				// moves, and that person is ordinarily an investor holding no seat. So the
				// owner rule cannot be reused, and dropping it for everyone would hand a
				// compromised money plane a branded security mail aimed at any address on the
				// platform. Identity is the narrower rule that replaces it: this mail may
				// reach exactly the one person the payload names, and nobody else.
				if recipient.id() != subject {
					return Err(Status::failed_precondition(format!("a {noun} may only be addressed to the person it names as its subject")));
				}
				// An unverified address is one nobody has proved belongs to this person. For a
				// notification that is a nuisance; for a mail carrying a consent link AND the
				// code that arms it, it hands the decision to whoever happens to hold the
				// mailbox — which is the entire thing consent is supposed to rule out.
				if !recipient.email_verified() {
					return Err(Status::failed_precondition(format!("a {noun} may only be sent to a verified address")));
				}
			}
		}

		let enqueued = self
			.governance
			.enqueue_mail(user_id.raw(), recipient.email().as_str(), recipient.email_verified(), kind, &req.dedupe_key, &payload)
			.await
			.map_err(domain_to_status)?;
		if enqueued {
			self.limiter.record(&budget_key);
		}

		// The inbox trace, written AFTER the mail is queued and never in its way: the
		// queue row is the security channel and the thing the money plane retries on; the
		// inbox entry is a courtesy copy, so a failure here is logged, not returned. Written
		// on a repeat too (`enqueued == false`): the same dedupe key makes it a no-op when
		// the entry exists, and the money plane's retry is exactly when a trace that failed
		// the first time gets its second chance.
		if let Some(notice) = notice
			&& let Err(err) = self
				.notifications
				.record(
					user_id.raw(),
					recipient.email().as_str(),
					recipient.email_verified(),
					SUBJECT_INBOX_TOPIC,
					kind,
					&notice.title,
					&notice.body,
					&format!("{INBOX_KEY_PREFIX}{}", req.dedupe_key),
					now_secs(),
				)
				.await
		{
			tracing::warn!(%err, dedupe_key = %req.dedupe_key, kind, "mail relay: could not record the trace in the subject's inbox");
		}
		Ok(Response::new(SendGovernanceMailResponse { enqueued }))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_a_cast_vote_crosses_the_wire() {
		assert_eq!(vote_from_proto(RemovalVote::Remove as i32).unwrap(), Vote::Remove);
		assert_eq!(vote_from_proto(RemovalVote::Keep as i32).unwrap(), Vote::Keep);
		// PENDING is a state, not an answer: accepting it would let a client "unvote".
		assert!(vote_from_proto(RemovalVote::Pending as i32).is_err());
		assert!(vote_from_proto(RemovalVote::Unspecified as i32).is_err());
		assert!(vote_from_proto(99).is_err());
	}

	#[test]
	fn every_domain_state_has_a_concrete_wire_state() {
		for state in [
			RemovalState::Open,
			RemovalState::Executed,
			RemovalState::Rejected,
			RemovalState::Expired,
			RemovalState::Cancelled,
			RemovalState::Void,
		] {
			assert_ne!(state_to_proto(state), OwnerRemovalState::Unspecified, "unmapped state: {}", state.as_str());
		}
		for vote in [Vote::Pending, Vote::Remove, Vote::Keep] {
			assert_ne!(vote_to_proto(vote), RemovalVote::Unspecified, "unmapped vote: {}", vote.as_str());
		}
	}

	/// A link in a concierge-branded security mail must point at us. The typed payload
	/// stops arbitrary markup; only this stops an arbitrary destination.
	///
	/// `approval_link` reads only `approval_origin`, so the check is exercised through a
	/// bare origin rather than by standing up two Postgres-backed ports.
	#[test]
	fn an_emailed_link_must_sit_under_our_own_origin() {
		let origin = "https://evinvest.ltd".to_owned();
		let link = |raw: &str| MailRelay::check_origin(&origin, raw);
		assert!(link("https://evinvest.ltd/cabinet/payout-approval/abc").is_ok());
		assert!(link("https://evinvest.ltd").is_ok());

		// The classic prefix bug: a bare `starts_with` accepts every one of these.
		for hostile in [
			"https://evinvest.ltd.attacker.example/cabinet/payout-approval/abc",
			"https://evinvest.ltd@attacker.example/",
			"https://evinvest.ltd//attacker.example/",
			"http://evinvest.ltd/cabinet/payout-approval/abc",
			"https://attacker.example/cabinet/payout-approval/abc",
			"javascript:alert(1)",
			// The origin is only a prefix. Anything that breaks the line after it puts a
			// second link — somebody else's — on the same bare line of the text part.
			"https://evinvest.ltd/cabinet/payout-approval/abc https://attacker.example/",
			"https://evinvest.ltd/cabinet/payout-approval/abc\nhttps://attacker.example/",
			"https://evinvest.ltd/cabinet/payout-approval/abc\r\n",
			"https://evinvest.ltd/cabinet/payout-approval/abc\t",
			"https://evinvest.ltd/cabinet/payout-approval/\u{a0}abc",
			"https://evinvest.ltd/cabinet/payout-approval/abc\u{7}",
			"https://evinvest.ltd/cabinet/payout-approval/ábc",
		] {
			assert!(link(hostile).is_err(), "must be refused: {hostile:?}");
		}
	}

	/// The inbox filters by topic and the catalogue is closed, so the topic a consent or a
	/// notice is filed under has to be one the catalogue actually lists.
	#[test]
	fn the_subject_inbox_topic_is_in_the_catalogue() {
		assert!(crate::notification::topic(SUBJECT_INBOX_TOPIC).is_some(), "{SUBJECT_INBOX_TOPIC} is not a catalogued topic");
	}

	/// The one emailed link the money plane spells no host for. Hung off the cabinet's
	/// origin by the dispatcher, so what is refused is anything that would not stay
	/// under it once it is.
	#[test]
	fn a_notice_link_is_a_cabinet_path_or_nothing() {
		assert_eq!(cabinet_path("").unwrap(), "");
		assert_eq!(cabinet_path("/funds/quy-nhon/fees?tab=terms").unwrap(), "/funds/quy-nhon/fees?tab=terms");
		assert_eq!(cabinet_path("/").unwrap(), "/");
		for hostile in [
			"https://attacker.example/",
			"//attacker.example/",
			"/\\attacker.example/",
			"funds/fees",
			"/funds/fees https://attacker.example/",
			"/funds/fees\nhttps://attacker.example/",
			"/funds/f\u{e9}es",
			"/funds/fees\u{7}",
		] {
			assert!(cabinet_path(hostile).is_err(), "must be refused: {hostile:?}");
		}
		assert!(cabinet_path(&format!("/{}", "a".repeat(512))).is_err(), "over the byte limit");
	}

	/// The two inbox-repeated fields are different kinds of text, so they get different
	/// grades of the same check: an amount has no business containing the word `http`,
	/// a fund slug legally does — and only a scheme or a `www.` host ever becomes a link.
	#[test]
	fn a_fund_slug_may_say_http_but_an_amount_may_not() {
		for slug in ["httpfund", "lighthttp-arb", "Quy Nhon Fund", "HTTP Arbitrage"] {
			assert_eq!(no_url(slug, "fund").unwrap(), slug, "a legal fund name: {slug:?}");
		}
		for hostile in ["http://x", "Quy Nhon — see https://evil.example", "www.x", "WWW.X", "fund (www.evil.example)"] {
			assert!(no_url(hostile, "fund").is_err(), "a fund must not link: {hostile:?}");
			assert!(no_link(hostile, "amount").is_err(), "and neither may an amount: {hostile:?}");
		}
		// The amount keeps the coarse grade: the bare word, with no scheme at all.
		for hostile in ["1 USDT http evil.example", "http", "1 USDT HTTPS://x"] {
			assert!(no_link(hostile, "amount").is_err(), "an amount must not say http: {hostile:?}");
		}
		assert_eq!(no_link("1 000.50 USDT", "amount").unwrap(), "1 000.50 USDT");
	}

	/// The terms are rendered at somebody approving or paying a price, so every field is
	/// either a bounded number or a word from a closed set.
	#[test]
	fn fee_terms_are_bounded_numbers_and_closed_words() {
		let house = FeeTermsMsg {
			management_bps: 200,
			performance_bps: 2_000,
			hurdle_bps: 0,
			basis: "invested_capital".into(),
			crystallization: "annual".into(),
		};
		let with = |edit: &dyn Fn(&mut FeeTermsMsg)| {
			let mut terms = house.clone();
			edit(&mut terms);
			terms
		};
		let json = fee_terms(&house, "proposed").unwrap();
		assert_eq!(json["management_bps"], 200);
		assert_eq!(json["crystallization"], "annual");
		assert!(fee_terms(&with(&|t| t.management_bps = MAX_BPS), "proposed").is_ok(), "100% is the ceiling, inclusive");
		for (bad, why) in [
			(with(&|t| t.management_bps = MAX_BPS + 1), "a management fee over 100%"),
			(with(&|t| t.performance_bps = u32::MAX), "a performance fee over 100%"),
			(with(&|t| t.hurdle_bps = MAX_BPS + 1), "a hurdle over 100%"),
			(with(&|t| t.basis = "aum".into()), "an unknown basis"),
			(with(&|t| t.basis = String::new()), "no basis"),
			(with(&|t| t.crystallization = "weekly".into()), "an unknown crystallization"),
			(with(&|t| t.crystallization = "Annual".into()), "the money plane's own casing is lower"),
		] {
			assert!(fee_terms(&bad, "proposed").is_err(), "{why}");
		}
		assert!(current_fee_terms(None).unwrap().is_null(), "no current terms is a fund that charged nothing");
	}

	#[test]
	fn bounded_rejects_only_what_exceeds_the_width() {
		assert_eq!(bounded("0x1234", 128, "address").unwrap(), "0x1234");
		assert!(bounded(&"a".repeat(128), 128, "address").is_ok());
		assert!(bounded(&"a".repeat(129), 128, "address").is_err());
	}
}
