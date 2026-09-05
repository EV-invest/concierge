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
//! to redirect a governance mail or put arbitrary HTML in an owner's inbox.
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
	governance::{AdmissionId, AdmissionVote as DomainAdmissionVote, PAYOUT_MIN_OWNERS, ProposalState, RemovalId, RemovalState, Vote},
	users::{Email, User, UserId},
};
use evconcierge_contracts::concierge::v1::{
	AdmissionPeer as AdmissionPeerMsg, AdmissionVote, CancelOwnerAdmissionRequest, CancelOwnerRemovalRequest, GetOwnerAdmissionRequest, GetOwnerRemovalRequest, GetRemovalInvitationRequest,
	GovernanceMailKind, GovernanceTick, ListOwnerAdmissionsRequest, ListOwnerRemovalsRequest, ListOwnersRequest, OpenOwnerAdmissionRequest, OpenOwnerRemovalRequest, Owner,
	OwnerAdmission as OwnerAdmissionMsg, OwnerAdmissionList, OwnerAdmissionState, OwnerList, OwnerRemoval as OwnerRemovalMsg, OwnerRemovalInvitation, OwnerRemovalList, OwnerRemovalState,
	RemovalPeer, RemovalVote, ResignOwnershipRequest, SendGovernanceMailRequest, SendGovernanceMailResponse, SubmitAdmissionVoteRequest, SubmitPeerVoteRequest, SubmitSelfDecisionRequest,
	SubmitSelfDecisionResponse, WatchGovernanceRequest, governance_service_server::GovernanceService, mail_relay_service_server::MailRelayService,
	owner_removal_approval_service_server::OwnerRemovalApprovalService,
};
use tokio::sync::{broadcast, mpsc};
use tonic::{Request, Response, Status, codegen::tokio_stream::Stream};
use uuid::Uuid;

use crate::{
	authz::BreakGlass,
	infrastructure::governance::{AdmissionRecord, Audit, InvitationRecord, RemovalRecord, SelfDecision},
	notification::now_secs,
	ports::{GovernanceRepository, UserDirectoryRepository},
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
fn audit_of<T>(request: &Request<T>) -> Audit {
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
			// INVALID_ARGUMENT, deliberately not PERMISSION_DENIED: the BFF folds
			// PermissionDenied into an opaque 404, so an owner who mistyped one character
			// would be told their invitation does not exist — and would retry, burn their
			// own token, and set off a brute-force alert to every owner. This is not an
			// enumeration oracle: a wrong code is only reachable by someone already
			// holding a valid, live, unspent token.
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
	/// `None` ⇒ the relay is not configured and every call is rejected (fail closed).
	/// In production this is the SAME `BRIDGE_SERVICE_TOKEN` banking presents when it
	/// pulls the outbox: one trust relationship between the planes, one secret to rotate.
	token: Option<Arc<str>>,
	/// Origin every emailed link must sit under, without a trailing slash.
	approval_origin: String,
}

impl MailRelay {
	pub fn new(users: Arc<dyn UserDirectoryRepository>, governance: Arc<dyn GovernanceRepository>, token: Option<String>, approval_origin: String) -> Self {
		Self {
			users,
			governance,
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
		let url = bounded(raw, 512, "approval_url")?;
		Self::check_origin(&self.approval_origin, &url)?;
		Ok(url)
	}

	/// The origin rule alone, free of the ports, so it can be exercised directly.
	fn check_origin(origin: &str, url: &str) -> Result<(), Status> {
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

#[tonic::async_trait]
impl MailRelayService for MailRelay {
	async fn send_governance_mail(&self, request: Request<SendGovernanceMailRequest>) -> Result<Response<SendGovernanceMailResponse>, Status> {
		authenticate_service(self.token.as_ref(), &request, "mail relay")?;
		let req = request.into_inner();

		if req.dedupe_key.is_empty() || req.dedupe_key.chars().count() > 128 {
			return Err(Status::invalid_argument("dedupe_key must be 1-128 characters"));
		}
		let user_id = parse_user_id(&req.user_id, "user_id")?;

		let (kind, payload) = match GovernanceMailKind::try_from(req.kind) {
			Ok(GovernanceMailKind::PayoutApproval) => {
				let mail = req.payout_approval.ok_or_else(|| Status::invalid_argument("payout_approval is required for this kind"))?;
				let payload = serde_json::json!({
					"consilium_id": bounded(&mail.consilium_id, 64, "consilium_id")?,
					"initiator_email": bounded(&mail.initiator_email, 320, "initiator_email")?,
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
				("payout_approval", payload)
			}
			// A burned approval token is an outcome the owners are told about, and the
			// outcome payload already carries everything that mail needs to say.
			Ok(GovernanceMailKind::PayoutOutcome) | Ok(GovernanceMailKind::ApprovalTokenBurned) => {
				let mail = req.payout_outcome.ok_or_else(|| Status::invalid_argument("payout_outcome is required for this kind"))?;
				let payload = serde_json::json!({
					"consilium_id": bounded(&mail.consilium_id, 64, "consilium_id")?,
					"outcome": bounded(&mail.outcome, 64, "outcome")?,
					"network": bounded(&mail.network, 64, "network")?,
					"address": bounded(&mail.address, 128, "address")?,
					"amount": bounded(&mail.amount, 64, "amount")?,
					"detail": bounded(&mail.detail, 500, "detail")?,
				});
				("payout_outcome", payload)
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

		// A governance mail goes to a FUND OWNER and nobody else. Every kind this relay
		// renders is addressed to the consilium — an approval to cast, or the outcome of
		// one — so any other recipient means the money plane asked for a security mail to
		// be sent to someone with no standing in it. The PERSISTED role, never the elevated
		// one: emergency access authorizes an operator, it does not seat them, and it must
		// not turn them into a governance correspondent either.
		if recipient.role() != Role::Owner {
			return Err(Status::failed_precondition("a governance mail may only be addressed to a fund owner"));
		}

		let enqueued = self
			.governance
			.enqueue_mail(user_id.raw(), recipient.email().as_str(), kind, &req.dedupe_key, &payload)
			.await
			.map_err(domain_to_status)?;
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
		] {
			assert!(link(hostile).is_err(), "must be refused: {hostile}");
		}
	}

	#[test]
	fn bounded_rejects_only_what_exceeds_the_width() {
		assert_eq!(bounded("0x1234", 128, "address").unwrap(), "0x1234");
		assert!(bounded(&"a".repeat(128), 128, "address").is_ok());
		assert!(bounded(&"a".repeat(129), 128, "address").is_err());
	}
}
