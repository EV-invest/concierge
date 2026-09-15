//! The web-session locker's invariants:
//!
//! - persistence: with `REDIS_URL` set, a session opened by one `WebSessions`
//!   instance is served by a NEW instance — a concierge restart no longer signs
//!   everyone out;
//! - liveness of the principal: `fresh` answers with the directory's CURRENT
//!   summary (a role granted since login shows at once), and a directory outage
//!   falls back to the stored copy rather than ending the session.

use std::sync::Mutex;

use concierge::web::{PrincipalSource, WebSessions};
use evconcierge_auth::{AuthError, AuthService};
use evconcierge_contracts::concierge::v1::{
	ExchangeRequest, JwksRequest, JwksResponse, ListSessionsRequest, ListSessionsResponse, LogoutRequest, LogoutResponse, RefreshRequest, RevokeSessionRequest, RevokeSessionResponse,
	TokenResponse, UserSummary, auth_service_server::AuthService as AuthRpc,
};
use tonic::{Request, Response, Status};

fn summary(user_id: &str, role: &str) -> UserSummary {
	UserSummary {
		user_id: user_id.into(),
		email: "user@test".into(),
		status: "active".into(),
		token_version: 1,
		role: role.into(),
		role_is_break_glass: false,
	}
}

fn tokens(user_id: &str) -> TokenResponse {
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
	TokenResponse {
		access_token: "access".into(),
		access_expires_at: now + 900,
		refresh_token: "family.secret".into(),
		refresh_expires_at: now + 3600,
		user: Some(summary(user_id, "investor")),
	}
}

/// A directory stand-in for the live principal read: `Some` answers with that
/// summary, `None` fails as an outage. Issuance is never reached (the access token
/// is far from expiry), so every RPC is a panic — reaching one is a test bug.
struct Directory(Mutex<Option<UserSummary>>);

impl Directory {
	fn answering(user: UserSummary) -> Self {
		Self(Mutex::new(Some(user)))
	}

	fn down() -> Self {
		Self(Mutex::new(None))
	}

	fn set(&self, answer: Option<UserSummary>) {
		*self.0.lock().unwrap() = answer;
	}
}

impl PrincipalSource for Directory {
	async fn principal(&self, _user_id: &str) -> Result<UserSummary, AuthError> {
		self.0.lock().unwrap().clone().ok_or(AuthError::Unavailable)
	}
}

#[tonic::async_trait]
impl AuthRpc for Directory {
	async fn exchange(&self, _: Request<ExchangeRequest>) -> Result<Response<TokenResponse>, Status> {
		unreachable!("issuance is not part of a live principal read")
	}

	async fn refresh(&self, _: Request<RefreshRequest>) -> Result<Response<TokenResponse>, Status> {
		unreachable!("issuance is not part of a live principal read")
	}

	async fn logout(&self, _: Request<LogoutRequest>) -> Result<Response<LogoutResponse>, Status> {
		unreachable!("issuance is not part of a live principal read")
	}

	async fn list_sessions(&self, _: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
		unreachable!("issuance is not part of a live principal read")
	}

	async fn revoke_session(&self, _: Request<RevokeSessionRequest>) -> Result<Response<RevokeSessionResponse>, Status> {
		unreachable!("issuance is not part of a live principal read")
	}

	async fn jwks(&self, _: Request<JwksRequest>) -> Result<Response<JwksResponse>, Status> {
		unreachable!("issuance is not part of a live principal read")
	}
}

// A role granted from the console after login is what `/auth/session` reports on
// the very next call — and it is written back, so the stored copy is the new one
// even once the directory can no longer be asked.
#[tokio::test]
async fn fresh_reports_the_directory_role_not_the_login_copy() {
	let sessions = WebSessions::from_env().await.unwrap();
	let (id, ..) = sessions.put(tokens("web-sess-live-role-user")).await.unwrap().expect("token pair carries a user");

	let directory = Directory::answering(summary("web-sess-live-role-user", "operator"));
	let fresh = sessions.fresh(&id, &directory).await.unwrap().expect("session is live");
	assert_eq!(fresh.user.role, "operator");

	directory.set(None);
	let fresh = sessions.fresh(&id, &directory).await.unwrap().expect("an outage keeps the session");
	assert_eq!(fresh.user.role, "operator", "the live summary must have been persisted, not only returned");
}

// A directory outage is not a verdict on the session: the login-time copy answers
// and nothing is removed.
#[tokio::test]
async fn fresh_falls_back_to_the_stored_summary_when_the_directory_is_down() {
	let sessions = WebSessions::from_env().await.unwrap();
	let (id, csrf, _) = sessions.put(tokens("web-sess-outage-user")).await.unwrap().expect("token pair carries a user");

	let directory = Directory::down();
	let fresh = sessions.fresh(&id, &directory).await.unwrap().expect("an outage keeps the session");
	assert_eq!(fresh.user.role, "investor");
	assert_eq!(sessions.csrf(&id).await.unwrap(), Some(csrf));

	sessions.forget(&id).await.unwrap();
}

#[tokio::test]
async fn sessions_survive_a_restart() {
	if std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()).is_none() {
		eprintln!("skipped: REDIS_URL unset — the in-process arm is restart-lossy by design");
		return;
	}

	let before = WebSessions::from_env().await.unwrap();
	let (id, csrf, _max_age) = before.put(tokens("web-sess-restart-user")).await.unwrap().expect("token pair carries a user");
	drop(before);

	// A new instance = a restarted process. The auth service is never consulted
	// while the access token is far from expiry, so the inert one suffices.
	let after = WebSessions::from_env().await.unwrap();
	let auth = AuthService::unconfigured();
	let fresh = after.fresh(&id, &auth).await.unwrap().expect("session must survive the restart");
	assert_eq!(fresh.user.user_id, "web-sess-restart-user");
	assert_eq!(after.csrf(&id).await.unwrap(), Some(csrf));

	// forget hands back the refresh token for upstream revocation and ends the session.
	assert_eq!(after.forget(&id).await.unwrap().as_deref(), Some("family.secret"));
	assert!(after.fresh(&id, &auth).await.unwrap().is_none());
}
