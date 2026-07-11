//! The web-session locker's persistence invariant: with `REDIS_URL` set, a
//! session opened by one `WebSessions` instance is served by a NEW instance —
//! a concierge restart no longer signs everyone out.

use concierge::web::WebSessions;
use evconcierge_auth::AuthService;
use evconcierge_contracts::concierge::v1::{TokenResponse, UserSummary};

fn tokens(user_id: &str) -> TokenResponse {
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
	TokenResponse {
		access_token: "access".into(),
		access_expires_at: now + 900,
		refresh_token: "family.secret".into(),
		refresh_expires_at: now + 3600,
		user: Some(UserSummary {
			user_id: user_id.into(),
			email: "user@test".into(),
			status: "active".into(),
			token_version: 1,
			role: "investor".into(),
		}),
	}
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
