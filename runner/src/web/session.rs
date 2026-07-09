//! The web session locker: opaque cookie id → the server-held concierge token
//! pair. The refresh token never reaches the browser; the access JWT does (as the
//! zone-shared `ev_access` cookie) but is re-minted here on demand. Ported from
//! the cabinet BFF's session store, trimmed to the identity plane; refresh goes
//! through the issuance service IN-PROCESS rather than over gRPC.
//!
//! ponytail: in-process map only — a restart signs everyone out (the refresh
//! families in the plane's own store survive; just this locker is lost). Port the
//! BFF's Redis arm onto it when multi-replica/durable sessions matter.

use std::{collections::HashMap, sync::Arc};

use evconcierge_contracts::concierge::v1::{RefreshRequest, TokenResponse, UserSummary, auth_service_server::AuthService as AuthRpc};
use tokio::sync::Mutex;
use tonic::{Code, Request};

use crate::web::{now_secs, random_token};

/// Refresh the access token when it has less than this long to live, so a token
/// handed to a zone stays valid for the request that follows.
const ACCESS_SKEW_SECS: i64 = 30;

pub struct WebSession {
	pub access_token: String,
	pub access_expires_at: i64,
	pub refresh_token: String,
	pub refresh_expires_at: i64,
	pub user: UserSummary,
	pub csrf: String,
}

/// A fresh view of a live session, for the session route and the access cookie.
pub struct Fresh {
	pub user: UserSummary,
	pub access_token: String,
	pub remaining_secs: i64,
}

/// id → session, each behind its own lock so concurrent refreshes of one session
/// single-flight (two racing rotations of the same refresh token read as theft
/// upstream and revoke the family).
pub struct WebSessions {
	inner: Mutex<HashMap<String, Arc<Mutex<WebSession>>>>,
}

impl WebSessions {
	pub fn new() -> Self {
		Self { inner: Mutex::new(HashMap::new()) }
	}

	/// Open a session for a freshly exchanged token pair. Returns
	/// `(session_id, csrf, max_age_secs)`; `None` when the response carries no user
	/// (an issuance bug — fail the login rather than store a half-session).
	pub async fn put(&self, tokens: TokenResponse) -> Option<(String, String, i64)> {
		let user = tokens.user?;
		let id = random_token(32);
		let csrf = random_token(32);
		let now = now_secs();
		let max_age = (tokens.refresh_expires_at - now).max(0);
		let session = WebSession {
			access_token: tokens.access_token,
			access_expires_at: tokens.access_expires_at,
			refresh_token: tokens.refresh_token,
			refresh_expires_at: tokens.refresh_expires_at,
			user,
			csrf: csrf.clone(),
		};
		let mut map = self.inner.lock().await;
		map.retain(|_, s| s.try_lock().map(|s| s.refresh_expires_at > now).unwrap_or(true));
		map.insert(id.clone(), Arc::new(Mutex::new(session)));
		Some((id, csrf, max_age))
	}

	/// The session's current view, refreshing the access token through the issuance
	/// service when it is about to expire. `None` ⇒ the session is gone (expired,
	/// revoked upstream, or never existed) and its cookies should be cleared.
	pub async fn fresh(&self, id: &str, auth: &impl AuthRpc) -> Option<Fresh> {
		let slot = self.inner.lock().await.get(id).cloned()?;
		let mut s = slot.lock().await;
		let now = now_secs();

		if s.access_expires_at <= now + ACCESS_SKEW_SECS {
			if s.refresh_expires_at <= now {
				drop(s);
				self.inner.lock().await.remove(id);
				return None;
			}
			match auth
				.refresh(Request::new(RefreshRequest {
					refresh_token: s.refresh_token.clone(),
				}))
				.await
			{
				Ok(response) => {
					let t = response.into_inner();
					s.access_token = t.access_token;
					s.access_expires_at = t.access_expires_at;
					s.refresh_token = t.refresh_token;
					s.refresh_expires_at = t.refresh_expires_at;
					if let Some(user) = t.user {
						s.user = user;
					}
				}
				// An auth verdict kills the session; a transport blip keeps it (the
				// possibly-stale access token is still the best available answer).
				Err(status) if matches!(status.code(), Code::Unauthenticated | Code::PermissionDenied) => {
					drop(s);
					self.inner.lock().await.remove(id);
					return None;
				}
				Err(_) => {}
			}
		}

		Some(Fresh {
			user: s.user.clone(),
			access_token: s.access_token.clone(),
			remaining_secs: (s.refresh_expires_at - now).max(0),
		})
	}

	/// The session's CSRF token (double-submit check).
	pub async fn csrf(&self, id: &str) -> Option<String> {
		let slot = self.inner.lock().await.get(id).cloned()?;
		let csrf = slot.lock().await.csrf.clone();
		Some(csrf)
	}

	/// The session's refresh token (proves identity on ListSessions/RevokeSession).
	pub async fn refresh_token(&self, id: &str) -> Option<String> {
		let slot = self.inner.lock().await.get(id).cloned()?;
		let token = slot.lock().await.refresh_token.clone();
		Some(token)
	}

	/// Drop the session, returning its refresh token for upstream revocation.
	pub async fn forget(&self, id: &str) -> Option<String> {
		let slot = self.inner.lock().await.remove(id)?;
		let token = slot.lock().await.refresh_token.clone();
		Some(token)
	}
}
