//! The web session locker: opaque cookie id → the server-held concierge token
//! pair. The refresh token never reaches the browser; the access JWT does (as the
//! zone-shared `ev_access` cookie) but is re-minted here on demand. Ported from
//! the cabinet BFF's session store, trimmed to the identity plane; refresh goes
//! through the issuance service IN-PROCESS rather than over gRPC.
//!
//! Storage mirrors the issuance side's `RefreshStore`: `REDIS_URL` set ⇒ one hash
//! per session in the central Redis, reaped by `EXPIREAT`, surviving restarts and
//! shared across replicas; unset ⇒ an in-process map (local/CI unaffected).

use std::{collections::HashMap, sync::Arc};

use color_eyre::eyre::{Context, bail};
use evconcierge_contracts::concierge::v1::{RefreshRequest, TokenResponse, UserSummary, auth_service_server::AuthService as AuthRpc};
use prost::Message;
use tokio::sync::Mutex;
use tonic::{Code, Request};

use crate::web::{now_secs, random_token};

/// Refresh the access token when it has less than this long to live, so a token
/// handed to a zone stays valid for the request that follows.
const ACCESS_SKEW_SECS: i64 = 30;

const FIELDS: [&str; 6] = ["access_token", "access_expires_at", "refresh_token", "refresh_expires_at", "csrf", "user"];
#[derive(Clone)]
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

pub struct WebSessions {
	store: Store,
	/// Per-session single-flight for the refresh path: two racing rotations of one
	/// refresh token read as theft upstream and revoke the family.
	/// ponytail: in-process locks — correct for one replica; going multi-replica
	/// needs a distributed lock (SET NX) or upstream rotation grace.
	locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl WebSessions {
	/// Back the store with Redis when `REDIS_URL` is set; otherwise keep the
	/// in-process map (matches `RefreshStore::from_env` one module over).
	pub async fn from_env() -> color_eyre::Result<Self> {
		let store = match std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()) {
			Some(url) => {
				let client = redis::Client::open(url.as_str()).context("invalid REDIS_URL")?;
				Store::Redis(client.get_connection_manager().await.context("web session store: redis connect")?)
			}
			None => Store::InProcess(Mutex::new(HashMap::new())),
		};
		Ok(Self {
			store,
			locks: Mutex::new(HashMap::new()),
		})
	}

	/// Open a session for a freshly exchanged token pair. Returns
	/// `(session_id, csrf, max_age_secs)`; `None` when the response carries no user
	/// (an issuance bug — fail the login rather than store a half-session).
	pub async fn put(&self, tokens: TokenResponse) -> color_eyre::Result<Option<(String, String, i64)>> {
		let Some(user) = tokens.user else { return Ok(None) };
		let id = random_token(32);
		let csrf = random_token(32);
		let max_age = (tokens.refresh_expires_at - now_secs()).max(0);
		let session = WebSession {
			access_token: tokens.access_token,
			access_expires_at: tokens.access_expires_at,
			refresh_token: tokens.refresh_token,
			refresh_expires_at: tokens.refresh_expires_at,
			user,
			csrf: csrf.clone(),
		};
		self.store.save(&id, &session).await?;
		Ok(Some((id, csrf, max_age)))
	}

	/// The session's current view, refreshing the access token through the issuance
	/// service when it is about to expire. `Ok(None)` ⇒ the session is gone (expired,
	/// revoked upstream, or never existed) and its cookies should be cleared; `Err` ⇒
	/// the store itself failed and the session's fate is UNKNOWN — don't touch cookies.
	pub async fn fresh(&self, id: &str, auth: &impl AuthRpc) -> color_eyre::Result<Option<Fresh>> {
		let lock = self.lock_for(id).await;
		let _flight = lock.lock().await;
		let Some(mut s) = self.store.load(id).await? else { return Ok(None) };
		let now = now_secs();

		if s.access_expires_at <= now + ACCESS_SKEW_SECS {
			if s.refresh_expires_at <= now {
				self.store.remove(id).await?;
				return Ok(None);
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
					self.store.save(id, &s).await?;
				}
				// An auth verdict kills the session; a transport blip keeps it (the
				// possibly-stale access token is still the best available answer).
				Err(status) if matches!(status.code(), Code::Unauthenticated | Code::PermissionDenied) => {
					self.store.remove(id).await?;
					return Ok(None);
				}
				Err(_) => {}
			}
		}

		Ok(Some(Fresh {
			user: s.user,
			access_token: s.access_token,
			remaining_secs: (s.refresh_expires_at - now).max(0),
		}))
	}

	/// The session's CSRF token (double-submit check).
	pub async fn csrf(&self, id: &str) -> color_eyre::Result<Option<String>> {
		Ok(self.store.load(id).await?.map(|s| s.csrf))
	}

	/// The session's refresh token (proves identity on ListSessions/RevokeSession).
	pub async fn refresh_token(&self, id: &str) -> color_eyre::Result<Option<String>> {
		Ok(self.store.load(id).await?.map(|s| s.refresh_token))
	}

	/// Drop the session, returning its refresh token for upstream revocation.
	pub async fn forget(&self, id: &str) -> color_eyre::Result<Option<String>> {
		self.store.remove(id).await
	}

	async fn lock_for(&self, id: &str) -> Arc<Mutex<()>> {
		let mut locks = self.locks.lock().await;
		locks.retain(|_, l| Arc::strong_count(l) > 1);
		locks.entry(id.to_string()).or_default().clone()
	}
}

enum Store {
	InProcess(Mutex<HashMap<String, WebSession>>),
	Redis(redis::aio::ConnectionManager),
}

impl Store {
	fn key(id: &str) -> String {
		format!("websess:{id}")
	}

	async fn load(&self, id: &str) -> color_eyre::Result<Option<WebSession>> {
		match self {
			Self::InProcess(map) => Ok(map.lock().await.get(id).cloned()),
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				let (access_token, access_expires_at, refresh_token, refresh_expires_at, csrf, user): (
					Option<String>,
					Option<i64>,
					Option<String>,
					Option<i64>,
					Option<String>,
					Option<Vec<u8>>,
				) = redis::cmd("HMGET").arg(Self::key(id)).arg(&FIELDS).query_async(&mut conn).await.context("web session load")?;
				let fields = (access_token, access_expires_at, refresh_token, refresh_expires_at, csrf, user);
				match fields {
					(None, None, None, None, None, None) => Ok(None),
					(Some(access_token), Some(access_expires_at), Some(refresh_token), Some(refresh_expires_at), Some(csrf), Some(user)) => Ok(Some(WebSession {
						access_token,
						access_expires_at,
						refresh_token,
						refresh_expires_at,
						user: UserSummary::decode(user.as_slice()).context("web session user decode")?,
						csrf,
					})),
					_ => bail!("web session {id}: partial hash — store corrupted"),
				}
			}
		}
	}

	async fn save(&self, id: &str, s: &WebSession) -> color_eyre::Result<()> {
		match self {
			Self::InProcess(map) => {
				let now = now_secs();
				let mut map = map.lock().await;
				map.retain(|_, s| s.refresh_expires_at > now);
				map.insert(id.to_string(), s.clone());
			}
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				redis::pipe()
					.atomic()
					.cmd("HSET")
					.arg(Self::key(id))
					.arg(FIELDS[0])
					.arg(&s.access_token)
					.arg(FIELDS[1])
					.arg(s.access_expires_at)
					.arg(FIELDS[2])
					.arg(&s.refresh_token)
					.arg(FIELDS[3])
					.arg(s.refresh_expires_at)
					.arg(FIELDS[4])
					.arg(&s.csrf)
					.arg(FIELDS[5])
					.arg(s.user.encode_to_vec())
					// Reap the session with its refresh window: past it, `fresh` would
					// remove it anyway (mirrors the in-process retain above).
					.expire_at(Self::key(id), s.refresh_expires_at)
					.exec_async(&mut conn)
					.await
					.context("web session save")?;
			}
		}
		Ok(())
	}

	async fn remove(&self, id: &str) -> color_eyre::Result<Option<String>> {
		match self {
			Self::InProcess(map) => Ok(map.lock().await.remove(id).map(|s| s.refresh_token)),
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				let (refresh_token, _deleted): (Option<String>, i64) = redis::pipe()
					.atomic()
					.hget(Self::key(id), "refresh_token")
					.del(Self::key(id))
					.query_async(&mut conn)
					.await
					.context("web session remove")?;
				Ok(refresh_token)
			}
		}
	}
}
