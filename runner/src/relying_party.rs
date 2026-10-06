//! The relying-party flow: this plane as the identity provider of first-party clients on
//! other origins (the Service-Arb panel on `sa.evinvest.ltd`).
//!
//! ```text
//! browser → evinvest.ltd/api/auth/authorize?client_id&redirect_uri&state&code_challenge  (web::authorize)
//!         → [no session] /api/auth/login?returnTo=<that authorize URL> → Google → back
//!         → account active → 302 redirect_uri?code&state
//! client backend → AuthService.ExchangeCode(client_id, secret, code, redirect_uri, verifier)
//!                → access JWT (aud = client audience, ≤15 min) + refresh token
//! client backend → UserDirectory.GetMe with that JWT — the ONE RPC it opens
//! ```
//!
//! Every client signs in any ACTIVE account; what the user may do there is their tenant
//! permissions, which GetMe hands the client fresh on every call — its own copy is never
//! trusted. The account is re-read at authorize, again at the exchange (a code does not
//! outlive a suspension, even inside its 60s), and again on every refresh.
//!
//! What is logged, and why it is `tracing` and not `admin_action`: that table answers
//! "what was done TO this person, by whom", and a person signing themselves into a panel
//! is neither. The codes and families are already a durable record of every sign-in
//! (`rp_codes`, `rp_sessions`, with IP and user agent); the log lines add the refusals,
//! and a replay — the one event here that means somebody else holds a user's credential —
//! goes out at `error!`, which is Sentry.

use std::{collections::HashMap, sync::Arc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use color_eyre::eyre::{Result, bail, ensure};
use domain::{
	error::DomainError,
	iam::Catalog,
	users::{UserId, UserStatus},
};
use evconcierge_auth::{
	AuthError, Authenticate, BoxFuture, CatalogPublication, Claims, ClientGrant, ClientGrantError, ClientGrants, ClientRefresh, CodeRedemption, UpstreamRevocation, Verifier,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::ports::{ClientRecord, CodeClaim, CodeOutcome, GrantRepository, NewCode, NewSession, PublishOutcome, RelyingPartyRepository, SessionRevocation, UserDirectoryRepository};

/// A code is carried by a browser redirect and redeemed by the client's backend at once;
/// a minute is generous for that and short for anyone who copies one out of a log.
pub const CODE_TTL_SECS: i64 = 60;
/// A client's refresh window, slid on every rotation.
pub const REFRESH_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// The immutable ceiling on a client session, however often it is refreshed: past it the
/// user signs in again. Shorter than the cabinet's own, because a panel is somebody's
/// working tool on a second origin, not their account.
pub const SESSION_MAX_SECS: i64 = 30 * 24 * 60 * 60;
/// The shortest client secret the boot will store. Anything shorter was typed, not
/// generated, and is guessable against an endpoint that answers per attempt.
pub const MIN_CLIENT_SECRET_LEN: usize = 32;
/// How far ahead of this plane's clock a catalog version may lie. A version nothing can
/// supersede would leave the tenant unable even to narrow a compromised alias.
const MAX_CATALOG_VERSION_LEAD_SECS: u64 = 24 * 60 * 60;

/// The env var that carries a client's secret.
pub fn secret_var(client_id: &str) -> String {
	format!("RP_CLIENT_SECRET_{}", client_id.to_ascii_uppercase())
}

/// Development-only extra redirect URIs, `client_id=uri` pairs separated by commas —
/// `RP_DEV_REDIRECT_URIS`. Refused in production and refused for anything but a
/// loopback `http://` origin, so it can only ever point a code at the developer's own
/// machine.
pub fn parse_dev_redirects(raw: &str, production: bool) -> Result<HashMap<String, Vec<String>>> {
	let mut extras: HashMap<String, Vec<String>> = HashMap::new();
	let pairs: Vec<&str> = raw.split(',').map(str::trim).filter(|p| !p.is_empty()).collect();
	if pairs.is_empty() {
		return Ok(extras);
	}
	ensure!(
		!production,
		"RP_DEV_REDIRECT_URIS must never be set in production: it registers redirect targets no migration reviewed"
	);
	for pair in pairs {
		let Some((client_id, uri)) = pair.split_once('=') else {
			bail!("RP_DEV_REDIRECT_URIS entry {pair:?} is not `client_id=uri`");
		};
		let authority = uri.strip_prefix("http://").and_then(|rest| rest.split(['/', '?']).next()).unwrap_or("");
		let loopback = ["localhost:", "127.0.0.1:"]
			.iter()
			.any(|host| authority.strip_prefix(host).is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())));
		ensure!(
			loopback && valid_redirect_shape(uri),
			"RP_DEV_REDIRECT_URIS entry {pair:?}: only http://localhost:<port>/… or http://127.0.0.1:<port>/… is accepted"
		);
		extras.entry(client_id.to_owned()).or_default().push(uri.to_owned());
	}
	Ok(extras)
}

/// A redirect URI this plane will ever send a code to: absolute, no fragment (a code in a
/// fragment is where the client cannot read it and scripts can), no whitespace, no
/// userinfo.
fn valid_redirect_shape(uri: &str) -> bool {
	let rest = uri.strip_prefix("https://").or_else(|| uri.strip_prefix("http://"));
	let Some(rest) = rest else { return false };
	let authority = rest.split(['/', '?']).next().unwrap_or("");
	!authority.is_empty() && !authority.contains('@') && !uri.contains('#') && !uri.chars().any(char::is_whitespace)
}

/// Refuse to serve a registry row that would redirect somewhere it should not.
pub fn check_registered_redirects(client: &ClientRecord) -> Result<()> {
	for uri in &client.redirect_uris {
		ensure!(
			uri.starts_with("https://") && valid_redirect_shape(uri),
			"relying party {:?} registers redirect URI {uri:?}: only an absolute https:// URI without a fragment or userinfo is served",
			client.client_id
		);
	}
	Ok(())
}

fn sha256(input: &[u8]) -> [u8; 32] {
	Sha256::digest(input).into()
}

/// The S256 challenge of a PKCE verifier (RFC 7636 §4.2).
pub fn s256_challenge(verifier: &str) -> String {
	URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()))
}

/// A syntactically valid S256 challenge: base64url of 32 bytes, no padding.
pub fn is_s256_challenge(challenge: &str) -> bool {
	challenge.len() == 43 && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A PKCE verifier of the RFC's shape: 43-128 unreserved characters.
fn is_pkce_verifier(verifier: &str) -> bool {
	(43..=128).contains(&verifier.len()) && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn random_secret() -> String {
	let mut buf = [0u8; 32];
	getrandom::fill(&mut buf).expect("CSPRNG unavailable");
	URL_SAFE_NO_PAD.encode(buf)
}

fn now_secs() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Whether a user may be signed into a client right now.
pub enum Admission {
	Admitted { token_version: u64 },
	Denied,
}

/// Where a browser at `/auth/authorize` came from, for the code row.
pub struct Requester<'a> {
	/// The `evinvest.ltd` refresh family the browser is signed in with.
	pub upstream_family: &'a str,
	pub client_ip: &'a str,
	pub user_agent: &'a str,
}

/// The relying-party application service: the registry lookups and admission for
/// `/auth/authorize`, and the [`ClientGrants`] port behind `ExchangeCode` /
/// `RefreshClientToken`.
pub struct RelyingParties {
	repo: Arc<dyn RelyingPartyRepository>,
	users: Arc<dyn UserDirectoryRepository>,
	grants: Arc<dyn GrantRepository>,
	/// `RP_DEV_REDIRECT_URIS`, already refused in production.
	dev_redirects: HashMap<String, Vec<String>>,
}

impl RelyingParties {
	pub fn new(repo: Arc<dyn RelyingPartyRepository>, users: Arc<dyn UserDirectoryRepository>, grants: Arc<dyn GrantRepository>, dev_redirects: HashMap<String, Vec<String>>) -> Self {
		Self { repo, users, grants, dev_redirects }
	}

	/// The boot's half of the registry: write every client's secret digest from
	/// `RP_CLIENT_SECRET_<ID>` when it is set, refuse a registered redirect that
	/// could send a code anywhere unexpected, and hand back the audiences the inbound
	/// verifier must admit on `GetMe`.
	pub async fn sync_registry(&self, secret_of: impl Fn(&str) -> Option<String>) -> Result<Vec<String>> {
		let now = now_secs();
		let mut audiences = Vec::new();
		for client in self.repo.clients().await? {
			check_registered_redirects(&client)?;
			let var = secret_var(&client.client_id);
			let secret = secret_of(&var).map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
			if let Some(secret) = &secret {
				ensure!(
					secret.len() >= MIN_CLIENT_SECRET_LEN,
					"{var} is shorter than {MIN_CLIENT_SECRET_LEN} characters — generate one with `openssl rand -base64 48`"
				);
			}
			// An unset variable writes NOTHING: replicas boot one by one, and one missing the
			// variable must not clear the digest the others serve with — that would sign the
			// client out everywhere on a config slip. Switching a client off is `disabled_at`.
			match secret {
				Some(secret) =>
					if self.repo.set_secret_hash(&client.client_id, Some(sha256(secret.as_bytes()).as_slice()), now).await? {
						tracing::info!(client_id = %client.client_id, "relying party secret set from {var}");
					},
				None if client.secret_hash.is_some() => tracing::warn!(client_id = %client.client_id, "{var} is unset on this replica: keeping the stored client secret"),
				None => tracing::warn!(client_id = %client.client_id, "relying party has no secret ({var} unset): it can obtain no token"),
			}
			if !client.disabled {
				audiences.push(client.audience);
			}
		}
		Ok(audiences)
	}

	/// The client, when `client_id` names an enabled one and `redirect_uri` is one of its
	/// URIs byte for byte. `None` is the ONLY answer for anything else, so the caller has
	/// no way to redirect to an address nobody registered.
	pub async fn resolve(&self, client_id: &str, redirect_uri: &str) -> Result<Option<ClientRecord>, DomainError> {
		let Some(client) = self.repo.client(client_id).await? else {
			return Ok(None);
		};
		let registered = client
			.redirect_uris
			.iter()
			.chain(self.dev_redirects.get(client_id).into_iter().flatten())
			.any(|uri| uri == redirect_uri);
		Ok((registered && !client.disabled).then_some(client))
	}

	/// Whether `user` may be signed into a client right now: an active account.
	pub async fn admit(&self, user: UserId) -> Result<Admission, DomainError> {
		Ok(match self.users.authz_record(user).await? {
			Some(record) if record.status != UserStatus::Disabled => Admission::Admitted {
				token_version: record.token_version,
			},
			_ => Admission::Denied,
		})
	}

	/// Mint and store a one-time code; the code itself is returned and never stored.
	pub async fn issue_code(&self, client: &ClientRecord, redirect_uri: &str, code_challenge: &str, user: UserId, token_version: u64, from: Requester<'_>) -> Result<String, DomainError> {
		let code = random_secret();
		let now = now_secs();
		self.repo
			.issue_code(NewCode {
				code_hash: &sha256(code.as_bytes()),
				client_id: &client.client_id,
				redirect_uri,
				code_challenge,
				user,
				token_version,
				upstream_family: from.upstream_family,
				issued_at: now,
				expires_at: now + CODE_TTL_SECS,
				client_ip: truncate(from.client_ip, 64),
				user_agent: truncate(from.user_agent, 256),
			})
			.await?;
		tracing::info!(client_id = %client.client_id, user_id = %user, "relying party: authorization code issued");
		Ok(code)
	}

	/// Whether an access token issued under family `session_id` for `audience` may still
	/// be honoured.
	pub async fn session_live(&self, session_id: Uuid, audience: &str) -> Result<bool, DomainError> {
		self.repo.session_live(session_id, audience, now_secs()).await
	}

	/// The client, when it exists, is enabled and `secret` is its secret.
	async fn authenticate_client(&self, client_id: &str, secret: &str) -> Result<ClientRecord, ClientGrantError> {
		let client = self.repo.client(client_id).await.map_err(unavailable)?.ok_or(ClientGrantError::InvalidClient)?;
		let Some(stored) = client.secret_hash.as_deref() else {
			return Err(ClientGrantError::InvalidClient);
		};
		// Both sides are 32-byte digests, so the length guard `ct_eq` needs is implicit.
		let presented = sha256(secret.as_bytes());
		if client.disabled || stored.len() != presented.len() || !bool::from(stored.ct_eq(&presented)) {
			// Debug, not Display: this is the caller's own string and may carry newlines.
			tracing::warn!(client_id = ?truncate(client_id, 32), "relying party: client authentication failed");
			return Err(ClientGrantError::InvalidClient);
		}
		Ok(client)
	}

	/// Store the catalog a client publishes for its tenant: every permission and alias in
	/// the tenant's namespace, never older than what is stored. A rollback that republished
	/// an older catalog would silently take away whatever the newer one granted.
	async fn publish(&self, publication: CatalogPublication) -> Result<(), ClientGrantError> {
		let client = self.authenticate_client(&publication.client_id, &publication.client_secret).await?;
		let now = now_secs();
		if publication.version > now.unsigned_abs() + MAX_CATALOG_VERSION_LEAD_SECS {
			return Err(ClientGrantError::InvalidCatalog(format!(
				"version {} is more than a day ahead of this plane's clock: it is the unix seconds of the build's commit",
				publication.version
			)));
		}
		let mut aliases = std::collections::BTreeMap::new();
		let mut delegations = std::collections::BTreeMap::new();
		for alias in publication.aliases {
			if !alias.delegates.is_empty() {
				delegations.insert(alias.name.clone(), alias.delegates.into_iter().collect());
			}
			if aliases.insert(alias.name.clone(), alias.members.into_iter().collect()).is_some() {
				return Err(ClientGrantError::InvalidCatalog(format!("alias `{}` is published twice", alias.name)));
			}
		}
		let catalog = Catalog {
			version: publication.version,
			permissions: publication.permissions.into_iter().collect(),
			aliases,
			delegations,
		};
		let namespace = client.namespace;
		catalog.check(&namespace).map_err(ClientGrantError::InvalidCatalog)?;
		match self.grants.publish(&namespace, &client.client_id, &catalog, now).await.map_err(|err| match err {
			DomainError::Validation(why) => ClientGrantError::InvalidCatalog(why),
			other => unavailable(other),
		})? {
			PublishOutcome::Published => tracing::info!(client_id = %client.client_id, %namespace, version = catalog.version, "relying party: catalog published"),
			PublishOutcome::Unchanged => {}
			PublishOutcome::Stale { stored } => {
				tracing::warn!(client_id = %client.client_id, %namespace, version = catalog.version, stored, "relying party: stale catalog refused");
				return Err(ClientGrantError::StaleCatalog(format!("version {} does not supersede the stored {stored}", catalog.version)));
			}
		}
		Ok(())
	}

	async fn redeem_code(&self, redemption: CodeRedemption) -> Result<ClientGrant, ClientGrantError> {
		let client = self.authenticate_client(&redemption.client_id, &redemption.client_secret).await?;
		if !is_pkce_verifier(&redemption.code_verifier) {
			return Err(ClientGrantError::InvalidGrant);
		}
		let code_hash = sha256(redemption.code.as_bytes());
		let now = now_secs();
		let outcome = self
			.repo
			.claim_code(CodeClaim {
				code_hash: &code_hash,
				client_id: &client.client_id,
				redirect_uri: &redemption.redirect_uri,
				challenge_of_verifier: &s256_challenge(&redemption.code_verifier),
				now,
			})
			.await
			.map_err(unavailable)?;
		let (user, token_version) = match outcome {
			CodeOutcome::Redeemed { user, token_version } => (user, token_version),
			CodeOutcome::Replayed { client_id, user, revoked_sessions } => {
				tracing::error!(%client_id, user_id = %user, revoked_sessions, "relying party: authorization code presented twice — the sessions it opened are revoked");
				return Err(ClientGrantError::InvalidGrant);
			}
			refused @ (CodeOutcome::Unknown | CodeOutcome::Expired | CodeOutcome::Mismatch) => {
				tracing::info!(client_id = %client.client_id, outcome = refused.label(), "relying party: code refused");
				return Err(ClientGrantError::InvalidGrant);
			}
		};

		match self.admit(user).await.map_err(unavailable)? {
			Admission::Admitted { token_version: current } if current == token_version => {}
			_ => {
				tracing::info!(client_id = %client.client_id, user_id = %user, "relying party: code redeemed but the user no longer passes");
				return Err(ClientGrantError::AccessDenied);
			}
		}

		let session_id = Uuid::new_v4();
		let secret = random_secret();
		let expires_at = now + REFRESH_TTL_SECS;
		let opened = self
			.repo
			.open_session(NewSession {
				id: session_id,
				client_id: &client.client_id,
				user,
				code_hash: &code_hash,
				secret_hash: &sha256(secret.as_bytes()),
				token_version,
				now,
				expires_at,
				absolute_expires_at: now + SESSION_MAX_SECS,
			})
			.await
			.map_err(unavailable)?;
		if !opened {
			tracing::error!(client_id = %client.client_id, user_id = %user, "relying party: code replayed while it was being redeemed — no session opened");
			return Err(ClientGrantError::InvalidGrant);
		}
		tracing::info!(client_id = %client.client_id, user_id = %user, %session_id, "relying party: signed in");
		Ok(ClientGrant {
			user_id: user.to_string(),
			audience: client.audience,
			token_version,
			session_id: session_id.to_string(),
			refresh_token: format!("{session_id}.{secret}"),
			refresh_expires_at: expires_at as u64,
		})
	}

	async fn rotate_refresh(&self, refresh: ClientRefresh) -> Result<ClientGrant, ClientGrantError> {
		let client = self.authenticate_client(&refresh.client_id, &refresh.client_secret).await?;
		let (session_id, secret) = refresh.refresh_token.split_once('.').ok_or(ClientGrantError::InvalidGrant)?;
		let session_id = Uuid::parse_str(session_id).map_err(|_| ClientGrantError::InvalidGrant)?;
		let session = self.repo.session(session_id).await.map_err(unavailable)?.ok_or(ClientGrantError::InvalidGrant)?;
		let now = now_secs();
		if session.client_id != client.client_id || session.revoked || now >= session.expires_at || now >= session.absolute_expires_at {
			return Err(ClientGrantError::InvalidGrant);
		}

		let presented = sha256(secret.as_bytes());
		if !bool::from(session.current_hash.as_slice().ct_eq(&presented)) {
			// ANY wrong secret, not only the rotated-out one. The client has proved it is
			// the client and names a real, live family of its own, so it holds the session
			// id; a secret that does not match means somebody has the id without the
			// credential — a leaked handle being guessed at. Ending the family costs the
			// user one sign-in; letting the guessing go on costs nothing to the guesser.
			let reused = session.prev_hash.as_deref().is_some_and(|prev| bool::from(prev.ct_eq(&presented)));
			self.repo.revoke_session(session_id, SessionRevocation::RefreshReuse, now).await.map_err(unavailable)?;
			tracing::error!(client_id = %client.client_id, user_id = %session.user, %session_id, reused, "relying party: wrong refresh secret for a live session — session revoked");
			return Err(ClientGrantError::InvalidGrant);
		}

		// Decided BEFORE the rotation, so a refusal leaves nothing half-done; the refusal
		// itself revokes, because a family whose user no longer passes has no future.
		let token_version = match self.admit(session.user).await.map_err(unavailable)? {
			Admission::Admitted { token_version } if token_version > session.token_version => {
				self.repo.revoke_session(session_id, SessionRevocation::TokensRevoked, now).await.map_err(unavailable)?;
				tracing::info!(client_id = %client.client_id, user_id = %session.user, %session_id, "relying party: tokens revoked since sign-in — session ended");
				return Err(ClientGrantError::InvalidGrant);
			}
			Admission::Admitted { token_version } => token_version,
			Admission::Denied => {
				self.repo.revoke_session(session_id, SessionRevocation::AccessDenied, now).await.map_err(unavailable)?;
				tracing::info!(client_id = %client.client_id, user_id = %session.user, %session_id, "relying party: account no longer active — session ended");
				return Err(ClientGrantError::AccessDenied);
			}
		};

		let next = random_secret();
		let expires_at = (now + REFRESH_TTL_SECS).min(session.absolute_expires_at);
		if !self
			.repo
			.rotate_session(session_id, &presented, &sha256(next.as_bytes()), expires_at, now)
			.await
			.map_err(unavailable)?
		{
			return Err(ClientGrantError::InvalidGrant);
		}
		Ok(ClientGrant {
			user_id: session.user.to_string(),
			audience: client.audience,
			token_version,
			session_id: session_id.to_string(),
			refresh_token: format!("{session_id}.{next}"),
			refresh_expires_at: expires_at as u64,
		})
	}
}

impl CodeOutcome {
	fn label(&self) -> &'static str {
		match self {
			Self::Redeemed { .. } => "redeemed",
			Self::Unknown => "unknown",
			Self::Expired => "expired",
			Self::Mismatch => "mismatch",
			Self::Replayed { .. } => "replayed",
		}
	}
}

fn unavailable(err: DomainError) -> ClientGrantError {
	ClientGrantError::Unavailable(err.to_string())
}

fn truncate(value: &str, max_chars: usize) -> &str {
	value.char_indices().nth(max_chars).map_or(value, |(at, _)| &value[..at])
}

impl ClientGrants for RelyingParties {
	fn redeem(&self, redemption: CodeRedemption) -> BoxFuture<'_, Result<ClientGrant, ClientGrantError>> {
		Box::pin(self.redeem_code(redemption))
	}

	fn refresh(&self, refresh: ClientRefresh) -> BoxFuture<'_, Result<ClientGrant, ClientGrantError>> {
		Box::pin(self.rotate_refresh(refresh))
	}

	fn upstream_revoked(&self, revocation: UpstreamRevocation) -> BoxFuture<'_, Result<(), ClientGrantError>> {
		Box::pin(async move {
			let (user_id, family) = match &revocation {
				UpstreamRevocation::Family { user_id, family_id } => (user_id, Some(family_id.as_str())),
				UpstreamRevocation::User { user_id } => (user_id, None),
			};
			// A family of a principal that is not a user id cannot have signed anybody in.
			let Ok(user) = Uuid::parse_str(user_id).map(UserId::from_raw) else {
				return Ok(());
			};
			let ended = self.repo.revoke_upstream(user, family, now_secs()).await.map_err(unavailable)?;
			if ended > 0 {
				tracing::info!(user_id = %user, ended, whole_account = family.is_none(), "relying party: upstream sign-out ended client sessions");
			}
			Ok(())
		})
	}

	fn publish_catalog(&self, publication: CatalogPublication) -> BoxFuture<'_, Result<(), ClientGrantError>> {
		Box::pin(self.publish(publication))
	}
}

/// The inbound authenticator for relying parties' access tokens, mounted as the
/// restricted half of the gRPC auth layer (`AuthLayer::with_restricted`) on `GetMe`
/// alone.
///
/// A signature and an unexpired `exp` are not enough here: such a token is held by a
/// backend on another origin, and "revoke" has to mean now. Its `jti` names the refresh
/// family it was minted under, and a family that is revoked (a replayed code, a reused
/// refresh token, a suspension, a token_version bump seen at refresh) ends it on the spot.
#[derive(Clone)]
pub struct ClientTokenAuthenticator {
	verifier: Verifier,
	relying_parties: Arc<RelyingParties>,
}

impl ClientTokenAuthenticator {
	pub fn new(verifier: Verifier, relying_parties: Arc<RelyingParties>) -> Self {
		Self { verifier, relying_parties }
	}
}

impl Authenticate for ClientTokenAuthenticator {
	async fn authenticate(&self, token: String) -> Result<Claims, AuthError> {
		let claims = self.verifier.verify(&token).await?;
		let session_id = claims
			.jti
			.as_deref()
			.and_then(|jti| jti.split_once(':'))
			.and_then(|(session, _)| Uuid::parse_str(session).ok())
			.ok_or(AuthError::InvalidToken)?;
		match self.relying_parties.session_live(session_id, &claims.aud).await {
			Ok(true) => Ok(claims),
			Ok(false) => Err(AuthError::InvalidToken),
			Err(err) => {
				tracing::error!(%err, "relying party: session liveness unreadable — refusing the token");
				Err(AuthError::Unavailable)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn s256_matches_the_rfc_7636_example() {
		assert_eq!(s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
		assert!(is_s256_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
		assert!(!is_s256_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="));
	}

	#[test]
	fn dev_redirects_are_loopback_only_and_never_in_production() {
		let parsed = parse_dev_redirects("sa=http://localhost:5173/auth/callback, sa=http://127.0.0.1:3000/cb", false).unwrap();
		assert_eq!(parsed["sa"].len(), 2);
		assert!(parse_dev_redirects("", true).unwrap().is_empty());
		assert!(parse_dev_redirects("sa=http://localhost:5173/auth/callback", true).is_err());
		for bad in [
			"sa=https://evil.example/cb",
			"sa=http://localhost.evil.example/cb",
			"sa=http://localhost:5173.evil.example/cb",
			"sa=http://localhost:5173/cb#frag",
			"sa=http://127.0.0.1@evil.example/cb",
			"sa",
		] {
			assert!(parse_dev_redirects(bad, false).is_err(), "{bad:?} must be refused");
		}
	}

	#[test]
	fn registered_redirects_must_be_plain_https() {
		let client = |uri: &str| ClientRecord {
			client_id: "sa".into(),
			audience: "sa".into(),
			redirect_uris: vec![uri.into()],
			secret_hash: None,
			disabled: false,
			namespace: "sa".into(),
		};
		assert!(check_registered_redirects(&client("https://sa.evinvest.ltd/auth/callback")).is_ok());
		for bad in ["http://sa.evinvest.ltd/cb", "https://sa.evinvest.ltd/cb#x", "https://u@sa.evinvest.ltd/cb", "https:///cb"] {
			assert!(check_registered_redirects(&client(bad)).is_err(), "{bad:?} must be refused");
		}
	}
}
