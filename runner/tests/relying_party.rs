//! The relying-party code flow, end to end against a REAL Postgres: `/auth/authorize`
//! through the real axum router, `ExchangeCode`/`RefreshClientToken` through the real
//! `AuthService`, and the minted token through the real gRPC auth layer.
//!
//! Every test registers its OWN client (unique id, audience and tenant) rather than
//! touching the seeded `sa`, so runs neither collide nor depend on the registry's state.
//!
//! The authorize tests that need a signed-in browser need Redis as well: the session
//! locker is shared with the router only through it (see `web_sessions.rs`). Without
//! `REDIS_URL` those few print a skip line and return.

mod common;

use std::{net::TcpListener, sync::Arc, time::Duration};

use axum::{
	Router,
	body::Body,
	http::{Request as HttpRequest, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use concierge::{
	authz::BreakGlass,
	directory::Directory,
	infrastructure::{
		db, governance::PgGovernance, grants::PgGrants, kyc::cases::PgKycCases, notifications::PgNotifications, platform::PgPlatform, relying_parties::PgRelyingParties, users::PgUsers,
	},
	platform::Platform,
	ports::{ClientRecord, RelyingPartyRepository, UserDirectoryRepository},
	relying_party::{Admission, ClientTokenAuthenticator, RelyingParties, Requester, s256_challenge},
	web::{self, KycDeps},
};
use domain::users::{AuthSubject, Email, UserId};
use evconcierge_auth::{AuthConfig, AuthService, SigningConfig, TokenType, Verifier, VerifierConfig, grpc_auth_layer, provisioner_channel};
use evconcierge_contracts::concierge::v1::{
	ClientTokenResponse, ExchangeCodeRequest, GetMeRequest, GetPlatformConfigRequest, RefreshClientTokenRequest, TokenResponse, UpdateProfileRequest, UserSummary,
	auth_service_server::{AuthService as AuthRpc, AuthServiceServer},
	platform_service_client::PlatformServiceClient,
	platform_service_server::PlatformServiceServer,
	user_directory_client::UserDirectoryClient,
	user_directory_server::UserDirectoryServer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::{
	Code, Request,
	server::NamedService,
	transport::{Channel, Server},
};
use tower::{Layer, ServiceExt};
use uuid::Uuid;

// The same throwaway Ed25519 keypair the auth crate's own tests sign with.
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKolOSMXwE+tafZkX+jkKYJbmJ066f4E12wAwTIkKps6\n-----END PRIVATE KEY-----\n";
const TEST_JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
const ISSUER: &str = "https://auth.concierge.test";
const PLANE_AUDIENCE: &str = "concierge";

fn auth_config() -> AuthConfig {
	AuthConfig {
		issuer: ISSUER.into(),
		client_audience: PLANE_AUDIENCE.into(),
		service_audience: "concierge-services".into(),
		access_ttl_secs: 3600,
		refresh_ttl_secs: 3600,
		max_session_secs: 7_776_000,
		idle_timeout_secs: 0,
		service_ttl_secs: 300,
		signing: Some(SigningConfig {
			signing_key_pem: TEST_PEM.into(),
			kid: "test-kid".into(),
			jwks_json: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_JWK_X}","kid":"test-kid","alg":"EdDSA","use":"sig"}}]}}"#),
		}),
		google: None,
	}
}

fn sha256(input: &str) -> Vec<u8> {
	Sha256::digest(input.as_bytes()).to_vec()
}

fn random(n: usize) -> String {
	let mut buf = vec![0u8; n];
	getrandom::fill(&mut buf).unwrap();
	URL_SAFE_NO_PAD.encode(buf)
}

/// One registered client, private to the test that made it.
struct TestClient {
	id: String,
	audience: String,
	namespace: String,
	redirect_uri: String,
	secret: String,
}

struct Fx {
	pool: PgPool,
	users: Arc<PgUsers>,
	repo: Arc<PgRelyingParties>,
	rp: Arc<RelyingParties>,
	auth: AuthService,
	client: TestClient,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let users = Arc::new(PgUsers::new(pool.clone()));
	let repo = Arc::new(PgRelyingParties::new(pool.clone()));
	let rp = Arc::new(RelyingParties::new(repo.clone(), users.clone(), Arc::new(PgGrants::new(pool.clone())), Default::default()));

	let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
	let client = TestClient {
		id: format!("t_{tag}"),
		audience: format!("aud_{tag}"),
		namespace: format!("n_{tag}"),
		redirect_uri: format!("https://rp-{tag}.test/auth/callback"),
		secret: random(32),
	};
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ($1, $1, TRUE, 0)")
		.bind(&client.namespace)
		.execute(&pool)
		.await
		.expect("register the client's tenant");
	sqlx::query("INSERT INTO rp_clients (client_id, audience, redirect_uris, created_at, tenant_id) VALUES ($1, $2, $3, 0, $4)")
		.bind(&client.id)
		.bind(&client.audience)
		.bind(vec![client.redirect_uri.clone()])
		.bind(&client.namespace)
		.execute(&pool)
		.await
		.expect("register the test client");
	sqlx::query("INSERT INTO catalogs (tenant_id, version, catalog, published_at) VALUES ($1, 1, $2, 0)")
		.bind(&client.namespace)
		.bind(serde_json::json!({
			"version": 1,
			"permissions": [format!("{}:work:leads:read", client.namespace)],
			"aliases": { format!("{}:operator", client.namespace): [format!("{}:work:leads:read", client.namespace)] },
			"delegations": {},
		}))
		.execute(&pool)
		.await
		.expect("publish the tenant's catalog");
	repo.set_secret_hash(&client.id, Some(sha256(&client.secret).as_slice()), 1).await.expect("set the client secret");

	let (provisioner, _rx) = provisioner_channel();
	let auth = AuthService::try_new(auth_config(), provisioner).await.expect("auth service").with_client_grants(rp.clone());
	Some(Fx {
		pool,
		users,
		repo,
		rp,
		auth,
		client,
	})
}

macro_rules! fixture {
	() => {
		match setup().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

impl Fx {
	async fn user(&self) -> UserId {
		let subject = AuthSubject::parse(&format!("rp-itest-{}", Uuid::new_v4())).unwrap();
		self.users.provision(subject, Email::parse("rp@example.com").unwrap(), true).await.expect("provision").id()
	}

	/// The tenant's `operator` alias, granted by someone else.
	async fn grant_operator(&self, user: UserId) {
		let granter = self.user().await;
		sqlx::query("INSERT INTO grants (user_id, namespace, target, granted_by, granted_at) VALUES ($1, $2, $2 || ':operator', $3, 0)")
			.bind(user.raw())
			.bind(&self.client.namespace)
			.bind(granter.raw())
			.execute(&self.pool)
			.await
			.expect("grant the operator alias");
	}

	async fn set_status(&self, user: UserId, status: &str) {
		sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
			.bind(user.raw())
			.bind(status)
			.execute(&self.pool)
			.await
			.expect("set status");
	}

	async fn bump_token_version(&self, user: UserId) {
		sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1")
			.bind(user.raw())
			.execute(&self.pool)
			.await
			.expect("bump token_version");
	}

	async fn record(&self) -> ClientRecord {
		self.rp.resolve(&self.client.id, &self.client.redirect_uri).await.unwrap().expect("the test client resolves")
	}

	/// A code for `user`, issued the way `/auth/authorize` issues one (admission included),
	/// plus the PKCE verifier it is bound to.
	async fn code_for(&self, user: UserId) -> (String, String) {
		let client = self.record().await;
		let Admission::Admitted { token_version } = self.rp.admit(user).await.unwrap() else {
			panic!("the user must be admitted to be issued a code");
		};
		let verifier = random(48);
		let code = self
			.rp
			.issue_code(
				&client,
				&self.client.redirect_uri,
				&s256_challenge(&verifier),
				user,
				token_version,
				Requester {
					upstream_family: &format!("fam-{}", Uuid::new_v4()),
					client_ip: "203.0.113.7",
					user_agent: "itest",
				},
			)
			.await
			.expect("issue code");
		(code, verifier)
	}

	async fn exchange(&self, code: &str, verifier: &str) -> Result<ClientTokenResponse, tonic::Status> {
		self.exchange_as(&self.client.secret, code, verifier).await
	}

	async fn exchange_as(&self, secret: &str, code: &str, verifier: &str) -> Result<ClientTokenResponse, tonic::Status> {
		AuthRpc::exchange_code(
			&self.auth,
			Request::new(ExchangeCodeRequest {
				client_id: self.client.id.clone(),
				client_secret: secret.to_owned(),
				code: code.to_owned(),
				redirect_uri: self.client.redirect_uri.clone(),
				code_verifier: verifier.to_owned(),
			}),
		)
		.await
		.map(|r| r.into_inner())
	}

	async fn refresh(&self, refresh_token: &str) -> Result<ClientTokenResponse, tonic::Status> {
		AuthRpc::refresh_client_token(
			&self.auth,
			Request::new(RefreshClientTokenRequest {
				client_id: self.client.id.clone(),
				client_secret: self.client.secret.clone(),
				refresh_token: refresh_token.to_owned(),
			}),
		)
		.await
		.map(|r| r.into_inner())
	}

	async fn signed_in(&self) -> (UserId, ClientTokenResponse) {
		let user = self.user().await;
		let (code, verifier) = self.code_for(user).await;
		(user, self.exchange(&code, &verifier).await.expect("a fresh code redeems"))
	}

	async fn session_of(&self, tokens: &ClientTokenResponse) -> Uuid {
		Uuid::parse_str(tokens.refresh_token.split_once('.').unwrap().0).unwrap()
	}

	async fn revoked_reason(&self, session: Uuid) -> Option<String> {
		sqlx::query_scalar("SELECT revoked_reason FROM rp_sessions WHERE id = $1")
			.bind(session)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	async fn session_live(&self, tokens: &ClientTokenResponse) -> bool {
		self.rp.session_live(self.session_of(tokens).await, &self.client.audience).await.unwrap()
	}
}

/// The JWT's claims, read without verifying — the verifying half is the gRPC test below.
fn claims_of(token: &str) -> Value {
	let payload = token.split('.').nth(1).expect("a JWT");
	serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

// ─── ExchangeCode ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_code_redeems_once_for_a_client_audience_access_token() {
	let fx = fixture!();
	let (user, tokens) = fx.signed_in().await;

	let claims = claims_of(&tokens.access_token);
	assert_eq!(claims["aud"], fx.client.audience.as_str());
	assert_eq!(claims["sub"], user.to_string());
	assert_eq!(claims["typ"], "access");
	let ttl = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
	assert!(
		ttl <= 900,
		"a relying party's access token lives at most 15 minutes even when AUTH_ACCESS_TTL_SECS says an hour (got {ttl}s)"
	);
	assert!(claims["jti"].as_str().unwrap().starts_with(&format!("{}:", fx.session_of(&tokens).await)));
	assert_eq!(tokens.user_id, user.to_string());
	assert!(fx.session_live(&tokens).await);
}

#[tokio::test]
async fn a_wrong_pkce_verifier_is_refused_and_burns_the_code() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;

	let status = fx.exchange(&code, &random(48)).await.expect_err("a verifier that does not hash to the challenge");
	assert_eq!(status.code(), Code::Unauthenticated);
	// One attempt per code: the right verifier afterwards does not revive it.
	let status = fx.exchange(&code, &verifier).await.expect_err("a burned code");
	assert_eq!(status.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn a_replayed_code_is_refused_and_revokes_what_it_bought() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;
	let first = fx.exchange(&code, &verifier).await.expect("first redemption");
	assert!(fx.session_live(&first).await);

	let status = fx.exchange(&code, &verifier).await.expect_err("second redemption");
	assert_eq!(status.code(), Code::Unauthenticated);

	assert!(!fx.session_live(&first).await, "the access token the first redemption bought must stop working now");
	assert_eq!(fx.revoked_reason(fx.session_of(&first).await).await.as_deref(), Some("code_replay"));
	let status = fx.refresh(&first.refresh_token).await.expect_err("its refresh token too");
	assert_eq!(status.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn an_expired_code_is_refused() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;
	sqlx::query("UPDATE rp_codes SET expires_at = issued_at - 1 WHERE code_hash = $1")
		.bind(sha256(&code))
		.execute(&fx.pool)
		.await
		.unwrap();

	let status = fx.exchange(&code, &verifier).await.expect_err("expired");
	assert_eq!(status.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn a_wrong_client_secret_is_refused_without_burning_the_code() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;

	let status = fx.exchange_as(&random(32), &code, &verifier).await.expect_err("wrong secret");
	assert_eq!(status.code(), Code::Unauthenticated);
	assert_eq!(status.message(), "invalid client");
	fx.exchange(&code, &verifier).await.expect("the code was never presented by an authenticated client");
}

#[tokio::test]
async fn a_client_without_a_secret_obtains_nothing() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;
	fx.repo.set_secret_hash(&fx.client.id, None, 2).await.unwrap();

	let status = fx.exchange(&code, &verifier).await.expect_err("no secret set");
	assert_eq!(status.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn a_suspension_between_authorize_and_exchange_denies_the_exchange() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;
	fx.set_status(user, "disabled").await;

	let status = fx.exchange(&code, &verifier).await.expect_err("the account is re-read at the exchange");
	assert_eq!(status.code(), Code::PermissionDenied);
}

// ─── Admission ───────────────────────────────────────────────────────────────────

/// What a user may do inside a client is its tenant's permissions, which GetMe hands it;
/// signing in only asks whether the account is usable. A user holding nothing still gets
/// in — some of a client's surface is open to everyone.
#[tokio::test]
async fn any_active_account_is_admitted_and_a_suspended_one_is_not() {
	let fx = fixture!();
	let nobody = fx.user().await;
	assert!(matches!(fx.rp.admit(nobody).await.unwrap(), Admission::Admitted { .. }));
	fx.set_status(nobody, "disabled").await;
	assert!(matches!(fx.rp.admit(nobody).await.unwrap(), Admission::Denied));
}

// ─── RefreshClientToken ──────────────────────────────────────────────────────────

#[tokio::test]
async fn refresh_rotates_and_a_reused_token_revokes_the_session() {
	let fx = fixture!();
	let (_, first) = fx.signed_in().await;

	let second = fx.refresh(&first.refresh_token).await.expect("rotation");
	assert_ne!(second.refresh_token, first.refresh_token);
	assert_eq!(claims_of(&second.access_token)["aud"], fx.client.audience.as_str());

	let status = fx.refresh(&first.refresh_token).await.expect_err("the rotated-out token");
	assert_eq!(status.code(), Code::Unauthenticated);
	assert_eq!(fx.revoked_reason(fx.session_of(&first).await).await.as_deref(), Some("refresh_reuse"));
	fx.refresh(&second.refresh_token).await.expect_err("the whole family is gone, not just the replayed handle");
}

#[tokio::test]
async fn refresh_after_a_suspension_is_denied_and_ends_the_session() {
	let fx = fixture!();
	let (user, tokens) = fx.signed_in().await;
	fx.set_status(user, "disabled").await;

	let status = fx.refresh(&tokens.refresh_token).await.expect_err("the account is re-checked on every refresh");
	assert_eq!(status.code(), Code::PermissionDenied);
	assert_eq!(fx.revoked_reason(fx.session_of(&tokens).await).await.as_deref(), Some("access_denied"));
	assert!(!fx.session_live(&tokens).await, "the outstanding access token dies with the session");

	// Reinstating the account does not resurrect a session that was ended.
	fx.set_status(user, "active").await;
	fx.refresh(&tokens.refresh_token).await.expect_err("revoked for good");
}

#[tokio::test]
async fn refresh_after_revoke_all_is_refused() {
	let fx = fixture!();
	let (user, tokens) = fx.signed_in().await;
	fx.bump_token_version(user).await;

	let status = fx.refresh(&tokens.refresh_token).await.expect_err("token_version moved past the session");
	assert_eq!(status.code(), Code::Unauthenticated);
	assert_eq!(fx.revoked_reason(fx.session_of(&tokens).await).await.as_deref(), Some("tokens_revoked"));
}

#[tokio::test]
async fn a_refresh_token_is_bound_to_its_client() {
	let fx = fixture!();
	let (_, tokens) = fx.signed_in().await;
	let other = fixture!();

	let status = AuthRpc::refresh_client_token(
		&other.auth,
		Request::new(RefreshClientTokenRequest {
			client_id: other.client.id.clone(),
			client_secret: other.client.secret.clone(),
			refresh_token: tokens.refresh_token.clone(),
		}),
	)
	.await
	.expect_err("another client's refresh token");
	assert_eq!(status.code(), Code::Unauthenticated);
}

// ─── The token on the wire: GetMe and nothing else ───────────────────────────────

/// The composition `main::run` mounts: the plane's verifier on every service, the
/// client verifier admitted on `GetMe` alone.
async fn boot(fx: &Fx) -> Channel {
	let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
	let endpoint = format!("http://{addr}");
	let plane = Verifier::try_new(VerifierConfig {
		issuer: ISSUER.into(),
		audiences: vec![PLANE_AUDIENCE.into()],
		allowed_types: vec![TokenType::Access],
		jwks_grpc_endpoint: endpoint.clone(),
	})
	.unwrap();
	let clients = Verifier::try_new(VerifierConfig {
		issuer: ISSUER.into(),
		audiences: vec![fx.client.audience.clone()],
		allowed_types: vec![TokenType::Access],
		jwks_grpc_endpoint: endpoint.clone(),
	})
	.unwrap();
	let get_me = format!("/{}/GetMe", <UserDirectoryServer<Directory> as NamedService>::NAME);
	let auth = grpc_auth_layer(plane).with_restricted(ClientTokenAuthenticator::new(clients, fx.rp.clone()), [get_me]);

	let users: Arc<dyn UserDirectoryRepository> = fx.users.clone();
	let break_glass = Arc::new(BreakGlass::new(Vec::new()));
	let directory = Directory::new(users.clone(), Arc::new(PgGrants::new(fx.pool.clone())), break_glass.clone());
	let platform = Platform::new(users, break_glass, Arc::new(PgPlatform::new(fx.pool.clone())));
	let issuance = fx.auth.clone();
	tokio::spawn(async move {
		Server::builder()
			.add_service(AuthServiceServer::new(issuance))
			.add_service(auth.layer(UserDirectoryServer::new(directory)))
			.add_service(auth.layer(PlatformServiceServer::new(platform)))
			.serve(addr)
			.await
			.expect("server")
	});
	for _ in 0..50 {
		if let Ok(channel) = Channel::from_shared(endpoint.clone()).unwrap().connect().await {
			return channel;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	panic!("server never became reachable");
}

fn bearer<T>(message: T, token: &str) -> Request<T> {
	let mut request = Request::new(message);
	request.metadata_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
	request
}

#[tokio::test]
async fn a_client_token_opens_get_me_and_no_other_rpc() {
	let fx = fixture!();
	let (user, tokens) = fx.signed_in().await;
	let channel = boot(&fx).await;
	let mut directory = UserDirectoryClient::new(channel.clone());

	let me = directory
		.get_me(bearer(GetMeRequest {}, &tokens.access_token))
		.await
		.expect("GetMe admits the client's token")
		.into_inner();
	assert_eq!(me.user_id, user.to_string());
	assert!(me.permissions.is_empty(), "a user granted nothing holds nothing");
	fx.grant_operator(user).await;
	let me = directory.get_me(bearer(GetMeRequest {}, &tokens.access_token)).await.expect("GetMe").into_inner();
	assert_eq!(
		me.permissions,
		[format!("{}:work:leads:read", fx.client.namespace)],
		"GetMe hands the client the live permissions"
	);

	// Another method of the SAME service.
	let status = directory
		.update_profile(bearer(UpdateProfileRequest::default(), &tokens.access_token))
		.await
		.expect_err("UpdateProfile must not accept a client token");
	assert_eq!(status.code(), Code::Unauthenticated);

	// A method of ANOTHER service.
	let status = PlatformServiceClient::new(channel)
		.get_platform_config(bearer(GetPlatformConfigRequest {}, &tokens.access_token))
		.await
		.expect_err("the platform surface must not accept a client token");
	assert_eq!(status.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn a_revoked_session_ends_its_access_token_at_get_me() {
	let fx = fixture!();
	let (user, tokens) = fx.signed_in().await;
	let channel = boot(&fx).await;
	let mut directory = UserDirectoryClient::new(channel);
	directory.get_me(bearer(GetMeRequest {}, &tokens.access_token)).await.expect("live");

	fx.set_status(user, "disabled").await;
	fx.refresh(&tokens.refresh_token).await.expect_err("ends the session");

	let status = directory
		.get_me(bearer(GetMeRequest {}, &tokens.access_token))
		.await
		.expect_err("an unexpired token of a revoked session");
	assert_eq!(status.code(), Code::Unauthenticated);
}

// ─── /auth/authorize ─────────────────────────────────────────────────────────────

async fn router(fx: &Fx) -> Router {
	// The fixture's own issuance service, so the families `signed_in_browser` opens are
	// the ones the route checks.
	let state = web::WebState::try_new(
		fx.auth.clone(),
		"https://evinvest.test".to_string(),
		false,
		KycDeps {
			users: fx.users.clone(),
			cases: Arc::new(PgKycCases::new(fx.pool.clone())),
			notifications: Arc::new(PgNotifications::new(fx.pool.clone())),
			governance: Arc::new(PgGovernance::new(fx.pool.clone(), "https://evinvest.test/governance".to_string())),
			provider: None,
			support_email: "support@evinvest.test".into(),
			case_ttl_secs: 86_400,
		},
		Some(fx.rp.clone()),
	)
	.await
	.expect("web state");
	web::router(state)
}

struct Answer {
	status: StatusCode,
	location: Option<String>,
	headers: axum::http::HeaderMap,
}

async fn get(router: &Router, uri: &str, cookie: Option<&str>) -> Answer {
	let mut request = HttpRequest::builder().uri(uri);
	if let Some(cookie) = cookie {
		request = request.header(header::COOKIE, cookie);
	}
	let response = router.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
	Answer {
		status: response.status(),
		location: response.headers().get(header::LOCATION).map(|v| v.to_str().unwrap().to_owned()),
		headers: response.headers().clone(),
	}
}

fn authorize_uri(client_id: &str, redirect_uri: &str, challenge: &str) -> String {
	let query = form_urlencoded::Serializer::new(String::new())
		.append_pair("client_id", client_id)
		.append_pair("redirect_uri", redirect_uri)
		.append_pair("response_type", "code")
		.append_pair("state", "st-123")
		.append_pair("code_challenge", challenge)
		.append_pair("code_challenge_method", "S256")
		.finish();
	format!("/auth/authorize?{query}")
}

/// The query parameters of a redirect back to the client.
fn params(location: &str) -> std::collections::HashMap<String, String> {
	let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
	form_urlencoded::parse(query.as_bytes()).into_owned().collect()
}

/// A REAL `evinvest.ltd` session: a refresh family in the fixture's issuance store and a
/// locker entry pointing at it, as a Google sign-in leaves them. Returns the cookie and
/// the refresh token.
async fn signed_in_browser(fx: &Fx, user: UserId) -> Option<(String, String)> {
	std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty())?;
	let refresh_token = fx.auth.open_family_for_tests(&user.to_string(), 0).await.expect("open a refresh family");
	let sessions = web::WebSessions::from_env().await.expect("session store");
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
	let (id, ..) = sessions
		.put(TokenResponse {
			access_token: "access".into(),
			access_expires_at: now + 900,
			refresh_token: refresh_token.clone(),
			refresh_expires_at: now + 3600,
			user: Some(UserSummary {
				user_id: user.to_string(),
				email: "rp@example.com".into(),
				status: "active".into(),
				token_version: 0,
				role: "investor".into(),
				role_is_break_glass: false,
			}),
		})
		.await
		.expect("open session")
		.expect("token pair carries a user");
	Some((format!("ev_session={id}"), refresh_token))
}

async fn session_cookie(fx: &Fx, user: UserId) -> Option<String> {
	signed_in_browser(fx, user).await.map(|(cookie, _)| cookie)
}

#[tokio::test]
async fn an_unregistered_redirect_uri_gets_a_page_never_a_redirect() {
	let fx = fixture!();
	let router = router(&fx).await;
	let challenge = s256_challenge(&random(48));
	let registered = fx.client.redirect_uri.clone();

	for (client_id, redirect_uri) in [
		("no_such_client", registered.as_str()),
		(fx.client.id.as_str(), "https://evil.example/auth/callback"),
		// Neither a prefix nor a suffix of a registered URI is that URI.
		(fx.client.id.as_str(), &format!("{registered}/../../evil")),
		(fx.client.id.as_str(), &format!("{registered}?next=https://evil.example")),
		(fx.client.id.as_str(), registered.trim_end_matches("/callback")),
		(fx.client.id.as_str(), &registered.replace("https://", "http://")),
	] {
		let answer = get(&router, &authorize_uri(client_id, redirect_uri, &challenge), None).await;
		assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{client_id} → {redirect_uri}");
		assert_eq!(answer.location, None, "{client_id} → {redirect_uri} must not redirect anywhere");
	}

	// Missing parameters are the same page.
	let answer = get(&router, "/auth/authorize?client_id=x", None).await;
	assert_eq!((answer.status, answer.location), (StatusCode::BAD_REQUEST, None));
}

#[tokio::test]
async fn without_a_session_authorize_sends_the_browser_to_login_and_back() {
	let fx = fixture!();
	let router = router(&fx).await;
	let challenge = s256_challenge(&random(48));

	let answer = get(&router, &authorize_uri(&fx.client.id, &fx.client.redirect_uri, &challenge), None).await;
	assert_eq!(answer.status, StatusCode::FOUND);
	let location = answer.location.unwrap();
	assert!(location.starts_with("/api/auth/login?returnTo="), "{location}");
	let return_to = &params(&location)["returnTo"];
	assert!(
		return_to.starts_with("/api/auth/authorize?"),
		"returnTo must be a same-origin path the login accepts: {return_to}"
	);
	let back = params(return_to);
	assert_eq!(back["client_id"], fx.client.id);
	assert_eq!(back["redirect_uri"], fx.client.redirect_uri);
	assert_eq!(back["state"], "st-123");
	assert_eq!(back["code_challenge"], challenge);

	// Back from a failed or cancelled sign-in: the refusal goes to the client, not round
	// the login again.
	let answer = get(&router, &format!("{}&auth_error=denied", authorize_uri(&fx.client.id, &fx.client.redirect_uri, &challenge)), None).await;
	let location = answer.location.unwrap();
	assert!(location.starts_with(&fx.client.redirect_uri));
	assert_eq!(params(&location)["error"], "access_denied");
	assert_eq!(params(&location)["state"], "st-123");
}

#[tokio::test]
async fn select_account_goes_past_a_live_session_to_the_account_chooser() {
	let fx = fixture!();
	let router = router(&fx).await;
	let Some(cookie) = session_cookie(&fx, fx.user().await).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};
	let challenge = s256_challenge(&random(48));
	let uri = format!("{}&prompt=select_account", authorize_uri(&fx.client.id, &fx.client.redirect_uri, &challenge));

	let location = get(&router, &uri, Some(&cookie)).await.location.unwrap();
	assert!(
		location.starts_with("/api/auth/login?returnTo="),
		"a live session must not answer for another account: {location}"
	);
	let back = params(&params(&location)["returnTo"]);
	assert_eq!(back["code_challenge"], challenge);
	assert!(!back.contains_key("prompt"), "coming back from the chooser must authorize, not choose again");

	// Any other prompt is not one this server keeps.
	for prompt in ["none", "login", "consent", "select_account login"] {
		let uri = format!("{}&prompt={}", authorize_uri(&fx.client.id, &fx.client.redirect_uri, &challenge), prompt.replace(' ', "+"));
		let location = get(&router, &uri, Some(&cookie)).await.location.unwrap();
		assert!(location.starts_with(&fx.client.redirect_uri), "{prompt}: {location}");
		assert_eq!(params(&location)["error"], "invalid_request", "{prompt}");
	}
}

#[tokio::test]
async fn a_bad_pkce_challenge_goes_back_to_the_client_as_invalid_request() {
	let fx = fixture!();
	let router = router(&fx).await;
	let uri = authorize_uri(&fx.client.id, &fx.client.redirect_uri, "too-short").replace("S256", "plain");

	let answer = get(&router, &uri, None).await;
	assert_eq!(answer.status, StatusCode::FOUND);
	let location = answer.location.unwrap();
	assert!(location.starts_with(&fx.client.redirect_uri));
	assert_eq!(params(&location)["error"], "invalid_request");
}

#[tokio::test]
async fn authorize_issues_a_code_only_to_an_active_account() {
	let fx = fixture!();
	let router = router(&fx).await;

	let suspended = fx.user().await;
	let Some(cookie) = session_cookie(&fx, suspended).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};
	let verifier = random(48);
	let uri = authorize_uri(&fx.client.id, &fx.client.redirect_uri, &s256_challenge(&verifier));
	fx.set_status(suspended, "disabled").await;

	// Suspended: no code exists.
	let answer = get(&router, &uri, Some(&cookie)).await;
	assert_eq!(answer.status, StatusCode::FOUND);
	assert!(!params(answer.location.as_deref().unwrap()).contains_key("code"));

	// Anyone else gets a code that redeems, holding nothing in the tenant.
	let user = fx.user().await;
	let cookie = session_cookie(&fx, user).await.unwrap();
	let answer = get(&router, &uri, Some(&cookie)).await;
	let location = answer.location.unwrap();
	assert!(location.starts_with(&format!("{}?", fx.client.redirect_uri)), "{location}");
	let back = params(&location);
	assert_eq!(back["state"], "st-123");
	let tokens = fx.exchange(&back["code"], &verifier).await.expect("the issued code redeems with its verifier");
	assert_eq!(tokens.user_id, user.to_string());
}

// ─── Security follow-ups (PR #100 review) ────────────────────────────────────────

#[tokio::test]
async fn get_me_on_a_client_token_carries_no_identity_document_fields() {
	let fx = fixture!();
	let (user, tokens) = fx.signed_in().await;
	sqlx::query(
		"UPDATE users SET legal_name = 'Jane Q Public', preferred_name = 'Jane', phone = '+15550100', date_of_birth = '1990-01-01', nationality = 'DE', tax_residence = 'DE', residential_address = '1 Main St', kyc_level = 1 WHERE id = $1",
	)
	.bind(user.raw())
	.execute(&fx.pool)
	.await
	.expect("fill the profile");
	let mut directory = UserDirectoryClient::new(boot(&fx).await);

	let me = directory.get_me(bearer(GetMeRequest {}, &tokens.access_token)).await.expect("GetMe").into_inner();
	assert_eq!(me.user_id, user.to_string());
	assert_eq!(me.preferred_name, "Jane");
	assert_eq!(me.email, "rp@example.com");
	for (field, value) in [
		("legal_name", &me.legal_name),
		("phone", &me.phone),
		("date_of_birth", &me.date_of_birth),
		("nationality", &me.nationality),
		("tax_residence", &me.tax_residence),
		("residential_address", &me.residential_address),
	] {
		assert!(value.is_empty(), "{field} must not reach a relying party, got {value:?}");
	}
	assert_eq!(me.kyc_level, 0, "kyc_level must not reach a relying party");
}

#[tokio::test]
async fn a_wrong_refresh_secret_for_a_real_session_revokes_it() {
	let fx = fixture!();
	let (_, tokens) = fx.signed_in().await;
	let session = fx.session_of(&tokens).await;

	// The session id is right and the client proved itself; only the secret is wrong. That
	// is somebody holding a handle they should not — not a stale retry.
	let status = fx.refresh(&format!("{session}.{}", random(32))).await.expect_err("wrong secret");
	assert_eq!(status.code(), Code::Unauthenticated);
	assert_eq!(fx.revoked_reason(session).await.as_deref(), Some("refresh_reuse"));
	fx.refresh(&tokens.refresh_token).await.expect_err("the family is gone");
}

#[tokio::test]
async fn a_session_is_not_opened_off_a_code_whose_replay_is_still_committing() {
	let fx = fixture!();
	let user = fx.user().await;
	let (code, _) = fx.code_for(user).await;
	let code_hash = sha256(&code);

	// The replaying transaction has marked the code but not committed yet.
	let mut replay = fx.pool.begin().await.unwrap();
	sqlx::query("SELECT 1 FROM rp_codes WHERE code_hash = $1 FOR UPDATE")
		.bind(&code_hash)
		.execute(&mut *replay)
		.await
		.unwrap();
	sqlx::query("UPDATE rp_codes SET redeemed_at = 1, replayed_at = 1 WHERE code_hash = $1")
		.bind(&code_hash)
		.execute(&mut *replay)
		.await
		.unwrap();

	let repo = fx.repo.clone();
	let client_id = fx.client.id.clone();
	let hash = code_hash.clone();
	let opening = tokio::spawn(async move {
		let secret = sha256("irrelevant");
		repo.open_session(concierge::ports::NewSession {
			id: Uuid::new_v4(),
			client_id: &client_id,
			user,
			code_hash: &hash,
			secret_hash: &secret,
			token_version: 0,
			now: 10,
			expires_at: i64::MAX / 2,
			absolute_expires_at: i64::MAX / 2,
		})
		.await
	});
	tokio::time::sleep(Duration::from_millis(300)).await;
	replay.commit().await.unwrap();

	assert!(!opening.await.unwrap().unwrap(), "open_session must wait for the replay and then refuse");
	let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM rp_sessions WHERE code_hash = $1")
		.bind(&code_hash)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(sessions, 0);
}

#[tokio::test]
async fn state_and_response_type_are_required() {
	let fx = fixture!();
	let router = router(&fx).await;
	let good = authorize_uri(&fx.client.id, &fx.client.redirect_uri, &s256_challenge(&random(48)));

	for (uri, error) in [
		(good.replace("&state=st-123", ""), "invalid_request"),
		(good.replace("&state=st-123", "&state="), "invalid_request"),
		(good.replace("&state=st-123", &format!("&state={}", "x".repeat(513))), "invalid_request"),
		(good.replace("&response_type=code", ""), "invalid_request"),
		(good.replace("response_type=code", "response_type=token"), "unsupported_response_type"),
	] {
		let answer = get(&router, &uri, None).await;
		assert_eq!(answer.status, StatusCode::FOUND, "{uri}");
		let location = answer.location.unwrap();
		assert!(location.starts_with(&fx.client.redirect_uri), "{location}");
		assert_eq!(params(&location)["error"], error, "{uri}");
	}
}

#[tokio::test]
async fn authorize_answers_leak_no_referrer_and_its_page_cannot_be_framed() {
	let fx = fixture!();
	let router = router(&fx).await;

	let page = get(&router, &authorize_uri("no_such_client", &fx.client.redirect_uri, "x"), None).await;
	assert_eq!(page.headers[header::REFERRER_POLICY], "no-referrer");
	assert!(page.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("frame-ancestors 'none'"));

	let redirect = get(&router, &authorize_uri(&fx.client.id, &fx.client.redirect_uri, &s256_challenge(&random(48))), None).await;
	assert_eq!(redirect.status, StatusCode::FOUND);
	assert_eq!(redirect.headers[header::REFERRER_POLICY], "no-referrer");
}

fn logout(refresh_token: String, revoke_all: bool) -> Request<evconcierge_contracts::concierge::v1::LogoutRequest> {
	Request::new(evconcierge_contracts::concierge::v1::LogoutRequest { refresh_token, revoke_all })
}

fn revoke_session(refresh_token: String, session_id: String) -> Request<evconcierge_contracts::concierge::v1::RevokeSessionRequest> {
	Request::new(evconcierge_contracts::concierge::v1::RevokeSessionRequest { refresh_token, session_id })
}

#[tokio::test]
async fn a_cabinet_session_revoked_upstream_does_not_authorize() {
	let fx = fixture!();
	let router = router(&fx).await;
	let operator = fx.user().await;
	let Some((cookie, refresh_token)) = signed_in_browser(&fx, operator).await else {
		eprintln!("skipped: REDIS_URL unset — the router's session store would not see a session opened here");
		return;
	};
	let uri = authorize_uri(&fx.client.id, &fx.client.redirect_uri, &s256_challenge(&random(48)));
	let answer = get(&router, &uri, Some(&cookie)).await;
	assert!(params(answer.location.as_deref().unwrap()).contains_key("code"), "a live session authorizes");
	assert!(
		answer.headers.get_all(header::SET_COOKIE).iter().any(|c| c.to_str().unwrap().starts_with("ev_access=")),
		"the access cookie is handed back"
	);

	// Signed out on another device: the family is gone, the locker entry is not.
	AuthRpc::logout(&fx.auth, logout(refresh_token, false)).await.expect("logout");

	let location = get(&router, &uri, Some(&cookie)).await.location.unwrap();
	assert!(
		location.starts_with("/api/auth/login?"),
		"a signed-out session must be sent to sign in, not handed a code: {location}"
	);
	let session_id = cookie.trim_start_matches("ev_session=");
	assert!(
		web::WebSessions::from_env().await.unwrap().csrf(session_id).await.unwrap().is_none(),
		"the dead locker entry is dropped"
	);
}

/// Sign `user` into the client the way a browser does: through `/auth/authorize` on a
/// real cabinet session, then the exchange. Returns the cabinet refresh token and the
/// client's pair.
async fn signed_into_client(fx: &Fx, router: &Router, user: UserId) -> Option<(String, ClientTokenResponse)> {
	let (cookie, refresh_token) = signed_in_browser(fx, user).await?;
	let verifier = random(48);
	let answer = get(router, &authorize_uri(&fx.client.id, &fx.client.redirect_uri, &s256_challenge(&verifier)), Some(&cookie)).await;
	let code = params(answer.location.as_deref().unwrap())["code"].clone();
	Some((refresh_token, fx.exchange(&code, &verifier).await.expect("exchange")))
}

#[tokio::test]
async fn signing_out_of_the_cabinet_signs_out_of_the_client() {
	let fx = fixture!();
	let router = router(&fx).await;
	let user = fx.user().await;
	let Some((cabinet, client)) = signed_into_client(&fx, &router, user).await else {
		eprintln!("skipped: REDIS_URL unset");
		return;
	};
	// A second cabinet session of the same user, and a client session made through it.
	let (_, other_client) = signed_into_client(&fx, &router, user).await.unwrap();

	AuthRpc::logout(&fx.auth, logout(cabinet, false)).await.expect("logout");

	assert!(!fx.session_live(&client).await, "the client session that cabinet session authorized ends");
	assert_eq!(fx.revoked_reason(fx.session_of(&client).await).await.as_deref(), Some("upstream_revoked"));
	assert!(fx.session_live(&other_client).await, "one authorized by ANOTHER cabinet session stays");
}

#[tokio::test]
async fn revoking_a_cabinet_session_by_id_ends_its_client_sessions_and_only_the_owners() {
	let fx = fixture!();
	let router = router(&fx).await;
	let user = fx.user().await;
	let Some((cabinet, client)) = signed_into_client(&fx, &router, user).await else {
		eprintln!("skipped: REDIS_URL unset");
		return;
	};
	let listed = AuthRpc::list_sessions(&fx.auth, Request::new(evconcierge_contracts::concierge::v1::ListSessionsRequest { refresh_token: cabinet }))
		.await
		.unwrap()
		.into_inner();
	let family = listed.sessions.iter().find(|s| s.current).unwrap().id.clone();

	// Somebody else naming that family revokes nothing, here or at the client.
	let (_, stranger) = signed_in_browser(&fx, fx.user().await).await.unwrap();
	AuthRpc::revoke_session(&fx.auth, revoke_session(stranger, family.clone())).await.unwrap();
	assert!(fx.session_live(&client).await, "a stranger's RevokeSession must not reach the owner's client sessions");

	let (_, second_device) = signed_in_browser(&fx, user).await.unwrap();
	AuthRpc::revoke_session(&fx.auth, revoke_session(second_device, family)).await.unwrap();
	assert!(!fx.session_live(&client).await);
	assert_eq!(fx.revoked_reason(fx.session_of(&client).await).await.as_deref(), Some("upstream_revoked"));
}

#[tokio::test]
async fn revoke_all_ends_every_client_session_and_outstanding_code() {
	let fx = fixture!();
	let router = router(&fx).await;
	let user = fx.user().await;
	let Some((cabinet, client)) = signed_into_client(&fx, &router, user).await else {
		eprintln!("skipped: REDIS_URL unset");
		return;
	};
	let (pending_code, verifier) = fx.code_for(user).await;

	AuthRpc::logout(&fx.auth, logout(cabinet, true)).await.expect("logout everywhere");

	assert!(!fx.session_live(&client).await);
	fx.exchange(&pending_code, &verifier).await.expect_err("a code issued before the sign-out is dead too");
}

#[tokio::test]
async fn a_replica_without_the_secret_variable_keeps_the_stored_secret() {
	let fx = fixture!();
	fx.rp.sync_registry(|_| None).await.expect("sync with no secrets in env");
	let user = fx.user().await;
	let (code, verifier) = fx.code_for(user).await;
	fx.exchange(&code, &verifier).await.expect("the client still authenticates with the secret another replica set");
}
