//! A whole provider sign-in through the web router — redirect out, callback in — against a
//! stand-in GitHub, so the arm's own rules (numeric id as subject, the PRIMARY email and
//! GitHub's word on whether it is verified) and the account resolution behind them are
//! exercised end to end.

mod common;

use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use axum::{
	Form, Json, Router,
	body::Body,
	extract::State,
	http::{Request, StatusCode, header},
	routing::{get, post},
};
use concierge::{
	infrastructure::{db, governance::PgGovernance, kyc::cases::PgKycCases, notifications::PgNotifications, users::PgUsers},
	ports::UserDirectoryRepository,
	web::{self, KycDeps},
};
use evconcierge_auth::{OAuthClientConfig, oauth::OAuthProvider};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://evinvest.test";

/// Who the stand-in GitHub says is signing in, per authorization code.
#[derive(Clone, Default)]
struct Github(Arc<Mutex<HashMap<String, (u64, Value)>>>);

async fn token(State(gh): State<Github>, Form(form): Form<HashMap<String, String>>) -> Json<Value> {
	let code = form.get("code").cloned().unwrap_or_default();
	match (gh.0.lock().unwrap().contains_key(&code), form.get("code_verifier").is_some_and(|v| !v.is_empty())) {
		(true, true) => Json(json!({ "access_token": code, "token_type": "bearer" })),
		_ => Json(json!({ "error": "bad_verification_code" })),
	}
}

fn bearer(headers: &axum::http::HeaderMap) -> String {
	headers.get(header::AUTHORIZATION).unwrap().to_str().unwrap().trim_start_matches("Bearer ").to_owned()
}

async fn user(State(gh): State<Github>, headers: axum::http::HeaderMap) -> Json<Value> {
	Json(json!({ "id": gh.0.lock().unwrap()[&bearer(&headers)].0, "login": "octo" }))
}

async fn emails(State(gh): State<Github>, headers: axum::http::HeaderMap) -> Json<Value> {
	Json(gh.0.lock().unwrap()[&bearer(&headers)].1.clone())
}

struct Fx {
	router: Router,
	pool: PgPool,
	users: Arc<PgUsers>,
	github: Github,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users = Arc::new(PgUsers::new(pool.clone()));

	let github = Github::default();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let stub = format!("http://{}", listener.local_addr().unwrap());
	let app = Router::new()
		.route("/login/oauth/access_token", post(token))
		.route("/user", get(user))
		.route("/user/emails", get(emails))
		.with_state(github.clone());
	tokio::spawn(async move { axum::serve(listener, app).await });

	let mut sign_in = common::inert_sign_in(&pool);
	let client = OAuthClientConfig {
		client_id: "gh-client".into(),
		client_secret: "gh-secret".into(),
	};
	sign_in.providers.push(OAuthProvider::github_at(&client, &format!("{stub}/login/oauth/access_token"), &stub));
	let state = web::WebState::try_new(
		common::signing_auth(users.clone()).await,
		ORIGIN.to_string(),
		false,
		sign_in,
		KycDeps {
			users: users.clone(),
			cases: Arc::new(PgKycCases::new(pool.clone())),
			notifications: Arc::new(PgNotifications::new(pool.clone())),
			governance: Arc::new(PgGovernance::new(pool.clone(), format!("{ORIGIN}/governance"))),
			provider: None,
			support_email: "support@evinvest.test".into(),
			case_ttl_secs: 86_400,
		},
		None,
	)
	.await
	.expect("build the web state");
	Some(Fx {
		router: web::router(state),
		pool,
		users,
		github,
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

fn cookies(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
	headers
		.get_all(header::SET_COOKIE)
		.iter()
		.filter_map(|raw| raw.to_str().unwrap().split(';').next().unwrap().split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
		.filter(|(_, v)| !v.is_empty())
		.collect()
}

impl Fx {
	/// GitHub will answer `code` with this numeric id and these `/user/emails`.
	fn will_answer(&self, code: &str, id: u64, emails: Value) {
		self.github.0.lock().unwrap().insert(code.to_owned(), (id, emails));
	}

	/// Run the redirect out and the callback in. Returns where the browser lands and the
	/// cookies it holds afterwards.
	async fn sign_in(&self, code: &str) -> (String, HashMap<String, String>) {
		let out = self
			.router
			.clone()
			.oneshot(Request::get("/auth/login?provider=github&returnTo=/cabinet").body(Body::empty()).unwrap())
			.await
			.unwrap();
		assert_eq!(out.status(), StatusCode::SEE_OTHER);
		let location = out.headers()[header::LOCATION].to_str().unwrap().to_owned();
		assert!(location.starts_with("https://github.com/login/oauth/authorize?"), "{location}");
		assert!(location.contains("code_challenge_method=S256"));
		let state = url_param(&location, "state");
		let tx = cookies(out.headers())["ev_oauth_tx"].clone();

		let back = self
			.router
			.clone()
			.oneshot(
				Request::get(format!("/callback/auth/github?code={code}&state={state}"))
					.header(header::COOKIE, format!("ev_oauth_tx={tx}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		(back.headers()[header::LOCATION].to_str().unwrap().to_owned(), cookies(back.headers()))
	}

	async fn github_account(&self, id: u64) -> Option<Uuid> {
		sqlx::query_scalar("SELECT user_id FROM user_identities WHERE provider = 'github' AND subject = $1")
			.bind(id.to_string())
			.fetch_optional(&self.pool)
			.await
			.unwrap()
	}
}

fn url_param(url: &str, name: &str) -> String {
	let query = url.split_once('?').unwrap().1;
	form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == name).unwrap().1.into_owned()
}

fn github_id() -> u64 {
	u64::from(Uuid::new_v4().as_fields().0)
}

fn address(tag: &str) -> String {
	format!("{tag}-{}@example.com", Uuid::new_v4().simple())
}

#[tokio::test]
async fn github_signs_in_by_its_numeric_id_and_primary_address() {
	let fx = fixture!();
	let (id, email) = (github_id(), address("gh"));
	let code = format!("code-{}", Uuid::new_v4().simple());
	fx.will_answer(
		&code,
		id,
		json!([
			{ "email": address("secondary"), "primary": false, "verified": true },
			{ "email": email, "primary": true, "verified": true },
		]),
	);
	let (landed, jar) = fx.sign_in(&code).await;
	assert_eq!(landed, "/cabinet");
	assert!(jar.contains_key("ev_session") && jar.contains_key("ev_access"));

	let account = fx.github_account(id).await.expect("the id is linked");
	let user = fx.users.find_by_id(domain::users::UserId::from_raw(account)).await.unwrap().unwrap();
	assert_eq!(user.email().as_str(), email, "the primary address, not the first one listed");
	assert!(user.email_verified(), "GitHub verified it");
}

#[tokio::test]
async fn github_joins_the_account_its_verified_address_already_opens() {
	let fx = fixture!();
	let existing = fx.users.resolve(common::google("before-github", true), 0).await.unwrap();
	let id = github_id();
	let code = format!("code-{}", Uuid::new_v4().simple());
	fx.will_answer(&code, id, json!([{ "email": existing.email().as_str(), "primary": true, "verified": true }]));
	fx.sign_in(&code).await;
	assert_eq!(fx.github_account(id).await, Some(existing.id().raw()));
}

#[tokio::test]
async fn an_unverified_github_address_opens_a_separate_account() {
	let fx = fixture!();
	let existing = fx.users.resolve(common::google("unverified-github", true), 0).await.unwrap();
	let id = github_id();
	let code = format!("code-{}", Uuid::new_v4().simple());
	fx.will_answer(&code, id, json!([{ "email": existing.email().as_str(), "primary": true, "verified": false }]));
	fx.sign_in(&code).await;
	let account = fx.github_account(id).await.expect("linked to something");
	assert_ne!(account, existing.id().raw(), "an address GitHub did not verify proves nothing");
}

#[tokio::test]
async fn a_refused_code_lands_back_signed_out() {
	let fx = fixture!();
	let (landed, jar) = fx.sign_in("never-issued").await;
	assert_eq!(landed, "/cabinet?auth_error=exchange");
	assert!(!jar.contains_key("ev_session"));
}
