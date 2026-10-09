//! The sign-in methods this plane checks itself, driven through the web router the
//! conductor reaches: emailed codes (and, beside them, passwords and verify-later).

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
	Router,
	body::Body,
	http::{Request, StatusCode, header},
};
use concierge::{
	dispatch::{DispatcherConfig, drain_once},
	infrastructure::{
		db,
		email::transport::{EmailTransport, OutgoingEmail},
		governance::PgGovernance,
		kyc::cases::PgKycCases,
		notifications::PgNotifications,
		users::PgUsers,
	},
	ports::{CODE_MAX_ATTEMPTS, CODE_SENDS_PER_WINDOW, UserDirectoryRepository},
	web::{self, KycDeps},
};
use domain::error::DomainError;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://evinvest.test";

struct Fx {
	router: Router,
	pool: PgPool,
	users: Arc<PgUsers>,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users = Arc::new(PgUsers::new(pool.clone()));
	let auth = common::signing_auth(users.clone()).await;
	let state = web::WebState::try_new(
		auth,
		ORIGIN.to_string(),
		false,
		common::sign_in_with_turnstile(&pool, &common::stub_turnstile().await),
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

/// A browser: the cookies the plane set, and the CSRF token it may read.
#[derive(Default)]
struct Browser {
	cookies: Vec<(String, String)>,
}

impl Browser {
	fn header(&self) -> String {
		self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
	}

	fn get(&self, name: &str) -> Option<&str> {
		self.cookies.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
	}

	fn absorb(&mut self, headers: &axum::http::HeaderMap) {
		for raw in headers.get_all(header::SET_COOKIE) {
			let pair = raw.to_str().unwrap().split(';').next().unwrap();
			let (name, value) = pair.split_once('=').unwrap();
			self.cookies.retain(|(k, _)| k != name);
			if !value.is_empty() {
				self.cookies.push((name.to_owned(), value.to_owned()));
			}
		}
	}
}

struct Answer {
	status: StatusCode,
	body: Value,
}

impl Fx {
	async fn post_from(&self, origin: &str, path: &str, body: Value, browser: &mut Browser) -> Answer {
		let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json").header(header::ORIGIN, origin);
		if !browser.cookies.is_empty() {
			request = request.header(header::COOKIE, browser.header());
		}
		if let Some(csrf) = browser.get("ev_csrf") {
			request = request.header("x-ev-csrf", csrf);
		}
		let response = self.router.clone().oneshot(request.body(Body::from(body.to_string())).unwrap()).await.unwrap();
		browser.absorb(response.headers());
		let status = response.status();
		let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
		Answer {
			status,
			body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
		}
	}

	async fn post(&self, path: &str, body: Value, browser: &mut Browser) -> Answer {
		self.post_from(ORIGIN, path, body, browser).await
	}

	async fn request_code(&self, email: &str) -> Answer {
		self.post("/auth/code/request", json!({ "email": email, "turnstileToken": "human" }), &mut Browser::default())
			.await
	}

	/// The plaintext of the newest code queued for `email`, as the mailer will send it.
	async fn mailed_code(&self, email: &str) -> String {
		sqlx::query_scalar("SELECT payload->>'code' FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1 ORDER BY id DESC LIMIT 1")
			.bind(email)
			.fetch_one(&self.pool)
			.await
			.expect("a code was queued")
	}

	async fn queued_codes(&self, email: &str) -> i64 {
		sqlx::query_scalar("SELECT count(*) FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1")
			.bind(email)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	async fn sign_in_with_code(&self, email: &str, browser: &mut Browser) -> Answer {
		assert_eq!(self.request_code(email).await.status, StatusCode::OK);
		let code = self.mailed_code(email).await;
		self.post("/auth/code/verify", json!({ "email": email, "code": code }), browser).await
	}

	async fn session(&self, browser: &Browser) -> Value {
		let request = Request::get("/auth/session").header(header::COOKIE, browser.header()).body(Body::empty()).unwrap();
		let response = self.router.clone().oneshot(request).await.unwrap();
		serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap()
	}
}

fn address(tag: &str) -> String {
	format!("{tag}-{}@example.com", Uuid::new_v4().simple())
}

fn wrong(code: &str) -> String {
	format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000)
}

#[tokio::test]
async fn a_code_signs_a_new_address_into_a_new_verified_account() {
	let fx = fixture!();
	let email = address("code");
	let mut browser = Browser::default();
	let answer = fx.sign_in_with_code(&email, &mut browser).await;
	assert_eq!((answer.status, answer.body), (StatusCode::OK, json!({ "ok": true })));
	assert!(browser.get("ev_session").is_some() && browser.get("ev_access").is_some() && browser.get("ev_csrf").is_some());

	let session = fx.session(&browser).await;
	assert_eq!(session["authenticated"], true);
	assert_eq!(session["user"]["email"], email);

	let again = fx.sign_in_with_code(&email, &mut Browser::default()).await;
	assert_eq!(again.status, StatusCode::OK);
	let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1 AND email_verified")
		.bind(&email)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(accounts, 1, "the second code opens the same account");
}

/// Whether an address has an account is decided only once a code proves the mailbox, so
/// asking for one says nothing either way.
#[tokio::test]
async fn asking_for_a_code_answers_alike_for_known_and_unknown_addresses() {
	let fx = fixture!();
	let known = fx.users.resolve(common::google("known", true), 0).await.unwrap();
	let a = fx.request_code(known.email().as_str()).await;
	let b = fx.request_code(&address("unknown")).await;
	assert_eq!((a.status, &a.body), (b.status, &b.body));
	assert_eq!(a.body, json!({ "ok": true }));
}

#[tokio::test]
async fn a_foreign_origin_signs_nobody_in() {
	let fx = fixture!();
	let email = address("csrf");
	let asked = fx
		.post_from(
			"https://evil.example",
			"/auth/code/request",
			json!({ "email": email, "turnstileToken": "human" }),
			&mut Browser::default(),
		)
		.await;
	assert_eq!((asked.status, asked.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));

	fx.request_code(&email).await;
	let code = fx.mailed_code(&email).await;
	let mut browser = Browser::default();
	let verified = fx
		.post_from("https://evil.example", "/auth/code/verify", json!({ "email": email, "code": code }), &mut browser)
		.await;
	assert_eq!((verified.status, verified.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));
	assert!(browser.get("ev_session").is_none());
}

#[tokio::test]
async fn a_failed_challenge_mails_nothing() {
	let fx = fixture!();
	let email = address("bot");
	let answer = fx.post("/auth/code/request", json!({ "email": email, "turnstileToken": "robot" }), &mut Browser::default()).await;
	assert_eq!((answer.status, answer.body), (StatusCode::FORBIDDEN, json!({ "error": "captcha" })));
	assert_eq!(fx.queued_codes(&email).await, 0);
}

#[tokio::test]
async fn the_last_wrong_guess_burns_the_code() {
	let fx = fixture!();
	let email = address("guess");
	fx.request_code(&email).await;
	let code = fx.mailed_code(&email).await;
	let mut browser = Browser::default();
	for attempt in 1..=CODE_MAX_ATTEMPTS {
		let answer = fx.post("/auth/code/verify", json!({ "email": email, "code": wrong(&code) }), &mut browser).await;
		let expected = if attempt < CODE_MAX_ATTEMPTS { "invalid_code" } else { "attempts_exceeded" };
		assert_eq!(answer.body, json!({ "error": expected }), "attempt {attempt}");
	}
	let late = fx.post("/auth/code/verify", json!({ "email": email, "code": code }), &mut browser).await;
	assert_eq!(late.body, json!({ "error": "attempts_exceeded" }), "the right code is too late once burned");
	assert!(browser.get("ev_session").is_none());

	let fresh = fx.sign_in_with_code(&email, &mut browser).await;
	assert_eq!(fresh.status, StatusCode::OK, "a new code starts over");
}

#[tokio::test]
async fn an_expired_code_proves_nothing() {
	let fx = fixture!();
	let email = address("late");
	fx.request_code(&email).await;
	let code = fx.mailed_code(&email).await;
	sqlx::query("UPDATE email_codes SET expires_at = 0 WHERE email = $1")
		.bind(&email)
		.execute(&fx.pool)
		.await
		.unwrap();
	let answer = fx.post("/auth/code/verify", json!({ "email": email, "code": code }), &mut Browser::default()).await;
	assert_eq!(answer.body, json!({ "error": "code_expired" }));
}

#[tokio::test]
async fn one_address_is_sent_a_bounded_number_of_codes() {
	let fx = fixture!();
	let email = address("flood");
	for _ in 0..CODE_SENDS_PER_WINDOW {
		assert_eq!(fx.request_code(&email).await.status, StatusCode::OK);
	}
	let answer = fx.request_code(&email).await;
	assert_eq!((answer.status, answer.body), (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "throttled" })));
	assert_eq!(fx.queued_codes(&email).await, CODE_SENDS_PER_WINDOW);
}

#[derive(Default)]
struct Outbox(Mutex<Vec<OutgoingEmail>>);

#[async_trait]
impl EmailTransport for Outbox {
	async fn send(&self, _from: &str, email: OutgoingEmail) -> Result<(), DomainError> {
		self.0.lock().unwrap().push(email);
		Ok(())
	}
}

#[tokio::test]
async fn the_code_leaves_in_a_mail_and_not_in_the_table() {
	let fx = fixture!();
	let email = address("mail");
	fx.request_code(&email).await;
	let code = fx.mailed_code(&email).await;

	let outbox = Outbox::default();
	let cfg = DispatcherConfig {
		mail_from: "EV <noreply@evinvest.test>".into(),
		cabinet_url: format!("{ORIGIN}/cabinet"),
		public_origin: ORIGIN.into(),
		daily_budget: i64::MAX,
		interval: std::time::Duration::from_secs(60),
	};
	while drain_once(&PgNotifications::new(fx.pool.clone()), &outbox, &cfg).await > 0 {}

	let sent = outbox.0.lock().unwrap().iter().find(|m| m.to == email).cloned().expect("the code mail was sent");
	assert!(sent.subject.contains(&code) && sent.text.contains(&code));
	assert!(sent.unsubscribe_url.is_empty(), "nobody unsubscribes from their own sign-in code");
	let stored: Option<Value> = sqlx::query_scalar("SELECT payload FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1")
		.bind(&email)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert!(stored.is_none(), "the plaintext is struck once the mail is out");
}
