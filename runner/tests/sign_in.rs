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

impl Fx {
	async fn sign_up(&self, email: &str, password: &str, verify: bool, browser: &mut Browser) -> Answer {
		self.post(
			"/auth/password/signup",
			json!({ "email": email, "password": password, "verify": verify, "turnstileToken": "human" }),
			browser,
		)
		.await
	}

	async fn password_sign_in(&self, identifier: &str, password: &str, browser: &mut Browser) -> Answer {
		self.post(
			"/auth/password/signin",
			json!({ "identifier": identifier, "password": password, "turnstileToken": "human" }),
			browser,
		)
		.await
	}

	/// Mail the signed-in account a verification code and read it back.
	async fn verification_code(&self, browser: &mut Browser) -> String {
		let answer = self.post("/auth/email/verify/request", json!({}), browser).await;
		assert_eq!(answer.body, json!({ "ok": true }));
		let email = self.session(browser).await["user"]["email"].as_str().unwrap().to_owned();
		self.mailed_code(&email).await
	}

	async fn methods(&self, browser: &Browser) -> Value {
		let request = Request::get("/auth/methods").header(header::COOKIE, browser.header()).body(Body::empty()).unwrap();
		let response = self.router.clone().oneshot(request).await.unwrap();
		serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap()
	}
}

const PASSWORD: &str = "correct horse battery";

#[tokio::test]
async fn a_password_account_works_unverified_and_verifies_later() {
	let fx = fixture!();
	let email = address("later");
	let mut browser = Browser::default();
	let answer = fx.sign_up(&email, PASSWORD, false, &mut browser).await;
	assert_eq!((answer.status, answer.body), (StatusCode::OK, json!({ "ok": true, "verification": "skipped" })));
	assert_eq!(fx.session(&browser).await["user"]["emailVerified"], false, "signed in, unverified");

	let code = fx.verification_code(&mut browser).await;
	let confirmed = fx.post("/auth/email/verify/confirm", json!({ "code": code }), &mut browser).await;
	assert_eq!(confirmed.body, json!({ "ok": true }));
	assert_eq!(fx.session(&browser).await["user"]["emailVerified"], true);
	assert_eq!(fx.methods(&browser).await["password"], true, "verifying later keeps the password");
}

#[tokio::test]
async fn ticking_verify_mails_a_code_at_sign_up() {
	let fx = fixture!();
	let email = address("now");
	let answer = fx.sign_up(&email, PASSWORD, true, &mut Browser::default()).await;
	assert_eq!(answer.body, json!({ "ok": true, "verification": "sent" }));
	assert_eq!(fx.queued_codes(&email).await, 1);
}

#[tokio::test]
async fn an_address_somebody_proved_or_backs_a_password_is_not_signed_up_again() {
	let fx = fixture!();
	let proved = address("proved");
	fx.sign_in_with_code(&proved, &mut Browser::default()).await;
	let answer = fx.sign_up(&proved, PASSWORD, false, &mut Browser::default()).await;
	assert_eq!((answer.status, answer.body), (StatusCode::CONFLICT, json!({ "error": "email_taken" })));

	let registered = address("registered");
	fx.sign_up(&registered, PASSWORD, false, &mut Browser::default()).await;
	let again = fx.sign_up(&registered, "another password", false, &mut Browser::default()).await;
	assert_eq!(again.body, json!({ "error": "email_taken" }));
}

#[tokio::test]
async fn a_short_password_is_refused() {
	let fx = fixture!();
	let answer = fx.sign_up(&address("short"), "1234567", false, &mut Browser::default()).await;
	assert_eq!((answer.status, answer.body), (StatusCode::BAD_REQUEST, json!({ "error": "weak_password" })));
}

#[tokio::test]
async fn a_password_signs_in_by_email_or_username_and_says_nothing_else() {
	let fx = fixture!();
	let local = format!("pw{}", Uuid::new_v4().simple());
	let email = format!("{local}@example.com");
	fx.sign_up(&email, PASSWORD, false, &mut Browser::default()).await;

	for identifier in [email.as_str(), local.as_str(), &email.to_uppercase()] {
		let mut browser = Browser::default();
		let answer = fx.password_sign_in(identifier, PASSWORD, &mut browser).await;
		assert_eq!(answer.status, StatusCode::OK, "{identifier}");
		assert_eq!(fx.session(&browser).await["user"]["email"], email);
	}
	let invalid = json!({ "error": "invalid_credentials" });
	assert_eq!(fx.password_sign_in(&email, "not the password", &mut Browser::default()).await.body, invalid);
	assert_eq!(
		fx.password_sign_in(&address("nobody"), PASSWORD, &mut Browser::default()).await.body,
		invalid,
		"no account reads as a wrong password"
	);
}

/// A username spelled like an address never captures that address's sign-in: the handle
/// is read as an email first.
#[tokio::test]
async fn an_address_is_an_email_before_it_is_a_username() {
	let fx = fixture!();
	let local = format!("shadow{}", Uuid::new_v4().simple());
	let email = format!("{local}@example.com");
	fx.sign_up(&email, PASSWORD, false, &mut Browser::default()).await;
	let twin = fx.users.resolve(common::google_as(&format!("twin-{}", Uuid::new_v4()), &email, false), 0).await.unwrap();
	assert_eq!(
		twin.username().map(|u| u.as_str()),
		Some(email.as_str()),
		"the local part was taken, so the twin's handle is the address"
	);

	let mut browser = Browser::default();
	assert_eq!(fx.password_sign_in(&email, PASSWORD, &mut browser).await.status, StatusCode::OK);
	assert_ne!(fx.session(&browser).await["user"]["userId"], twin.id().to_string());
}

#[tokio::test]
async fn a_locked_password_still_lets_a_code_in() {
	let fx = fixture!();
	let email = address("locked");
	fx.sign_up(&email, PASSWORD, false, &mut Browser::default()).await;
	for _ in 0..concierge::ports::PASSWORD_MAX_FAILURES {
		fx.password_sign_in(&email, "wrong guess", &mut Browser::default()).await;
	}
	let locked = fx.password_sign_in(&email, PASSWORD, &mut Browser::default()).await;
	assert_eq!((locked.status, locked.body), (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "password_locked" })));

	let mut browser = Browser::default();
	assert_eq!(fx.sign_in_with_code(&email, &mut browser).await.status, StatusCode::OK, "the mailbox still opens it");
}

#[tokio::test]
async fn setting_a_password_takes_a_mailed_code() {
	let fx = fixture!();
	let email = address("setpw");
	let mut browser = Browser::default();
	fx.sign_in_with_code(&email, &mut browser).await;
	assert_eq!(fx.methods(&browser).await["password"], false);

	let refused = fx.post("/auth/password/set", json!({ "password": PASSWORD, "code": "000000" }), &mut browser).await;
	assert_eq!(refused.body, json!({ "error": "invalid_code" }), "a session alone plants no password");

	let code = fx.verification_code(&mut browser).await;
	let set = fx.post("/auth/password/set", json!({ "password": PASSWORD, "code": code }), &mut browser).await;
	assert_eq!(set.body, json!({ "ok": true }));
	assert_eq!(fx.password_sign_in(&email, PASSWORD, &mut Browser::default()).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_username_is_chosen_within_its_alphabet_and_held_by_one_account() {
	let fx = fixture!();
	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("handle"), &mut browser).await;
	let wanted = format!("h{}", &Uuid::new_v4().simple().to_string()[..12]);

	let set = fx.post("/auth/username", json!({ "username": wanted.to_uppercase() }), &mut browser).await;
	assert_eq!(set.body, json!({ "ok": true, "username": wanted }));
	let with_at = fx.post("/auth/username", json!({ "username": "me@example.com" }), &mut browser).await;
	assert_eq!(with_at.body, json!({ "error": "invalid_username" }), "a chosen handle never looks like an address");

	let mut other = Browser::default();
	fx.sign_in_with_code(&address("rival"), &mut other).await;
	let taken = fx.post("/auth/username", json!({ "username": wanted }), &mut other).await;
	assert_eq!((taken.status, taken.body), (StatusCode::CONFLICT, json!({ "error": "username_taken" })));
}

#[tokio::test]
async fn the_admin_search_finds_a_username() {
	let fx = fixture!();
	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("searched"), &mut browser).await;
	let wanted = format!("s{}", &Uuid::new_v4().simple().to_string()[..12]);
	fx.post("/auth/username", json!({ "username": wanted }), &mut browser).await;
	let (rows, total) = fx.users.list(&wanted[..10], "", "", 10, 0).await.unwrap();
	assert_eq!(total, 1);
	assert_eq!(rows[0].username.as_deref(), Some(wanted.as_str()));
}

/// A guest is a principal with a declared permission set, not an absence: the session
/// answers it, and a sign-in replaces it with the seat's.
#[tokio::test]
async fn the_session_states_a_guests_permissions_and_then_the_seats() {
	let fx = fixture!();
	let guest = fx.session(&Browser::default()).await;
	assert_eq!(guest, json!({ "authenticated": false, "permissions": domain::authz::SEAT_GUEST.members }));

	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("seat"), &mut browser).await;
	let session = fx.session(&browser).await;
	let held: Vec<&str> = session["permissions"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
	assert_eq!(held, domain::authz::Role::Investor.permissions());
	assert!(held.contains(&"concierge:self:profile"), "an account holds its own record");
}

mod passkeys {
	use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
	use webauthn_rs::prelude::{CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse, Url};

	use super::*;

	/// The soft authenticator keeps no resident keys and answers no discoverable request,
	/// so the test plays that part of a platform authenticator: it is told which key to use
	/// and stamps the user handle the key was registered under.
	struct Device {
		authenticator: WebauthnAuthenticator<SoftPasskey>,
		credential_id: Option<String>,
		user_handle: Option<Vec<u8>>,
	}

	impl Device {
		fn new() -> Self {
			Self {
				authenticator: WebauthnAuthenticator::new(SoftPasskey::new(true)),
				credential_id: None,
				user_handle: None,
			}
		}

		fn origin() -> Url {
			Url::parse(ORIGIN).unwrap()
		}

		fn register(&mut self, mut options: Value) -> Value {
			assert_eq!(options["publicKey"]["authenticatorSelection"]["residentKey"], "required", "a passkey must be discoverable");
			options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(false);
			let handle = options["publicKey"]["user"]["id"].as_str().unwrap().to_owned();
			let ccr: CreationChallengeResponse = serde_json::from_value(options).unwrap();
			let credential = self.authenticator.do_registration(Self::origin(), ccr).expect("the authenticator registers");
			self.credential_id = Some(credential.id.clone());
			self.user_handle = Some(base64_url(&handle));
			serde_json::to_value(credential).unwrap()
		}

		fn assert(&mut self, mut options: Value) -> PublicKeyCredential {
			assert_eq!(options["publicKey"]["allowCredentials"], json!([]), "a discoverable request names no credential");
			options["publicKey"]["allowCredentials"] = json!([{ "type": "public-key", "id": self.credential_id.clone().unwrap() }]);
			let rcr: RequestChallengeResponse = serde_json::from_value(options).unwrap();
			let mut credential = self.authenticator.do_authentication(Self::origin(), rcr).expect("the authenticator asserts");
			credential.response.user_handle = Some(self.user_handle.clone().unwrap().into());
			credential
		}
	}

	fn base64_url(raw: &str) -> Vec<u8> {
		use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
		URL_SAFE_NO_PAD.decode(raw.trim_end_matches('=')).unwrap()
	}

	async fn registered(fx: &Fx, email: &str) -> (Device, Browser) {
		let mut browser = Browser::default();
		fx.sign_in_with_code(email, &mut browser).await;
		let begun = fx.post("/auth/passkey/register/options", json!({}), &mut browser).await;
		let mut device = Device::new();
		let credential = device.register(begun.body["options"].clone());
		let done = fx
			.post(
				"/auth/passkey/register/verify",
				json!({ "ceremony": begun.body["ceremony"], "credential": credential, "name": "Test key" }),
				&mut browser,
			)
			.await;
		assert_eq!(done.body, json!({ "ok": true }));
		(device, browser)
	}

	#[tokio::test]
	async fn a_registered_passkey_signs_in_without_naming_the_account() {
		let fx = fixture!();
		let email = address("passkey");
		let (mut device, owner) = registered(&fx, &email).await;
		assert_eq!(fx.methods(&owner).await["passkeys"].as_array().unwrap().len(), 1);

		let mut browser = Browser::default();
		let begun = fx.post("/auth/passkey/signin/options", json!({}), &mut browser).await;
		let assertion = device.assert(begun.body["options"].clone());
		let done = fx
			.post(
				"/auth/passkey/signin/verify",
				json!({ "ceremony": begun.body["ceremony"], "credential": assertion }),
				&mut browser,
			)
			.await;
		assert_eq!((done.status, done.body), (StatusCode::OK, json!({ "ok": true })));
		assert_eq!(fx.session(&browser).await["user"]["email"], email);

		let replay = fx
			.post(
				"/auth/passkey/signin/verify",
				json!({ "ceremony": begun.body["ceremony"], "credential": assertion }),
				&mut Browser::default(),
			)
			.await;
		assert_eq!(replay.body, json!({ "error": "passkey_expired" }), "a ceremony answers once");
	}

	#[tokio::test]
	async fn a_forged_assertion_signs_nobody_in() {
		let fx = fixture!();
		let (mut device, _) = registered(&fx, &address("forged")).await;
		let mut browser = Browser::default();
		let begun = fx.post("/auth/passkey/signin/options", json!({}), &mut browser).await;
		let mut assertion = device.assert(begun.body["options"].clone());
		let mut signature: Vec<u8> = assertion.response.signature.clone().into();
		let last = signature.len() - 1;
		signature[last] ^= 1;
		assertion.response.signature = signature.into();
		let done = fx
			.post(
				"/auth/passkey/signin/verify",
				json!({ "ceremony": begun.body["ceremony"], "credential": assertion }),
				&mut browser,
			)
			.await;
		assert_eq!((done.status, done.body), (StatusCode::UNAUTHORIZED, json!({ "error": "passkey_rejected" })));
		assert!(browser.get("ev_session").is_none());
	}

	#[tokio::test]
	async fn a_removed_passkey_no_longer_signs_in() {
		let fx = fixture!();
		let (mut device, mut owner) = registered(&fx, &address("removed")).await;
		let id = fx.methods(&owner).await["passkeys"][0]["id"].as_str().unwrap().to_owned();
		assert_eq!(fx.post("/auth/passkey/remove", json!({ "credentialId": id }), &mut owner).await.body, json!({ "ok": true }));

		let mut browser = Browser::default();
		let begun = fx.post("/auth/passkey/signin/options", json!({}), &mut browser).await;
		let assertion = device.assert(begun.body["options"].clone());
		let done = fx
			.post(
				"/auth/passkey/signin/verify",
				json!({ "ceremony": begun.body["ceremony"], "credential": assertion }),
				&mut browser,
			)
			.await;
		assert_eq!(done.body, json!({ "error": "passkey_rejected" }));
	}
}
