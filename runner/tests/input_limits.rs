//! Integration tests for the input-limit guard clauses (#25) at the gRPC handlers.
//!
//! Real Postgres (no mocks, per the project rules), `DATABASE_URL`-gated like the
//! other suites. The field-by-field parsing rules are covered by the domain unit
//! tests; here we prove each hardened handler maps a bad input to
//! `INVALID_ARGUMENT` before writing, and that the legal edge shapes (clearing the
//! announcement, empty list filters) keep working.

use std::sync::Arc;

use concierge::{
	directory::Directory,
	infrastructure::{db, platform::PgPlatform, users::PgUsers},
	platform::Platform,
	ports::{PlatformConfigRepository, UserDirectoryRepository},
};
use domain::users::{AuthSubject, Email};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	ListUsersRequest, SetAnnouncementRequest, SetFeatureFlagRequest, SetKycLevelRequest, UpdateProfileRequest, platform_service_server::PlatformService, user_directory_server::UserDirectory,
};
use tonic::{Code, Request};
use uuid::Uuid;

async fn setup() -> Option<(Arc<dyn UserDirectoryRepository>, Arc<dyn PlatformConfigRepository>)> {
	let url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some((Arc::new(PgUsers::new(pool.clone())), Arc::new(PgPlatform::new(pool))))
}

fn access_claims(sub: &str) -> Claims {
	Claims {
		sub: sub.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
	}
}

fn request_with<T>(sub: &str, inner: T) -> Request<T> {
	let mut req = Request::new(inner);
	req.extensions_mut().insert(access_claims(sub));
	req
}

/// An allowlisted (break-glass Owner) caller so one principal exercises both the
/// self-service and the admin surfaces.
async fn owner(users: &Arc<dyn UserDirectoryRepository>) -> (String, Arc<[String]>) {
	let subject = AuthSubject::parse(&format!("limits-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("limits@example.com").unwrap(), true).await.unwrap();
	let sub = user.id().to_string();
	let admins: Arc<[String]> = vec![sub.clone()].into();
	(sub, admins)
}

fn profile(phone: &str, base_currency: &str) -> UpdateProfileRequest {
	UpdateProfileRequest {
		phone: phone.into(),
		base_currency: base_currency.into(),
		..UpdateProfileRequest::default()
	}
}

#[tokio::test]
async fn update_profile_rejects_junk_with_invalid_argument() {
	let Some((users, _)) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let (sub, admins) = owner(&users).await;
	let directory = Directory::new(users, admins);

	let err = directory.update_profile(request_with(&sub, profile("https://t.me/junk", ""))).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument);
	assert!(err.message().contains("phone"), "the message names the offending field: {}", err.message());

	// A valid set persists, with the currency normalized and blanks kept cleared.
	let updated = directory.update_profile(request_with(&sub, profile(" +84 28 3822 9284 ", "usd"))).await.unwrap().into_inner();
	assert_eq!(updated.phone, "+84 28 3822 9284");
	assert_eq!(updated.base_currency, "USD");
	assert_eq!(updated.legal_name, "", "an empty field stays a clear");
}

#[tokio::test]
async fn set_kyc_level_is_bounded() {
	let Some((users, _)) = setup().await else {
		return;
	};
	let (sub, admins) = owner(&users).await;
	let directory = Directory::new(users, admins);

	let err = directory
		.set_kyc_level(request_with(&sub, SetKycLevelRequest { user_id: sub.clone(), kyc_level: 4 }))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument);

	let ok = directory
		.set_kyc_level(request_with(&sub, SetKycLevelRequest { user_id: sub.clone(), kyc_level: 3 }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(ok.kyc_level, 3);
}

#[tokio::test]
async fn list_users_validates_filters_and_truncates_query() {
	let Some((users, _)) = setup().await else {
		return;
	};
	let (sub, admins) = owner(&users).await;
	let directory = Directory::new(users, admins);
	let list = |query: &str, role: &str, status: &str| ListUsersRequest {
		query: query.into(),
		role: role.into(),
		status: status.into(),
		limit: 1,
		offset: 0,
	};

	let bad_role = directory.list_users(request_with(&sub, list("", "superuser", ""))).await.unwrap_err();
	assert_eq!(bad_role.code(), Code::InvalidArgument);
	let bad_status = directory.list_users(request_with(&sub, list("", "", "meh"))).await.unwrap_err();
	assert_eq!(bad_status.code(), Code::InvalidArgument);

	// Empty filters stay "no filter", and an oversized query is truncated, not fatal.
	directory.list_users(request_with(&sub, list(&"q".repeat(5000), "", ""))).await.unwrap();
	directory.list_users(request_with(&sub, list("", "investor", "active"))).await.unwrap();
}

#[tokio::test]
async fn announcement_and_flag_writes_enforce_caps() {
	let Some((users, config)) = setup().await else {
		return;
	};
	let (sub, admins) = owner(&users).await;
	let platform = Platform::new(users, admins, config);

	let announce = |title: String, body: String| SetAnnouncementRequest { title, body, active: true };
	let long_title = platform.set_announcement(request_with(&sub, announce("t".repeat(201), String::new()))).await.unwrap_err();
	assert_eq!(long_title.code(), Code::InvalidArgument);
	let long_body = platform.set_announcement(request_with(&sub, announce(String::new(), "b".repeat(2001)))).await.unwrap_err();
	assert_eq!(long_body.code(), Code::InvalidArgument);
	// Clearing the banner (empty title/body) must keep working.
	let cleared = platform
		.set_announcement(request_with(
			&sub,
			SetAnnouncementRequest {
				title: String::new(),
				body: String::new(),
				active: false,
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(cleared.announcement_title, "");
	assert!(!cleared.announcement_active);

	let flag = |key: &str, description: String| SetFeatureFlagRequest {
		key: key.into(),
		description,
		enabled: false,
		rollout: 0,
	};
	for bad_key in ["", "Upper", "has space", "-leading", &"k".repeat(65)] {
		let err = platform.set_feature_flag(request_with(&sub, flag(bad_key, String::new()))).await.unwrap_err();
		assert_eq!(err.code(), Code::InvalidArgument, "key {bad_key:?} must be rejected");
	}
	let long_description = platform.set_feature_flag(request_with(&sub, flag("ok-flag_1", "d".repeat(501)))).await.unwrap_err();
	assert_eq!(long_description.code(), Code::InvalidArgument);
	platform.set_feature_flag(request_with(&sub, flag("ok-flag_1", "d".repeat(500)))).await.unwrap();
}
