//! Integration tests for the input-limit guard clauses (#25) at the gRPC handlers.
//!
//! Real Postgres (no mocks, per the project rules), `DATABASE_URL`-gated like the
//! other suites. The field-by-field parsing rules are covered by the domain unit
//! tests; here we prove each hardened handler maps a bad input to
//! `INVALID_ARGUMENT` before writing, and that the legal edge shapes (clearing the
//! announcement, empty list filters) keep working.

use std::sync::Arc;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	infrastructure::{
		db,
		platform::PgPlatform,
		users::{AdminAction, PgUsers},
	},
	platform::Platform,
	ports::{PlatformConfigRepository, UserDirectoryRepository},
	support::domain_to_status,
};
use domain::{
	authz::Role,
	users::{AuthSubject, Email, MAX_KYC_LEVEL, UserId},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	ListUsersRequest, SetAnnouncementRequest, SetFeatureFlagRequest, SetKycLevelRequest, UpdateProfileRequest, platform_service_server::PlatformService, user_directory_server::UserDirectory,
};
use sqlx::PgPool;
use tonic::{Code, Request};
use uuid::Uuid;

mod common;

/// The suite's preconditions, or `None` when there is no database to assert against.
///
/// The gate is not cosmetic. Every test here returns early when `DATABASE_URL` is missing,
/// and a skipped run prints exactly the same "N passed" a real one does — so "8 passed" is
/// evidence of nothing on its own, including for the refusal in `#47` this suite is the
/// only pin for. [`common::database_url`] answers that twice over: it panics under CI, and
/// it prints a SKIPPED line a local `--nocapture` run shows.
async fn setup() -> Option<(Arc<dyn UserDirectoryRepository>, Arc<dyn PlatformConfigRepository>, PgPool)> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some((Arc::new(PgUsers::new(pool.clone())), Arc::new(PgPlatform::new(pool.clone())), pool))
}

/// Rows `admin_action` holds about this person, and `KYC_CHANGED` rows on the outbox the
/// money plane mirrors. A refusal must move neither.
async fn traces_of(pool: &PgPool, user: UserId) -> (i64, i64) {
	let audit = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_action WHERE subject_user_id = $1")
		.bind(user.raw())
		.fetch_one(pool)
		.await
		.expect("count admin_action");
	let outbox = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_outbox WHERE user_id = $1 AND kind = 'KYC_CHANGED'")
		.bind(user.raw())
		.fetch_one(pool)
		.await
		.expect("count outbox rows");
	(audit, outbox)
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

/// An ordinary user for an admin verb to act ON.
///
/// `set_kyc_level` (#47) and `hold_user` are the two verbs that distinguish the caller
/// from the target and refuse when they are the same, so a bounds check that reused the
/// caller's own subject was testing a path the handler no longer reaches. It is NOT a
/// rule of the module: `revoke_tokens`, `reinstate_user` and `get_user` compare nothing,
/// and `update_profile`/`list_users` below are self-service and must stay that way.
async fn subject_of(users: &Arc<dyn UserDirectoryRepository>, tag: &str) -> String {
	let subject = AuthSubject::parse(&format!("{tag}-{}", Uuid::new_v4())).unwrap();
	users.provision(subject, Email::parse("limits-target@example.com").unwrap(), true).await.unwrap().id().to_string()
}

/// A PERSISTED admin, so one principal exercises both the self-service and the admin
/// surfaces. Deliberately NOT an `OWNER_SUBJECTS` caller: emergency elevation is live
/// only while the owner registry is empty, and this suite shares a database with the
/// consilium suite — one leftover owner there would silently turn every assertion here
/// into a `PermissionDenied`. `Admin` grants everything these handlers ask for.
async fn admin(users: &Arc<dyn UserDirectoryRepository>) -> (String, Arc<BreakGlass>) {
	let subject = AuthSubject::parse(&format!("limits-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("limits@example.com").unwrap(), true).await.unwrap();
	users.set_role(user.id(), Role::Admin).await.unwrap();
	(user.id().to_string(), Arc::new(BreakGlass::new(Vec::new())))
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
	let Some((users, _, _)) = setup().await else {
		return;
	};
	let (sub, break_glass) = admin(&users).await;
	let directory = Directory::new(users, break_glass);

	let err = directory.update_profile(request_with(&sub, profile("https://t.me/junk", ""))).await.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument);
	// Case-insensitive: the validator moved to `ev::types::PhoneNumber`, whose message
	// opens with a capitalised "Phone number …". The assertion is about the field being
	// named at all, not about its casing.
	assert!(err.message().to_lowercase().contains("phone"), "the message names the offending field: {}", err.message());

	// A valid set persists, with the currency normalized and blanks kept cleared.
	// E.164 is digits-only after the `+` since the validator moved to
	// `ev::types::PhoneNumber` (#29/#30) — the spaced form this fixture used to carry is
	// now rejected outright, so a stored number is the canonical one.
	let updated = directory.update_profile(request_with(&sub, profile(" +842838229284 ", "usd"))).await.unwrap().into_inner();
	assert_eq!(updated.phone, "+842838229284");
	assert_eq!(updated.base_currency, "USD");
	assert_eq!(updated.legal_name, "", "an empty field stays a clear");
}

#[tokio::test]
async fn set_kyc_level_is_bounded() {
	let Some((users, _, _)) = setup().await else {
		return;
	};
	let (sub, break_glass) = admin(&users).await;
	let target = subject_of(&users, "kyc-target").await;
	let directory = Directory::new(users, break_glass);

	let err = directory
		.set_kyc_level(request_with(
			&sub,
			SetKycLevelRequest {
				user_id: target.clone(),
				kyc_level: 4,
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument);

	let ok = directory
		.set_kyc_level(request_with(
			&sub,
			SetKycLevelRequest {
				user_id: target,
				kyc_level: 3,
				reason: String::new(),
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(ok.kyc_level, 3);
}

/// #47: a `KycManage` holder may not set their OWN level.
///
/// This test used to pin the opposite. It sent `SetKycLevelRequest { user_id: sub, .. }`
/// against the caller's own subject and asserted `kyc_level == 3` — which made the
/// behaviour look deliberate without anywhere saying so, while `SetRole` in the same file
/// forbids the dangerous direction at length and `domain::authz` describes the matrix as a
/// separation of duties.
///
/// What it was pinning: `KycManage` is granted to `Admin`, not only `Owner`, and tier 1 is
/// the floor for withdrawals on the MONEY plane. So an operator could lift their own money
/// gate in a plane where they hold no permissions at all, and it would read in both planes
/// as an ordinary verification.
///
/// The refusal is checked BEFORE the range check, so "level 4 on myself" is denied rather
/// than merely called out of range: an operator must not learn which of the two rules they
/// tripped by picking a legal number.
#[tokio::test]
async fn an_operator_cannot_set_their_own_kyc_level() {
	let Some((users, _, pool)) = setup().await else {
		return;
	};
	let (sub, break_glass) = admin(&users).await;
	let actor = sub.parse::<Uuid>().map(UserId::from_raw).unwrap();
	// The operator starts at 1, through the front door they are still allowed. A run that
	// started them at 0 could not tell a refusal apart from a write: the levels asked for
	// below include 0, and `admin()` provisions at 0.
	users.raise_kyc_level_to(actor, 1, &AdminAction::system("kyc_level_set"), 0).await.unwrap();
	let before = traces_of(&pool, actor).await;
	let directory = Directory::new(users.clone(), break_glass);

	for level in [1, 3, 0, 4] {
		let err = directory
			.set_kyc_level(request_with(
				&sub,
				SetKycLevelRequest {
					user_id: sub.clone(),
					kyc_level: level,
					reason: String::new(),
				},
			))
			.await
			.unwrap_err();
		assert_eq!(err.code(), Code::PermissionDenied, "setting level {level} on yourself must be refused");
	}

	let me = users.find_by_id(actor).await.unwrap().expect("the operator still exists");
	assert_eq!(me.kyc_level(), 1, "a refused write leaves the level where it was");
	// A refusal that moved nothing but appended a `KYC_CHANGED` would lift the money gate
	// in the OTHER plane, which mirrors the outbox and never re-reads this one. That is
	// the assertion `user_governance.rs` makes about every refused command, and the level
	// alone does not make it.
	assert_eq!(traces_of(&pool, actor).await, before, "a refused write leaves no audit row and no outbox event");

	// And the verb still works — the refusal is about the TARGET, not about the caller.
	let target = subject_of(&users, "kyc-other").await;
	let ok = directory
		.set_kyc_level(request_with(
			&sub,
			SetKycLevelRequest {
				user_id: target,
				kyc_level: 2,
				reason: String::new(),
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(ok.kyc_level, 2);
}

/// #47, on the line #45 draws: the handler guard is a fast path, not the boundary.
///
/// Skip the RPC and call the repository port the way the next writer of a level would —
/// an admin HTTP route, a batch import, a consilium outcome — and the rule must still
/// hold, because a rule that lives in one handler is a rule until somebody adds a second
/// handler.
#[tokio::test]
async fn a_self_targeted_kyc_write_is_refused_beneath_the_handler() {
	let Some((users, _, _)) = setup().await else {
		return;
	};
	let subject = AuthSubject::parse(&format!("kyc-self-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("kyc-self@example.com").unwrap(), true).await.unwrap();
	let other = subject_of(&users, "kyc-writer").await.parse::<Uuid>().map(UserId::from_raw).unwrap();

	let err = users
		.set_kyc_level(user.id(), 1, &AdminAction::by(user.id(), "kyc_level_set", &Default::default()), 0)
		.await
		.unwrap_err();
	assert_eq!(domain_to_status(err).code(), Code::PermissionDenied, "the actor is the subject, whatever surface asked");
	assert_eq!(users.find_by_id(user.id()).await.unwrap().expect("the user survives").kyc_level(), 0);

	// Somebody ELSE writing the same level is the whole point of the verb.
	users.set_kyc_level(user.id(), 1, &AdminAction::by(other, "kyc_level_set", &Default::default()), 0).await.unwrap();
	assert_eq!(users.find_by_id(user.id()).await.unwrap().expect("the user survives").kyc_level(), 1);
}

/// #45: the handler guard above is a fast path, not the boundary. Skip it — call the
/// repository port the way any other writer in this plane would — and the aggregate must
/// still refuse, mapping to `INVALID_ARGUMENT` because the level came from outside.
#[tokio::test]
async fn kyc_level_is_bounded_beneath_the_handler() {
	let Some((users, _, _)) = setup().await else {
		return;
	};
	let subject = AuthSubject::parse(&format!("kyc-bound-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("kyc-bound@example.com").unwrap(), true).await.unwrap();

	for level in [MAX_KYC_LEVEL + 1, 999, u32::MAX] {
		let err = users.set_kyc_level(user.id(), level, &AdminAction::system("kyc_level_set"), 0).await.unwrap_err();
		assert_eq!(domain_to_status(err).code(), Code::InvalidArgument, "level {level} must be refused as bad input");
	}

	let unchanged = users.find_by_id(user.id()).await.unwrap().expect("the user survives a refused write");
	assert_eq!(unchanged.kyc_level(), 0, "a refused write leaves the record alone");
}

/// #45, the last line: with the aggregate out of the picture entirely — a backfill, a
/// console `UPDATE`, the next adapter — the column itself refuses. This is the check that
/// makes the level unreachable rather than merely well-guarded, and the same bound covers
/// `user_outbox`, which is the copy the banking money plane actually mirrors.
#[tokio::test]
async fn kyc_level_out_of_range_is_refused_by_the_store() {
	let Some(url) = common::database_url() else {
		return;
	};
	let pool = db::connect_sized(&url, 2).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users: Arc<dyn UserDirectoryRepository> = Arc::new(PgUsers::new(pool.clone()));

	let subject = AuthSubject::parse(&format!("kyc-store-{}", Uuid::new_v4())).unwrap();
	let user = users.provision(subject, Email::parse("kyc-store@example.com").unwrap(), true).await.unwrap();

	// A negative value matters as much as 999: the column is signed, the domain reads it
	// as `u32`, and -1 would rehydrate as 4294967295 — the largest tier imaginable.
	for level in [-1_i32, 4, 999] {
		let err = sqlx::query("UPDATE users SET kyc_level = $2 WHERE id = $1")
			.bind(user.id().raw())
			.bind(level)
			.execute(&pool)
			.await
			.expect_err("the store must refuse a level no handler would accept");
		assert!(err.to_string().contains("users_kyc_level_range"), "rejected by the range CHECK, not by accident: {err}");
	}

	let outbox = sqlx::query("INSERT INTO user_outbox (user_id, kind, kyc_level, occurred_at, sequence, auth_subject) VALUES ($1, 'KYC_CHANGED', 999, 0, 99, 'bypass')")
		.bind(user.id().raw())
		.execute(&pool)
		.await
		.expect_err("the mirrored copy is bounded too");
	assert!(outbox.to_string().contains("user_outbox_kyc_level_range"), "rejected by the range CHECK: {outbox}");

	let unchanged = users.find_by_id(user.id()).await.unwrap().expect("the user survives");
	assert_eq!(unchanged.kyc_level(), 0);
}

#[tokio::test]
async fn list_users_validates_filters_and_truncates_query() {
	let Some((users, _, _)) = setup().await else {
		return;
	};
	let (sub, break_glass) = admin(&users).await;
	let directory = Directory::new(users, break_glass);
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
	let Some((users, config, _)) = setup().await else {
		return;
	};
	let (sub, break_glass) = admin(&users).await;
	let platform = Platform::new(users, break_glass, config);

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
