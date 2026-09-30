//! Integration tests for scoped grants over the `UserDirectory` gRPC handlers:
//! `GrantScope`, `RevokeScope`, `ListScopedGrants` and `GetMe.scopes`, against a REAL
//! Postgres (no mocks, per the project rules).
//!
//! Every test mints its own users and its own scope (`allocation:itest_<random>`), so the
//! suite shares a database with the others without reading their rows. No test here
//! touches the owner registry: global authority is exercised through a persisted
//! `admin`, and emergency access is off (empty `BreakGlass`), so a leftover owner from
//! another suite cannot change an outcome here.

use std::sync::Arc;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	infrastructure::{
		db,
		scoped_grants::PgScopedGrants,
		users::{AdminAction, PgUsers},
	},
	ports::{ScopeActor, ScopeGrantOutcome, ScopeRevokeOutcome, ScopeTarget, ScopedGrantRepository, UserDirectoryRepository},
};
use domain::{
	authz::Role,
	scopes::{Scope, ScopeRole},
	users::{AuthSubject, Email, ProfileFields, UserId},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	GetMeRequest, GrantScopeRequest, ListScopedGrantsRequest, RevokeScopeRequest, grant_scope_request, revoke_scope_request, user_directory_server::UserDirectory,
};
use sqlx::PgPool;
use tonic::{Code, Request};
use uuid::Uuid;

mod common;

struct Fixture {
	users: Arc<dyn UserDirectoryRepository>,
	pool: PgPool,
	directory: Directory,
	scope: String,
}

/// The suite's preconditions, or `None` when there is no database to assert against —
/// see [`common::database_url`] for why a skip is loud under CI.
async fn setup() -> Option<Fixture> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users: Arc<dyn UserDirectoryRepository> = Arc::new(PgUsers::new(pool.clone()));
	let directory = Directory::new(users.clone(), Arc::new(PgScopedGrants::new(pool.clone())), Arc::new(BreakGlass::new(Vec::new())));
	Some(Fixture {
		users,
		pool,
		directory,
		scope: fresh_scope(),
	})
}

fn fresh_scope() -> String {
	format!("allocation:itest_{}", &Uuid::new_v4().simple().to_string()[..12])
}

impl Fixture {
	async fn user(&self, tag: &str) -> UserId {
		let unique = Uuid::new_v4();
		let subject = AuthSubject::parse(&format!("scopes-{tag}-{unique}")).unwrap();
		let email = Email::parse(&format!("{tag}-{}@scopes.example.com", &unique.simple().to_string()[..12])).unwrap();
		self.users.provision(subject, email, true).await.unwrap().id()
	}

	async fn email_of(&self, user: UserId) -> String {
		sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.expect("read email")
	}

	async fn global_admin(&self) -> UserId {
		let id = self.user("global-admin").await;
		self.users.set_role(id, Role::Admin).await.unwrap();
		id
	}

	/// Grant by EMAIL — the one form every manager may use.
	async fn grant(&self, actor: UserId, target: UserId, scope: &str, role: &str) -> Result<(), tonic::Status> {
		let email = self.email_of(target).await;
		self.grant_to(actor, grant_scope_request::Target::Email(email), scope, role).await
	}

	/// Grant by USER ID — a global manager's form only.
	async fn grant_by_id(&self, actor: UserId, target: UserId, scope: &str, role: &str) -> Result<(), tonic::Status> {
		self.grant_to(actor, grant_scope_request::Target::UserId(target.to_string()), scope, role).await
	}

	async fn grant_to(&self, actor: UserId, target: grant_scope_request::Target, scope: &str, role: &str) -> Result<(), tonic::Status> {
		let request = GrantScopeRequest {
			target: Some(target),
			scope: scope.into(),
			role: role.into(),
			reason: "itest".into(),
		};
		self.directory.grant_scope(as_user(actor, request)).await.map(drop)
	}

	async fn revoke(&self, actor: UserId, target: UserId, scope: &str) -> Result<(), tonic::Status> {
		self.revoke_target(actor, revoke_scope_request::Target::UserId(target.to_string()), scope).await
	}

	async fn revoke_target(&self, actor: UserId, target: revoke_scope_request::Target, scope: &str) -> Result<(), tonic::Status> {
		let request = RevokeScopeRequest {
			target: Some(target),
			scope: scope.into(),
			reason: String::new(),
		};
		self.directory.revoke_scope(as_user(actor, request)).await.map(drop)
	}

	async fn list(&self, actor: UserId, scope: &str) -> Result<Vec<(String, String, String)>, tonic::Status> {
		let response = self
			.directory
			.list_scoped_grants(as_user(actor, ListScopedGrantsRequest { scope: scope.into() }))
			.await?
			.into_inner();
		Ok(response
			.holders
			.into_iter()
			.map(|holder| {
				let grant = holder.grant.expect("every holder carries its grant");
				(grant.user_id, grant.role, holder.email)
			})
			.collect())
	}

	/// The caller's `GetMe.scopes`, as `(scope, role)`.
	async fn my_scopes(&self, user: UserId) -> Vec<(String, String)> {
		let me = self.directory.get_me(as_user(user, GetMeRequest {})).await.unwrap().into_inner();
		me.scopes.into_iter().map(|grant| (grant.scope, grant.role)).collect()
	}

	/// Every row ever written for `user` on the fixture's scope, active or not, oldest first.
	async fn history(&self, user: UserId) -> Vec<(String, bool)> {
		sqlx::query_as::<_, (String, bool)>("SELECT role, revoked_at IS NOT NULL FROM scoped_grants WHERE user_id = $1 AND scope = $2 ORDER BY id")
			.bind(user.raw())
			.bind(&self.scope)
			.fetch_all(&self.pool)
			.await
			.expect("read scoped_grants")
	}

	async fn audit(&self, subject: UserId) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
		sqlx::query_as::<_, (String, Option<Uuid>, serde_json::Value)>(
			"SELECT action, actor_user_id, detail FROM admin_action WHERE subject_user_id = $1 AND action LIKE 'scope_%' ORDER BY position",
		)
		.bind(subject.raw())
		.fetch_all(&self.pool)
		.await
		.expect("read admin_action")
	}
}

fn as_user<T>(user: UserId, inner: T) -> Request<T> {
	let mut request = Request::new(inner);
	request.extensions_mut().insert(Claims {
		sub: user.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
	});
	request
}

fn code(result: Result<impl Sized, tonic::Status>) -> Code {
	match result {
		Ok(_) => Code::Ok,
		Err(status) => status.code(),
	}
}

#[tokio::test]
async fn a_scope_admin_cannot_grant_admin() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let scope_admin = fx.user("scope-admin").await;
	let newcomer = fx.user("newcomer").await;
	let operator = fx.user("operator").await;
	fx.grant(global, scope_admin, &fx.scope, "admin").await.unwrap();
	fx.grant(scope_admin, operator, &fx.scope, "operator").await.unwrap();

	assert_eq!(code(fx.grant(scope_admin, newcomer, &fx.scope, "admin").await), Code::PermissionDenied, "minting a scope admin");
	assert_eq!(
		code(fx.grant(scope_admin, operator, &fx.scope, "admin").await),
		Code::PermissionDenied,
		"promoting an operator to admin"
	);

	assert!(fx.history(newcomer).await.is_empty(), "a refusal writes no grant");
	assert_eq!(fx.history(operator).await, vec![("operator".into(), false)], "the operator's grant is untouched");
	assert!(fx.audit(newcomer).await.is_empty(), "a refusal writes no audit row");
}

#[tokio::test]
async fn a_scope_admin_cannot_touch_another_admin_grant() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let first = fx.user("first-admin").await;
	let second = fx.user("second-admin").await;
	fx.grant(global, first, &fx.scope, "admin").await.unwrap();
	fx.grant(global, second, &fx.scope, "admin").await.unwrap();

	assert_eq!(code(fx.grant(first, second, &fx.scope, "operator").await), Code::PermissionDenied, "demoting an admin");
	assert_eq!(code(fx.revoke(first, second, &fx.scope).await), Code::PermissionDenied, "revoking an admin");
	assert_eq!(code(fx.revoke(first, first, &fx.scope).await), Code::PermissionDenied, "not even their own admin grant");
	assert_eq!(fx.history(second).await, vec![("admin".into(), false)]);
}

#[tokio::test]
async fn a_scope_admin_manages_operators_in_their_own_scope_only() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let scope_admin = fx.user("scope-admin").await;
	let member = fx.user("member").await;
	fx.grant(global, scope_admin, &fx.scope, "admin").await.unwrap();

	fx.grant(scope_admin, member, &fx.scope, "operator").await.unwrap();
	assert_eq!(fx.my_scopes(member).await, vec![(fx.scope.clone(), "operator".into())]);

	let elsewhere = fresh_scope();
	assert_eq!(
		code(fx.grant(scope_admin, member, &elsewhere, "operator").await),
		Code::PermissionDenied,
		"another scope is not theirs"
	);
	assert_eq!(code(fx.list(scope_admin, &elsewhere).await), Code::PermissionDenied, "nor is its roster");

	fx.revoke(scope_admin, member, &fx.scope).await.unwrap();
	assert!(fx.my_scopes(member).await.is_empty(), "a revoked grant leaves GetMe");
	assert_eq!(fx.history(member).await, vec![("operator".into(), true)], "the grant is kept as history, no longer active");
}

#[tokio::test]
async fn a_global_admin_grants_any_role_and_the_history_and_audit_record_it() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let member = fx.user("member").await;

	fx.grant(global, member, &fx.scope, "operator").await.unwrap();
	fx.grant(global, member, &fx.scope, "admin").await.unwrap();
	// Re-granting what is held is a no-op: no history row, no audit row.
	fx.grant(global, member, &fx.scope, "admin").await.unwrap();

	assert_eq!(fx.history(member).await, vec![("operator".into(), true), ("admin".into(), false)]);
	assert_eq!(fx.my_scopes(member).await, vec![(fx.scope.clone(), "admin".into())]);

	let audit = fx.audit(member).await;
	assert_eq!(audit.len(), 2, "one audit row per change: {audit:?}");
	assert_eq!(audit[0].0, "scope_granted");
	assert_eq!(audit[0].1, Some(global.raw()), "the actor is recorded");
	assert_eq!(audit[0].2["role"], "operator");
	assert_eq!(audit[0].2["previous_role"], serde_json::Value::Null);
	assert_eq!(audit[1].2["role"], "admin");
	assert_eq!(audit[1].2["previous_role"], "operator");
	assert_eq!(audit[1].2["scope"], fx.scope.as_str());

	fx.revoke(global, member, &fx.scope).await.unwrap();
	let audit = fx.audit(member).await;
	assert_eq!(audit.last().map(|row| row.0.as_str()), Some("scope_revoked"));
	assert_eq!(audit.last().unwrap().2["role"], "admin");
}

#[tokio::test]
async fn everyone_else_is_denied_before_learning_whether_the_target_exists() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let investor = fx.user("investor").await;
	let console_operator = fx.user("console-operator").await;
	fx.users.set_role(console_operator, Role::Operator).await.unwrap();
	let scope_operator = fx.user("scope-operator").await;
	fx.grant(global, scope_operator, &fx.scope, "operator").await.unwrap();
	let target = fx.user("target").await;
	let nobody = UserId::from_raw(Uuid::new_v4());

	for outsider in [investor, console_operator, scope_operator] {
		assert_eq!(code(fx.grant(outsider, target, &fx.scope, "operator").await), Code::PermissionDenied);
		assert_eq!(code(fx.grant_by_id(outsider, nobody, &fx.scope, "operator").await), Code::PermissionDenied, "not NOT_FOUND");
		assert_eq!(code(fx.revoke(outsider, scope_operator, &fx.scope).await), Code::PermissionDenied);
		assert_eq!(code(fx.list(outsider, &fx.scope).await), Code::PermissionDenied);
	}
	assert!(fx.history(target).await.is_empty());

	assert_eq!(
		code(fx.grant_by_id(global, nobody, &fx.scope, "operator").await),
		Code::NotFound,
		"an unknown user, to someone entitled to know"
	);
	assert_eq!(code(fx.revoke(global, target, &fx.scope).await), Code::NotFound, "no active grant to revoke");
}

/// `viewer` was a scope role until 0024 removed it: a read-only holder is an ordinary
/// user and gets no grant. A client still sending it must hear "unknown role", from the
/// top of the matrix and from a scope admin alike, and nothing may be written.
#[tokio::test]
async fn granting_the_removed_viewer_role_is_invalid_argument() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let scope_admin = fx.user("scope-admin").await;
	let member = fx.user("member").await;
	fx.grant(global, scope_admin, &fx.scope, "admin").await.unwrap();

	assert_eq!(code(fx.grant(global, member, &fx.scope, "viewer").await), Code::InvalidArgument, "from a global admin");
	assert_eq!(code(fx.grant(scope_admin, member, &fx.scope, "viewer").await), Code::InvalidArgument, "from the scope's admin");
	assert!(fx.history(member).await.is_empty(), "a refused role writes no grant");
	assert!(fx.audit(member).await.is_empty(), "nor an audit row");
}

#[tokio::test]
async fn malformed_scopes_roles_and_ids_are_invalid_argument() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let member = fx.user("member").await;
	for scope in ["", "allocation:", "allocation:Service_Arb", "allocation:service-arb", "fund:service_arb", "service_arb"] {
		assert_eq!(code(fx.grant(global, member, scope, "operator").await), Code::InvalidArgument, "scope {scope:?}");
		assert_eq!(code(fx.revoke(global, member, scope).await), Code::InvalidArgument, "scope {scope:?}");
		assert_eq!(code(fx.list(global, scope).await), Code::InvalidArgument, "scope {scope:?}");
	}
	for role in ["", "owner", "Admin"] {
		assert_eq!(code(fx.grant(global, member, &fx.scope, role).await), Code::InvalidArgument, "role {role:?}");
	}
	let bad_id = grant_scope_request::Target::UserId("not-a-uuid".into());
	assert_eq!(code(fx.grant_to(global, bad_id, &fx.scope, "operator").await), Code::InvalidArgument);
	let bad_email = grant_scope_request::Target::Email("nobody".into());
	assert_eq!(code(fx.grant_to(global, bad_email, &fx.scope, "operator").await), Code::InvalidArgument);
	let no_target = GrantScopeRequest {
		target: None,
		scope: fx.scope.clone(),
		role: "operator".into(),
		reason: String::new(),
	};
	assert_eq!(code(fx.directory.grant_scope(as_user(global, no_target)).await), Code::InvalidArgument);
}

#[tokio::test]
async fn the_roster_carries_each_holders_identity_and_is_visible_to_its_admin() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let scope_admin = fx.user("roster-admin").await;
	let member = fx.user("roster-member").await;
	let names = ProfileFields::parse(ProfileFields {
		legal_name: Some("Ada Lovelace".into()),
		preferred_name: Some("Ada".into()),
		..ProfileFields::default()
	})
	.unwrap();
	fx.users.update_profile(member, names).await.unwrap();
	fx.grant(global, scope_admin, &fx.scope, "admin").await.unwrap();
	fx.grant(scope_admin, member, &fx.scope, "operator").await.unwrap();

	let roster = fx
		.directory
		.list_scoped_grants(as_user(scope_admin, ListScopedGrantsRequest { scope: fx.scope.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(roster.holders.len(), 2, "exactly this scope's active holders");
	let row = roster
		.holders
		.iter()
		.find(|holder| holder.grant.as_ref().unwrap().user_id == member.to_string())
		.expect("the member is listed");
	assert_eq!(row.email, fx.email_of(member).await);
	assert_eq!(row.legal_name, "", "the legal name stays with staff");
	assert_eq!(row.preferred_name, "Ada");
	let grant = row.grant.as_ref().unwrap();
	assert_eq!(grant.role, "operator");
	assert_eq!(grant.scope, fx.scope);
	assert_eq!(grant.granted_by, scope_admin.to_string());

	let as_staff = fx
		.directory
		.list_scoped_grants(as_user(global, ListScopedGrantsRequest { scope: fx.scope.clone() }))
		.await
		.unwrap()
		.into_inner();
	let staff_row = as_staff.holders.iter().find(|holder| holder.grant.as_ref().unwrap().user_id == member.to_string()).unwrap();
	assert_eq!(staff_row.legal_name, "Ada Lovelace", "a global admin sees the legal name");
	assert_eq!(staff_row.preferred_name, "Ada");
	fx.revoke(scope_admin, member, &fx.scope).await.unwrap();
	assert_eq!(fx.list(global, &fx.scope).await.unwrap().len(), 1, "a revoked grant leaves the roster");
}

#[tokio::test]
async fn get_me_reports_only_the_callers_active_grants() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let member = fx.user("member").await;
	let other = fx.user("other").await;
	let second = fresh_scope();
	fx.grant(global, member, &fx.scope, "operator").await.unwrap();
	fx.grant(global, member, &second, "admin").await.unwrap();
	fx.grant(global, other, &fx.scope, "admin").await.unwrap();

	let mut mine = fx.my_scopes(member).await;
	mine.sort();
	let mut expected = vec![(fx.scope.clone(), "operator".to_string()), (second.clone(), "admin".to_string())];
	expected.sort();
	assert_eq!(mine, expected);
	assert!(fx.my_scopes(global).await.is_empty(), "a global role is not folded into scopes");
}

#[tokio::test]
async fn the_table_itself_refuses_a_second_active_grant_and_a_malformed_scope() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let member = fx.user("member").await;
	fx.grant(global, member, &fx.scope, "operator").await.unwrap();
	let insert = |scope: String, role: &'static str| {
		sqlx::query("INSERT INTO scoped_grants (user_id, scope, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, 0)")
			.bind(member.raw())
			.bind(scope)
			.bind(role)
			.bind(global.raw())
			.execute(&fx.pool)
	};
	let duplicate = insert(fx.scope.clone(), "operator").await.expect_err("one active grant per (user, scope)");
	assert!(duplicate.to_string().contains("scoped_grants_active_idx"), "{duplicate}");
	let malformed = insert("allocation:Nope".into(), "operator").await.expect_err("the scope format is a column rule too");
	assert!(malformed.to_string().contains("scoped_grants_scope_format"), "{malformed}");
}

#[tokio::test]
async fn a_scope_admin_must_address_a_grant_by_email_not_by_id() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let scope_admin = fx.user("scope-admin").await;
	let staffer = fx.user("staffer").await;
	fx.grant(global, scope_admin, &fx.scope, "admin").await.unwrap();

	// The bare-id route is the PII oracle: grant an operator to an id seen in `granted_by`,
	// then read the address off the roster.
	assert_eq!(
		code(fx.grant_by_id(scope_admin, global, &fx.scope, "operator").await),
		Code::PermissionDenied,
		"not a staffer's id"
	);
	assert_eq!(code(fx.grant_by_id(scope_admin, staffer, &fx.scope, "operator").await), Code::PermissionDenied, "not anyone's id");
	assert_eq!(
		code(fx.grant_by_id(scope_admin, UserId::from_raw(Uuid::new_v4()), &fx.scope, "operator").await),
		Code::PermissionDenied,
		"nor an unknown one"
	);
	assert!(fx.history(staffer).await.is_empty(), "a refused id grant writes nothing");
	assert_eq!(fx.list(scope_admin, &fx.scope).await.unwrap().len(), 1, "the roster holds only the scope admin");

	fx.grant(scope_admin, staffer, &fx.scope, "operator").await.expect("by email, the address they already know");
	assert_eq!(fx.my_scopes(staffer).await, vec![(fx.scope.clone(), "operator".into())]);

	let unknown = grant_scope_request::Target::Email(format!("nobody-{}@scopes.example.com", Uuid::new_v4().simple()));
	assert_eq!(code(fx.grant_to(scope_admin, unknown, &fx.scope, "operator").await), Code::NotFound, "an address nobody holds");

	// A global admin keeps both forms.
	let other = fx.user("other").await;
	fx.grant_by_id(global, other, &fx.scope, "operator").await.expect("a global admin may address by id");
}

#[tokio::test]
async fn a_scope_admin_revokes_by_either_form_and_learns_nothing_from_a_stranger_id() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let scope_admin = fx.user("scope-admin").await;
	let first = fx.user("first").await;
	let second = fx.user("second").await;
	let stranger = fx.user("stranger").await;
	fx.grant(global, scope_admin, &fx.scope, "admin").await.unwrap();
	fx.grant(scope_admin, first, &fx.scope, "operator").await.unwrap();
	fx.grant(scope_admin, second, &fx.scope, "operator").await.unwrap();

	fx.revoke(scope_admin, first, &fx.scope).await.expect("by the id the roster hands back");
	let by_email = revoke_scope_request::Target::Email(fx.email_of(second).await);
	fx.revoke_target(scope_admin, by_email, &fx.scope).await.expect("by email");
	assert_eq!(fx.list(scope_admin, &fx.scope).await.unwrap().len(), 1);

	// A real account outside the scope and an id nobody holds answer alike.
	assert_eq!(code(fx.revoke(scope_admin, stranger, &fx.scope).await), Code::NotFound);
	assert_eq!(code(fx.revoke(scope_admin, UserId::from_raw(Uuid::new_v4()), &fx.scope).await), Code::NotFound);
}

#[tokio::test]
async fn a_disabled_account_is_not_granted_access() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let target = fx.user("disabled").await;
	fx.users.disable_user(target).await.unwrap();

	assert_eq!(code(fx.grant(global, target, &fx.scope, "operator").await), Code::FailedPrecondition);
	assert_eq!(code(fx.grant_by_id(global, target, &fx.scope, "operator").await), Code::FailedPrecondition);
	assert!(fx.history(target).await.is_empty());
}

#[tokio::test]
async fn an_email_shared_by_two_accounts_names_nobody() {
	let Some(fx) = setup().await else {
		return;
	};
	let global = fx.global_admin().await;
	let email = format!("shared-{}@scopes.example.com", Uuid::new_v4().simple());
	for _ in 0..2 {
		let subject = AuthSubject::parse(&format!("scopes-shared-{}", Uuid::new_v4())).unwrap();
		fx.users.provision(subject, Email::parse(&email).unwrap(), true).await.unwrap();
	}
	let target = grant_scope_request::Target::Email(email.to_uppercase());
	assert_eq!(code(fx.grant_to(global, target, &fx.scope, "operator").await), Code::FailedPrecondition);
	let holders: i64 = sqlx::query_scalar("SELECT count(*) FROM scoped_grants WHERE scope = $1")
		.bind(&fx.scope)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(holders, 0);
}

/// The RPC gate resolves the actor's role before the write transaction opens. A demotion
/// or a suspension committed in between must be SEEN by the write, which re-reads the
/// actor's row under its lock — so the adapter is driven here with a deliberately stale
/// gate role, the state that window produces.
#[tokio::test]
async fn the_write_decides_from_the_actors_persisted_role_not_the_gates() {
	let Some(fx) = setup().await else {
		return;
	};
	let repo = PgScopedGrants::new(fx.pool.clone());
	let scope = Scope::parse(&fx.scope).unwrap();
	let target = fx.user("target").await;
	let target_ref = ScopeTarget::Id(target);

	let demoted = fx.user("demoted").await;
	let stale = ScopeActor {
		id: demoted,
		role: Role::Admin,
		elevated: false,
	};
	let action = AdminAction {
		actor: Some(demoted),
		action: "scope_granted",
		..AdminAction::default()
	};
	let outcome = repo.grant(&target_ref, &scope, ScopeRole::Operator, &stale, &action, 0).await.unwrap();
	assert!(matches!(outcome, ScopeGrantOutcome::Denied), "the gate said admin, the row says investor");
	assert!(matches!(repo.revoke(&target_ref, &scope, &stale, &action, 0).await.unwrap(), ScopeRevokeOutcome::Denied));

	let suspended = fx.global_admin().await;
	fx.users.disable_user(suspended).await.unwrap();
	let suspended_actor = ScopeActor {
		id: suspended,
		role: Role::Admin,
		elevated: false,
	};
	let outcome = repo.grant(&target_ref, &scope, ScopeRole::Operator, &suspended_actor, &action, 0).await.unwrap();
	assert!(matches!(outcome, ScopeGrantOutcome::Denied), "a disabled actor acts with nothing");
	assert!(fx.history(target).await.is_empty());

	// Emergency access is the one elevation no row records, so it is carried explicitly.
	let elevated = fx.user("elevated").await;
	let actor = ScopeActor {
		id: elevated,
		role: Role::Owner,
		elevated: true,
	};
	let outcome = repo.grant(&target_ref, &scope, ScopeRole::Operator, &actor, &action, 0).await.unwrap();
	assert!(matches!(outcome, ScopeGrantOutcome::Granted(_)), "break-glass elevation still counts inside the transaction");
}
