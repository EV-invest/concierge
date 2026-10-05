//! Grants over tenant namespaces (`GrantPermission`/`RevokePermission`/`ListGrants`), the
//! permissions `GetMe` resolves from them, and a tenant's `PublishCatalog`, against a REAL
//! Postgres.
//!
//! Every test registers its own tenant (`n_<random>`) and client, so the suite shares a
//! database with the others without reading their rows. Global authority is a persisted
//! `admin`; emergency access is off.

use std::sync::Arc;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	infrastructure::{
		db,
		grants::PgGrants,
		relying_parties::PgRelyingParties,
		users::{AdminAction, PgUsers},
	},
	ports::{GrantOutcome, GrantRepository, RelyingPartyRepository, ScopeActor, ScopeTarget, UserDirectoryRepository},
	relying_party::RelyingParties,
};
use domain::{
	authz::Role,
	iam::Target,
	users::{AuthSubject, Email, UserId},
};
use evconcierge_auth::{CatalogPublication, Claims, ClientGrantError, ClientGrants, RestrictedCaller, TokenType};
use evconcierge_contracts::concierge::v1::{
	GetMeRequest, GrantPermissionRequest, ListGrantsRequest, RevokePermissionRequest, grant_permission_request, revoke_permission_request, user_directory_server::UserDirectory,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::{Code, Request};
use uuid::Uuid;

mod common;

struct Fixture {
	users: Arc<dyn UserDirectoryRepository>,
	pool: PgPool,
	directory: Directory,
	rp: RelyingParties,
	ns: String,
	client: String,
	audience: String,
	secret: String,
}

async fn setup() -> Option<Fixture> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users: Arc<dyn UserDirectoryRepository> = Arc::new(PgUsers::new(pool.clone()));
	let grants = Arc::new(PgGrants::new(pool.clone()));
	let break_glass = Arc::new(BreakGlass::new(Vec::new()));
	let directory = Directory::new(users.clone(), grants.clone(), break_glass.clone());
	let repo = Arc::new(PgRelyingParties::new(pool.clone()));
	let rp = RelyingParties::new(repo.clone(), users.clone(), grants, break_glass, Default::default());

	let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
	let ns = format!("n_{tag}");
	let client = format!("c_{tag}");
	let audience = format!("aud_{tag}");
	let secret = format!("{tag}{tag}{tag}");
	sqlx::query("INSERT INTO tenants (id, namespace, created_at) VALUES ($1, $1, 0)")
		.bind(&ns)
		.execute(&pool)
		.await
		.expect("register the tenant");
	sqlx::query("INSERT INTO rp_clients (client_id, audience, redirect_uris, access_policy, created_at, tenant_id) VALUES ($1, $2, $3, 'public', 0, $4)")
		.bind(&client)
		.bind(&audience)
		.bind(vec![format!("https://{tag}.test/cb")])
		.bind(&ns)
		.execute(&pool)
		.await
		.expect("register the client");
	repo.set_secret_hash(&client, Some(Sha256::digest(secret.as_bytes()).as_slice()), 0)
		.await
		.expect("set the secret");
	let fx = Fixture {
		users,
		pool,
		directory,
		rp,
		ns,
		client,
		audience,
		secret,
	};
	fx.publish(
		1,
		&["work:leads:read", "work:leads:edit", "admin:sources:manage"],
		&[("operator", &["work:leads:read", "work:leads:edit"])],
	)
	.await
	.expect("the first catalog");
	Some(fx)
}

impl Fixture {
	fn p(&self, rest: &str) -> String {
		format!("{}:{rest}", self.ns)
	}

	async fn publish(&self, version: u64, permissions: &[&str], aliases: &[(&str, &[&str])]) -> Result<(), ClientGrantError> {
		self.publish_raw(
			version,
			permissions.iter().map(|p| self.p(p)).collect(),
			aliases.iter().map(|(name, members)| (self.p(name), members.iter().map(|m| self.p(m)).collect())).collect(),
		)
		.await
	}

	async fn publish_raw(&self, version: u64, permissions: Vec<String>, aliases: Vec<(String, Vec<String>)>) -> Result<(), ClientGrantError> {
		self.rp
			.publish_catalog(CatalogPublication {
				client_id: self.client.clone(),
				client_secret: self.secret.clone(),
				version,
				permissions,
				aliases,
			})
			.await
	}

	async fn user(&self, tag: &str) -> UserId {
		let unique = Uuid::new_v4();
		let subject = AuthSubject::parse(&format!("iam-{tag}-{unique}")).unwrap();
		let email = Email::parse(&format!("{tag}-{}@iam.example.com", &unique.simple().to_string()[..12])).unwrap();
		self.users.provision(subject, email, true).await.unwrap().id()
	}

	async fn seated(&self, tag: &str, role: Role) -> UserId {
		let id = self.user(tag).await;
		self.users.set_role(id, role).await.unwrap();
		id
	}

	async fn grant(&self, actor: UserId, user: UserId, target: &str) -> Result<(), tonic::Status> {
		let request = GrantPermissionRequest {
			subject: Some(grant_permission_request::Subject::UserId(user.to_string())),
			target: target.into(),
			reason: "itest".into(),
		};
		self.directory.grant_permission(as_user(actor, "concierge", request)).await.map(drop)
	}

	async fn revoke(&self, actor: UserId, user: UserId, target: &str) -> Result<(), tonic::Status> {
		let request = RevokePermissionRequest {
			subject: Some(revoke_permission_request::Subject::UserId(user.to_string())),
			target: target.into(),
			reason: String::new(),
		};
		self.directory.revoke_permission(as_user(actor, "concierge", request)).await.map(drop)
	}

	/// `GetMe.permissions` as the user's own session sees them.
	async fn mine(&self, user: UserId) -> Vec<String> {
		self.directory.get_me(as_user(user, "concierge", GetMeRequest {})).await.unwrap().into_inner().permissions
	}

	/// `GetMe.permissions` as the tenant's client sees them.
	async fn clients_view(&self, user: UserId) -> Vec<String> {
		let mut request = as_user(user, &self.audience, GetMeRequest {});
		request.extensions_mut().insert(RestrictedCaller);
		self.directory.get_me(request).await.unwrap().into_inner().permissions
	}

	/// `(target, orphaned)` of every active grant in the tenant.
	async fn roster(&self, actor: UserId) -> Vec<(String, bool)> {
		let response = self
			.directory
			.list_grants(as_user(actor, "concierge", ListGrantsRequest { namespace: self.ns.clone() }))
			.await
			.unwrap()
			.into_inner();
		response
			.holders
			.into_iter()
			.map(|holder| {
				let grant = holder.grant.unwrap();
				(grant.target, grant.orphaned)
			})
			.collect()
	}
}

fn as_user<T>(user: UserId, audience: &str, inner: T) -> Request<T> {
	let mut request = Request::new(inner);
	request.extensions_mut().insert(Claims {
		sub: user.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: audience.into(),
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
async fn an_alias_resolves_to_concrete_permissions_and_follows_its_redefinition() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let member = fx.user("member").await;
	fx.grant(admin, member, &fx.p("operator")).await.unwrap();
	assert_eq!(fx.clients_view(member).await, [fx.p("work:leads:edit"), fx.p("work:leads:read")]);

	fx.publish(2, &["work:leads:read", "work:leads:edit", "admin:sources:manage"], &[("operator", &["work:leads:read"])])
		.await
		.unwrap();
	assert_eq!(fx.clients_view(member).await, [fx.p("work:leads:read")], "a republished alias reaches its holders");

	fx.revoke(admin, member, &fx.p("operator")).await.unwrap();
	assert!(fx.clients_view(member).await.is_empty());
	assert_eq!(code(fx.revoke(admin, member, &fx.p("operator")).await), Code::NotFound);
}

#[tokio::test]
async fn a_client_reads_its_own_namespace_and_a_session_reads_the_seat_too() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let operator = fx.seated("operator", Role::Operator).await;
	fx.grant(admin, operator, &fx.p("work:*")).await.unwrap();

	assert_eq!(
		fx.clients_view(operator).await,
		[fx.p("work:leads:edit"), fx.p("work:leads:read")],
		"no seat permission reaches a client"
	);
	let mine = fx.mine(operator).await;
	assert!(mine.contains(&"concierge:user:read".to_owned()) && mine.contains(&"bank:treasury:read".to_owned()), "{mine:?}");
	assert!(mine.contains(&fx.p("work:leads:read")));
	assert!(!mine.contains(&"bank:payment:open".to_owned()), "an operator seat views and never acts");

	// A seat that may grant everything in a tenant holds everything in it.
	assert_eq!(fx.clients_view(admin).await.len(), 3);
}

#[tokio::test]
async fn nothing_outside_a_tenant_namespace_is_grantable() {
	let Some(fx) = setup().await else { return };
	let owner_like = fx.seated("admin", Role::Admin).await;
	let member = fx.user("member").await;
	for target in [
		"iam:tenants:grant",
		"iam:*",
		"concierge:*",
		"concierge:role:grant",
		"bank:*",
		"bank:payment:open",
		"seat:owner",
		"owner",
		"admin",
	] {
		assert_eq!(code(fx.grant(owner_like, member, target).await), Code::InvalidArgument, "{target}");
	}
	assert_eq!(code(fx.grant(owner_like, member, "nobody_owns_this:x:y").await), Code::InvalidArgument, "an unknown tenant");
	assert_eq!(
		code(fx.grant(owner_like, member, &fx.p("work:gone:read")).await),
		Code::InvalidArgument,
		"a target the catalog does not define"
	);
	assert!(fx.mine(member).await.is_empty());
}

#[tokio::test]
async fn only_a_seat_holding_the_grant_permission_grants() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let operator = fx.seated("operator", Role::Operator).await;
	let holder = fx.user("holder").await;
	let member = fx.user("member").await;
	fx.grant(admin, holder, &fx.p("*")).await.unwrap();

	assert_eq!(code(fx.grant(operator, member, &fx.p("operator")).await), Code::PermissionDenied, "an operator seat");
	assert_eq!(
		code(fx.grant(holder, member, &fx.p("operator")).await),
		Code::PermissionDenied,
		"holding all of a tenant is not granting it"
	);
	assert_eq!(code(fx.revoke(holder, admin, &fx.p("*")).await), Code::PermissionDenied);
	let listed = fx.directory.list_grants(as_user(holder, "concierge", ListGrantsRequest { namespace: fx.ns.clone() })).await;
	assert_eq!(code(listed), Code::PermissionDenied);
}

#[tokio::test]
async fn the_write_decides_from_the_actors_persisted_seat() {
	let Some(fx) = setup().await else { return };
	let grants = PgGrants::new(fx.pool.clone());
	let member = fx.user("member").await;
	let demoted = fx.user("demoted").await;
	let stale = ScopeActor {
		id: demoted,
		role: Role::Admin,
		elevated: false,
	};
	let action = AdminAction {
		actor: Some(demoted),
		action: "permission_granted",
		..AdminAction::default()
	};
	let target = Target::parse(&fx.p("operator")).unwrap();
	let outcome = grants.grant(&ScopeTarget::Id(member), &target, &stale, &action, 0).await.unwrap();
	assert!(matches!(outcome, GrantOutcome::Denied), "the gate said admin, the row says investor");
}

#[tokio::test]
async fn a_disabled_ambiguous_or_unknown_account_is_not_granted() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let held = fx.user("held").await;
	fx.users.disable_user(held).await.unwrap();
	assert_eq!(code(fx.grant(admin, held, &fx.p("operator")).await), Code::FailedPrecondition);
	assert_eq!(code(fx.grant(admin, UserId::from_raw(Uuid::new_v4()), &fx.p("operator")).await), Code::NotFound);

	let email = format!("shared-{}@iam.example.com", Uuid::new_v4().simple());
	for _ in 0..2 {
		let subject = AuthSubject::parse(&format!("iam-shared-{}", Uuid::new_v4())).unwrap();
		fx.users.provision(subject, Email::parse(&email).unwrap(), true).await.unwrap();
	}
	let request = GrantPermissionRequest {
		subject: Some(grant_permission_request::Subject::Email(email)),
		target: fx.p("operator"),
		reason: String::new(),
	};
	assert_eq!(code(fx.directory.grant_permission(as_user(admin, "concierge", request)).await), Code::FailedPrecondition);
}

#[tokio::test]
async fn a_grant_is_audited_and_regranting_writes_nothing() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let member = fx.user("member").await;
	fx.grant(admin, member, &fx.p("operator")).await.unwrap();
	fx.grant(admin, member, &fx.p("operator")).await.unwrap();
	let rows: Vec<(String, Option<String>)> = sqlx::query_as("SELECT target, reason FROM grants WHERE user_id = $1")
		.bind(member.raw())
		.fetch_all(&fx.pool)
		.await
		.unwrap();
	assert_eq!(rows, [(fx.p("operator"), Some("itest".to_owned()))]);
	let audit: Vec<(String, Option<Uuid>, String)> = sqlx::query_as("SELECT action, actor_user_id, reason FROM admin_action WHERE subject_user_id = $1 ORDER BY position")
		.bind(member.raw())
		.fetch_all(&fx.pool)
		.await
		.unwrap();
	assert_eq!(audit, [("permission_granted".to_owned(), Some(admin.raw()), "itest".to_owned())]);
}

#[tokio::test]
async fn a_catalog_stays_inside_its_namespace_and_only_moves_forward() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let member = fx.user("member").await;
	fx.grant(admin, member, &fx.p("operator")).await.unwrap();

	let outside = fx.publish_raw(5, vec![fx.p("work:leads:read")], vec![(fx.p("operator"), vec!["bank:payment:open".into()])]).await;
	assert!(matches!(outside, Err(ClientGrantError::InvalidCatalog(_))), "an alias reaching into bank:*");
	let foreign = fx.publish_raw(5, vec!["bank:payment:open".into()], vec![]).await;
	assert!(matches!(foreign, Err(ClientGrantError::InvalidCatalog(_))), "a permission of another namespace");
	let seat = fx.publish_raw(5, vec![fx.p("work:leads:read")], vec![("seat:admin".into(), vec![fx.p("work:leads:read")])]).await;
	assert!(matches!(seat, Err(ClientGrantError::InvalidCatalog(_))), "an alias named outside the namespace");

	assert!(matches!(fx.publish(0, &["work:leads:read"], &[]).await, Err(ClientGrantError::StaleCatalog(_))), "a rollback");
	assert!(
		matches!(fx.publish(1, &["work:leads:read"], &[]).await, Err(ClientGrantError::StaleCatalog(_))),
		"the same version, different content"
	);
	fx.publish(
		1,
		&["work:leads:read", "work:leads:edit", "admin:sources:manage"],
		&[("operator", &["work:leads:read", "work:leads:edit"])],
	)
	.await
	.expect("republishing what is stored is a no-op");

	let mut wrong = fx.rp.publish_catalog(CatalogPublication {
		client_id: fx.client.clone(),
		client_secret: "not-the-secret-not-the-secret-xx".into(),
		version: 9,
		permissions: vec![],
		aliases: vec![],
	});
	assert!(matches!((&mut wrong).await, Err(ClientGrantError::InvalidClient)));

	fx.publish(2, &["work:leads:read"], &[]).await.unwrap();
	assert_eq!(fx.roster(admin).await, [(fx.p("operator"), true)], "a grant whose alias vanished stays, orphaned");
	assert!(fx.clients_view(member).await.is_empty(), "and grants nothing");
}
