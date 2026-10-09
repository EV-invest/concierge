//! Grants over tenant namespaces (`GrantPermission`/`RevokePermission`/`ListGrants`), the
//! permissions `GetMe` resolves from them, and a tenant's `PublishCatalog`, against a REAL
//! Postgres.
//!
//! Every test registers its own tenant (`n_<random>`) and client, so the suite shares a
//! database with the others without reading their rows. The tenant's `admin` alias
//! delegates `operator`. Seat authority is a persisted `admin`; emergency access is off.

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
	ports::{GrantActor, GrantOutcome, GrantRepository, GrantSubject, RelyingPartyRepository, RevokeOutcome, UserDirectoryRepository},
	relying_party::RelyingParties,
};
use domain::{authz::Role, iam::Target, users::UserId};
use evconcierge_auth::{CatalogPublication, Claims, ClientGrantError, ClientGrants, RestrictedCaller, TokenType};
use evconcierge_contracts::concierge::v1::{
	CatalogAlias, GetMeRequest, GrantPermissionRequest, ListGrantsRequest, RevokePermissionRequest, grant_permission_request, revoke_permission_request, user_directory_server::UserDirectory,
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

/// How a request names its subject.
#[derive(Clone)]
enum Who {
	Id(UserId),
	Email(String),
}

const PERMISSIONS: [&str; 3] = ["work:leads:read", "work:leads:edit", "admin:sources:manage"];

async fn setup() -> Option<Fixture> {
	tenant(true).await
}

async fn tenant(granting_seats_hold_all: bool) -> Option<Fixture> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users: Arc<dyn UserDirectoryRepository> = Arc::new(PgUsers::new(pool.clone()));
	let grants = Arc::new(PgGrants::new(pool.clone()));
	let directory = Directory::new(users.clone(), grants.clone(), Arc::new(BreakGlass::new(Vec::new())));
	let repo = Arc::new(PgRelyingParties::new(pool.clone()));
	let rp = RelyingParties::new(repo.clone(), users.clone(), grants, Default::default());

	let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
	let ns = format!("n_{tag}");
	let client = format!("c_{tag}");
	let audience = format!("aud_{tag}");
	let secret = format!("{tag}{tag}{tag}");
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ($1, $1, $2, 0)")
		.bind(&ns)
		.bind(granting_seats_hold_all)
		.execute(&pool)
		.await
		.expect("register the tenant");
	sqlx::query("INSERT INTO rp_clients (client_id, audience, redirect_uris, created_at, tenant_id) VALUES ($1, $2, $3, 0, $4)")
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
	fx.publish_initial(1).await.expect("the first catalog");
	Some(fx)
}

impl Fixture {
	fn p(&self, rest: &str) -> String {
		format!("{}:{rest}", self.ns)
	}

	/// `operator` = the two lead permissions; `admin` = all three and delegates `operator`.
	async fn publish_initial(&self, version: u64) -> Result<(), ClientGrantError> {
		self.publish(
			version,
			&PERMISSIONS,
			&[("operator", &["work:leads:read", "work:leads:edit"], &[]), ("admin", &PERMISSIONS, &["operator"])],
		)
		.await
	}

	async fn publish(&self, version: u64, permissions: &[&str], aliases: &[(&str, &[&str], &[&str])]) -> Result<(), ClientGrantError> {
		self.publish_raw(
			version,
			permissions.iter().map(|p| self.p(p)).collect(),
			aliases
				.iter()
				.map(|(name, members, delegates)| CatalogAlias {
					name: self.p(name),
					members: members.iter().map(|m| self.p(m)).collect(),
					delegates: delegates.iter().map(|d| self.p(d)).collect(),
				})
				.collect(),
		)
		.await
	}

	async fn publish_raw(&self, version: u64, permissions: Vec<String>, aliases: Vec<CatalogAlias>) -> Result<(), ClientGrantError> {
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
		let email = format!("{tag}-{}@iam.example.com", &unique.simple().to_string()[..12]);
		self.users.resolve(common::google_as(&format!("iam-{tag}-{unique}"), &email, true), 0).await.unwrap().id()
	}

	async fn seated(&self, tag: &str, role: Role) -> UserId {
		let id = self.user(tag).await;
		self.users.set_role(id, role).await.unwrap();
		id
	}

	/// A holder of the tenant's `admin` alias, granted by a seat.
	async fn delegate(&self) -> UserId {
		let seat = self.seated("seat", Role::Admin).await;
		let delegate = self.user("delegate").await;
		self.grant(seat, delegate, &self.p("admin")).await.unwrap();
		delegate
	}

	async fn email_of(&self, user: UserId) -> String {
		self.users.find_by_id(user).await.unwrap().unwrap().email().as_str().to_owned()
	}

	async fn grant_to(&self, actor: UserId, who: Who, target: &str) -> Result<(), tonic::Status> {
		let request = GrantPermissionRequest {
			subject: Some(match who {
				Who::Id(id) => grant_permission_request::Subject::UserId(id.to_string()),
				Who::Email(email) => grant_permission_request::Subject::Email(email),
			}),
			target: target.into(),
			reason: "itest".into(),
		};
		self.directory.grant_permission(as_user(actor, "concierge", request)).await.map(drop)
	}

	async fn revoke_from(&self, actor: UserId, who: Who, target: &str) -> Result<(), tonic::Status> {
		let request = RevokePermissionRequest {
			subject: Some(match who {
				Who::Id(id) => revoke_permission_request::Subject::UserId(id.to_string()),
				Who::Email(email) => revoke_permission_request::Subject::Email(email),
			}),
			target: target.into(),
			reason: String::new(),
		};
		self.directory.revoke_permission(as_user(actor, "concierge", request)).await.map(drop)
	}

	async fn grant(&self, actor: UserId, user: UserId, target: &str) -> Result<(), tonic::Status> {
		self.grant_to(actor, Who::Id(user), target).await
	}

	async fn grant_by_email(&self, actor: UserId, user: UserId, target: &str) -> Result<(), tonic::Status> {
		self.grant_to(actor, Who::Email(self.email_of(user).await), target).await
	}

	async fn revoke(&self, actor: UserId, user: UserId, target: &str) -> Result<(), tonic::Status> {
		self.revoke_from(actor, Who::Id(user), target).await
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

	/// `(target, orphaned, email, legal_name)` of every active grant in the tenant, as `actor`
	/// lists it.
	async fn roster(&self, actor: UserId) -> Result<Vec<(String, bool, String, String)>, tonic::Status> {
		let response = self.directory.list_grants(as_user(actor, "concierge", ListGrantsRequest { namespace: self.ns.clone() })).await?;
		Ok(response
			.into_inner()
			.holders
			.into_iter()
			.map(|holder| {
				let grant = holder.grant.unwrap();
				(grant.target, grant.orphaned, holder.email, holder.legal_name)
			})
			.collect())
	}

	async fn active_grants(&self, user: UserId) -> Vec<String> {
		sqlx::query_scalar("SELECT target FROM grants WHERE user_id = $1 AND revoked_at IS NULL ORDER BY target")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.unwrap()
	}

	/// Two accounts on one address, returned as that address. One verified mailbox names
	/// one account, so the second holds it unverified.
	async fn shared_email(&self) -> String {
		let email = format!("shared-{}@iam.example.com", Uuid::new_v4().simple());
		for verified in [true, false] {
			self.users
				.resolve(common::google_as(&format!("iam-shared-{}", Uuid::new_v4()), &email, verified), 0)
				.await
				.unwrap();
		}
		email
	}

	async fn disabled_email(&self) -> String {
		let user = self.user("disabled").await;
		self.users.disable_user(user).await.unwrap();
		self.email_of(user).await
	}

	async fn held_email(&self, by: UserId) -> String {
		let user = self.user("held").await;
		let action = AdminAction {
			actor: Some(by),
			action: "held",
			..AdminAction::default()
		};
		self.users.hold_user(user, &action, by, 0).await.unwrap();
		self.email_of(user).await
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

fn answer(result: Result<(), tonic::Status>) -> (Code, String) {
	match result {
		Ok(()) => (Code::Ok, String::new()),
		Err(status) => (status.code(), status.message().to_owned()),
	}
}

fn unknown_email() -> String {
	format!("nobody-{}@iam.example.com", Uuid::new_v4().simple())
}

#[tokio::test]
async fn an_alias_resolves_to_concrete_permissions_and_follows_its_redefinition() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let member = fx.user("member").await;
	fx.grant(admin, member, &fx.p("operator")).await.unwrap();
	assert_eq!(fx.clients_view(member).await, [fx.p("work:leads:edit"), fx.p("work:leads:read")]);

	fx.publish(2, &PERMISSIONS, &[("operator", &["work:leads:read"], &[])]).await.unwrap();
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

	assert_eq!(fx.clients_view(admin).await.len(), 3, "a tenant that trusts granting seats gives them everything");
}

#[tokio::test]
async fn a_tenant_that_does_not_trust_seats_gives_them_only_what_someone_granted() {
	let Some(fx) = tenant(false).await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let other = fx.seated("other", Role::Admin).await;
	assert!(fx.clients_view(admin).await.is_empty());
	fx.grant(other, admin, &fx.p("operator")).await.unwrap();
	assert_eq!(fx.clients_view(admin).await, [fx.p("work:leads:edit"), fx.p("work:leads:read")]);
}

#[tokio::test]
async fn nothing_outside_a_tenant_namespace_is_grantable() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
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
		assert_eq!(code(fx.grant(admin, member, target).await), Code::InvalidArgument, "{target}");
	}
	assert_eq!(code(fx.grant(admin, member, "nobody_owns_this:x:y").await), Code::InvalidArgument, "an unknown tenant");
	assert_eq!(
		code(fx.grant(admin, member, &fx.p("work:gone:read")).await),
		Code::InvalidArgument,
		"a target the catalog does not define"
	);
	assert!(fx.active_grants(member).await.is_empty());
}

#[tokio::test]
async fn nobody_grants_to_their_own_account() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	assert_eq!(code(fx.grant(admin, admin, &fx.p("operator")).await), Code::PermissionDenied, "a seat");
	assert_eq!(code(fx.grant_by_email(admin, admin, &fx.p("operator")).await), Code::PermissionDenied, "by address too");
	let delegate = fx.delegate().await;
	assert_eq!(code(fx.grant_by_email(delegate, delegate, &fx.p("operator")).await), Code::PermissionDenied, "a delegate");
	assert!(fx.active_grants(admin).await.is_empty());
	assert_eq!(fx.active_grants(delegate).await, [fx.p("admin")]);
}

#[tokio::test]
async fn a_delegate_grants_and_revokes_exactly_what_their_alias_delegates() {
	let Some(fx) = setup().await else { return };
	let delegate = fx.delegate().await;
	let member = fx.user("member").await;
	fx.grant_by_email(delegate, member, &fx.p("operator")).await.unwrap();
	assert_eq!(fx.clients_view(member).await, [fx.p("work:leads:edit"), fx.p("work:leads:read")]);

	for target in ["admin", "work:leads:read", "work:*", "*"] {
		assert_eq!(code(fx.grant_by_email(delegate, member, &fx.p(target)).await), Code::PermissionDenied, "{target}");
	}
	let peer = fx.delegate().await;
	assert_eq!(code(fx.revoke(delegate, peer, &fx.p("admin")).await), Code::PermissionDenied, "another delegate's alias");
	assert_eq!(code(fx.grant(delegate, fx.user("by-id").await, &fx.p("operator")).await), Code::PermissionDenied, "naming by id");

	fx.revoke(delegate, member, &fx.p("operator")).await.expect("revoking by id is fine: the roster hands ids back");
	assert!(fx.active_grants(member).await.is_empty());

	// An operator holds nothing that delegates.
	let operator = fx.user("operator").await;
	fx.grant_by_email(delegate, operator, &fx.p("operator")).await.unwrap();
	assert_eq!(code(fx.grant_by_email(operator, member, &fx.p("operator")).await), Code::PermissionDenied);
	assert_eq!(code(fx.roster(operator).await), Code::PermissionDenied);
}

/// banking#447: a delegate's grant by email must not be an oracle — NOT_FOUND for an
/// address nobody holds, and different texts for a shared address and a disabled account.
#[tokio::test]
async fn a_delegate_cannot_tell_a_missing_address_from_a_shared_or_disabled_one() {
	let Some(fx) = setup().await else { return };
	let delegate = fx.delegate().await;
	let seat = fx.seated("seat", Role::Admin).await;
	let addresses = [
		("unknown", unknown_email()),
		("shared", fx.shared_email().await),
		("disabled", fx.disabled_email().await),
		("held", fx.held_email(seat).await),
	];
	for (what, email) in addresses {
		let got = answer(fx.grant_to(delegate, Who::Email(email), &fx.p("operator")).await);
		assert_eq!(
			got,
			(Code::FailedPrecondition, "this address cannot be granted access".to_owned()),
			"{what}: one answer for every address that cannot be granted"
		);
	}

	// A target outside the delegation is refused before the address is looked at —
	// otherwise PERMISSION_DENIED for a real account against the answer above for a missing
	// one would be the same oracle by another door.
	let real = fx.email_of(fx.user("real").await).await;
	let for_real = answer(fx.grant_to(delegate, Who::Email(real), &fx.p("admin")).await);
	let for_nobody = answer(fx.grant_to(delegate, Who::Email(unknown_email()), &fx.p("admin")).await);
	assert_eq!(for_real.0, Code::PermissionDenied);
	assert_eq!(for_real, for_nobody);
}

/// Seats are entitled to know which account an address names.
#[tokio::test]
async fn a_seat_still_hears_why_an_address_cannot_be_granted() {
	let Some(fx) = setup().await else { return };
	let seat = fx.seated("seat", Role::Admin).await;
	let unknown = answer(fx.grant_to(seat, Who::Email(unknown_email()), &fx.p("operator")).await);
	let shared = answer(fx.grant_to(seat, Who::Email(fx.shared_email().await), &fx.p("operator")).await);
	let disabled = answer(fx.grant_to(seat, Who::Email(fx.disabled_email().await), &fx.p("operator")).await);
	assert_eq!(unknown.0, Code::NotFound);
	assert_eq!(shared.0, Code::FailedPrecondition);
	assert!(shared.1.contains("more than one account"), "{}", shared.1);
	assert_eq!(disabled.0, Code::FailedPrecondition);
	assert!(disabled.1.contains("disabled"), "{}", disabled.1);
}

#[tokio::test]
async fn a_delegate_revoking_by_email_hears_one_not_found_for_everything() {
	let Some(fx) = setup().await else { return };
	let delegate = fx.delegate().await;
	let outsider = fx.email_of(fx.user("outsider").await).await;
	let mut answers = Vec::new();
	for (what, email) in [
		("unknown", unknown_email()),
		("shared", fx.shared_email().await),
		("disabled", fx.disabled_email().await),
		("an account with no grant here", outsider),
	] {
		let got = answer(fx.revoke_from(delegate, Who::Email(email), &fx.p("operator")).await);
		assert_eq!(got.0, Code::NotFound, "{what}");
		answers.push(got);
	}
	answers.dedup();
	assert_eq!(answers.len(), 1, "one text for all of them: {answers:?}");
}

#[tokio::test]
async fn a_delegate_sees_addresses_and_grants_but_no_names() {
	let Some(fx) = setup().await else { return };
	let seat = fx.seated("seat", Role::Admin).await;
	let delegate = fx.delegate().await;
	let member = fx.user("member").await;
	sqlx::query("UPDATE users SET legal_name = 'Ada Lovelace' WHERE id = $1")
		.bind(member.raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	fx.grant(seat, member, &fx.p("work:*")).await.unwrap();

	let row = |roster: Vec<(String, bool, String, String)>| roster.into_iter().find(|(target, ..)| *target == fx.p("work:*")).unwrap();
	let (_, _, email, name) = row(fx.roster(delegate).await.unwrap());
	assert_eq!((email.as_str(), name.as_str()), (fx.email_of(member).await.as_str(), ""));
	let (_, _, _, name) = row(fx.roster(seat).await.unwrap());
	assert_eq!(name, "Ada Lovelace");
}

/// Twenty grant writes an hour is a busy afternoon of onboarding; a script walking a list
/// of addresses hits the ceiling long before it has learned anything.
#[tokio::test]
async fn a_delegate_gets_twenty_grant_writes_an_hour_and_a_seat_is_not_counted() {
	let Some(fx) = setup().await else { return };
	let seat = fx.seated("seat", Role::Admin).await;
	let delegate = fx.delegate().await;
	let member = fx.user("member").await;
	// Grants and revokes share one budget, and a refused write spends it too: the probing
	// this bounds is made of refusals.
	for round in 0..10 {
		fx.grant_by_email(delegate, member, &fx.p("operator")).await.unwrap_or_else(|err| panic!("grant {round}: {err}"));
		fx.revoke(delegate, member, &fx.p("operator")).await.unwrap_or_else(|err| panic!("revoke {round}: {err}"));
	}
	assert_eq!(code(fx.grant_by_email(delegate, member, &fx.p("operator")).await), Code::ResourceExhausted, "the 21st write");
	assert_eq!(code(fx.revoke(delegate, member, &fx.p("operator")).await), Code::ResourceExhausted);
	assert!(fx.active_grants(member).await.is_empty(), "the refused grant wrote nothing");

	fx.grant_by_email(fx.delegate().await, member, &fx.p("operator"))
		.await
		.expect("another delegate has their own budget");
	for round in 0..30 {
		fx.grant(seat, member, &fx.p("work:*")).await.unwrap_or_else(|err| panic!("seat grant {round}: {err}"));
	}
}

#[tokio::test]
async fn the_write_decides_from_the_actors_persisted_standing() {
	let Some(fx) = setup().await else { return };
	let grants = PgGrants::new(fx.pool.clone());
	let member = GrantSubject::Id(fx.user("member").await);
	let operator = Target::parse(&fx.p("operator")).unwrap();
	let action = |actor| AdminAction {
		actor: Some(actor),
		action: "permission_granted",
		..AdminAction::default()
	};
	let actor = |id, role, elevated| GrantActor { id, role, elevated };

	let demoted = fx.user("demoted").await;
	let stale = actor(demoted, Role::Admin, false);
	assert!(
		matches!(grants.grant(&member, &operator, &stale, &action(demoted), 0).await.unwrap(), GrantOutcome::Denied),
		"the gate said admin, the row says investor"
	);
	assert!(matches!(grants.revoke(&member, &operator, &stale, &action(demoted), 0).await.unwrap(), RevokeOutcome::Denied));

	let suspended = fx.seated("suspended", Role::Admin).await;
	fx.users.disable_user(suspended).await.unwrap();
	let outcome = grants.grant(&member, &operator, &actor(suspended, Role::Admin, false), &action(suspended), 0).await.unwrap();
	assert!(matches!(outcome, GrantOutcome::Denied), "a disabled actor acts with nothing");

	let delegate = fx.delegate().await;
	let seat = fx.seated("seat", Role::Admin).await;
	fx.revoke(seat, delegate, &fx.p("admin")).await.unwrap();
	let outcome = grants.grant(&member, &operator, &actor(delegate, Role::Investor, false), &action(delegate), 0).await.unwrap();
	assert!(matches!(outcome, GrantOutcome::Denied), "a revoked alias delegates nothing");

	// Emergency access is the one elevation no row records, so it is carried explicitly.
	let elevated = fx.user("elevated").await;
	let outcome = grants.grant(&member, &operator, &actor(elevated, Role::Owner, true), &action(elevated), 0).await.unwrap();
	assert!(matches!(outcome, GrantOutcome::Granted(_)), "break-glass elevation still counts inside the transaction");
}

#[tokio::test]
async fn a_disabled_ambiguous_or_unknown_account_is_not_granted() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let held = fx.user("held").await;
	fx.users.disable_user(held).await.unwrap();
	assert_eq!(code(fx.grant(admin, held, &fx.p("operator")).await), Code::FailedPrecondition);
	assert_eq!(code(fx.grant(admin, UserId::from_raw(Uuid::new_v4()), &fx.p("operator")).await), Code::NotFound);
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

	let alias = |name: String, members: Vec<String>, delegates: Vec<String>| CatalogAlias { name, members, delegates };
	let invalid = |result: Result<(), ClientGrantError>| matches!(result, Err(ClientGrantError::InvalidCatalog(_)));
	let lead = || vec![fx.p("work:leads:read")];
	assert!(
		invalid(fx.publish_raw(5, lead(), vec![alias(fx.p("operator"), vec!["bank:payment:open".into()], vec![])]).await),
		"an alias reaching into bank:*"
	);
	assert!(invalid(fx.publish_raw(5, vec!["bank:payment:open".into()], vec![]).await), "a permission of another namespace");
	assert!(
		invalid(fx.publish_raw(5, lead(), vec![alias("seat:admin".into(), lead(), vec![])]).await),
		"an alias named outside the namespace"
	);
	assert!(
		invalid(
			fx.publish(5, &PERMISSIONS, &[("operator", &[], &[]), ("lead", &[], &["operator"]), ("admin", &[], &["lead"])])
				.await
		),
		"a delegate that delegates"
	);
	let many: Vec<String> = (0..=concierge_iam::MAX_PERMISSIONS).map(|i| fx.p(&format!("p:x{i}"))).collect();
	assert!(invalid(fx.publish_raw(5, many, vec![]).await), "past the size bound");
	let far = time::OffsetDateTime::now_utc().unix_timestamp().unsigned_abs() + 2 * 24 * 60 * 60;
	assert!(invalid(fx.publish_initial(far).await), "a version nothing could ever supersede");

	assert!(matches!(fx.publish(0, &["work:leads:read"], &[]).await, Err(ClientGrantError::StaleCatalog(_))), "a rollback");
	assert!(
		matches!(fx.publish(1, &["work:leads:read"], &[]).await, Err(ClientGrantError::StaleCatalog(_))),
		"the same version, different content"
	);
	fx.publish_initial(1).await.expect("republishing what is stored is a no-op");

	let mut wrong = fx.rp.publish_catalog(CatalogPublication {
		client_id: fx.client.clone(),
		client_secret: "not-the-secret-not-the-secret-xx".into(),
		version: 9,
		permissions: vec![],
		aliases: vec![],
	});
	assert!(matches!((&mut wrong).await, Err(ClientGrantError::InvalidClient)));

	fx.publish(2, &["work:leads:read"], &[]).await.unwrap();
	assert_eq!(
		fx.roster(admin).await.unwrap().into_iter().map(|(target, orphaned, ..)| (target, orphaned)).collect::<Vec<_>>(),
		[(fx.p("operator"), true)],
		"a grant whose alias vanished stays, orphaned"
	);
	assert!(fx.clients_view(member).await.is_empty(), "and grants nothing");

	let history: Vec<(i64, Option<String>)> = sqlx::query_as("SELECT version, published_by FROM catalogs WHERE tenant_id = $1 ORDER BY version")
		.bind(&fx.ns)
		.fetch_all(&fx.pool)
		.await
		.unwrap();
	assert_eq!(history, [(1, Some(fx.client.clone())), (2, Some(fx.client.clone()))], "every catalog ever in force is kept");
}

#[tokio::test]
async fn the_table_refuses_a_grant_to_its_own_granter() {
	let Some(fx) = setup().await else { return };
	let admin = fx.seated("admin", Role::Admin).await;
	let refused = sqlx::query("INSERT INTO grants (user_id, namespace, target, granted_by, granted_at) VALUES ($1, $2, $3, $1, 0)")
		.bind(admin.raw())
		.bind(&fx.ns)
		.bind(fx.p("operator"))
		.execute(&fx.pool)
		.await;
	assert!(refused.is_err());
}
