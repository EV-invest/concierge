//! Composition root for the `concierge` modular monolith.
//!
//! `concierge` is the identity/platform plane (a sibling to the banking money
//! plane). One runner binary mounts its internal modules — `auth` (token issuance,
//! served by [`evconcierge_auth::AuthService`]), `directory` (user profile/admin),
//! `notification`, and `log` — on a single tonic server. It opens the Postgres
//! control plane and applies its migrations on boot (the identity records + the
//! cross-plane bridge outbox). Notifications and logs are DEFERRED stubs. There is
//! no money plane here.

use anyhow::Context;
use concierge::{bridge, config::Config, directory, infrastructure, log, notification};
use ev::error_monitoring::{self, Config as SentryConfig};
use evconcierge_auth::{AuthConfig, AuthService, Verifier, VerifierConfig, grpc_auth_layer, provisioner_channel};
use evconcierge_contracts::concierge::v1::{
	CheckRequest, CheckResponse,
	auth_service_server::AuthServiceServer,
	health_service_server::{HealthService, HealthServiceServer},
	log_service_server::LogServiceServer,
	notification_service_server::NotificationServiceServer,
	user_directory_server::UserDirectoryServer,
	user_events_server::UserEventsServer,
};
use tonic::{Request, Response, Status, transport::Server};
use tonic_web::GrpcWebLayer;
use tower::{Layer, ServiceBuilder};
use tower_http::trace::TraceLayer;

// Sentry must be initialised before the async runtime starts — no #[tokio::main].
fn main() -> anyhow::Result<()> {
	dotenvy::dotenv().ok();

	let config = Config::from_env().context("failed to load configuration")?;

	// Guard must stay alive for the duration of main — dropping it flushes events.
	// `None` DSN → `init` returns `None`, so this binding is simply inert.
	let _sentry_guard = error_monitoring::init(&SentryConfig {
		dsn: config.sentry_dsn.clone(),
		environment: config.app_env.clone(),
		traces_sample_rate: SentryConfig::traces_sample_rate_for(&config.app_env),
	});

	init_tracing();

	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()
		.context("failed to build tokio runtime")?
		.block_on(run(config))
}

async fn run(config: Config) -> anyhow::Result<()> {
	// The plane applies pending control-plane migrations on boot (idempotent). New
	// migration FILES are authored with the sqlx CLI (`sqlx migrate add …`), never
	// hand-written.
	let pool = infrastructure::db::connect_sized(&config.database_url, config.db_max_connections)
		.await
		.context("failed to connect to the database")?;
	infrastructure::db::migrate(&pool).await.context("failed to apply database migrations")?;

	// Product-analytics capture (native PostHog). A `None` key makes capture a
	// silent no-op, so this is safe to construct unconfigured.
	let _analytics = ev::analytics::Analytics::new(config.posthog_key.clone(), config.posthog_host.clone());

	tracing::info!(bind = %config.bind_addr, "concierge listening");

	// The user directory repository: the only writer of the identity control plane and
	// the cross-plane outbox. Shared by the directory service and the provisioner loop.
	let users = std::sync::Arc::new(infrastructure::users::PgUsers::new(pool.clone()));

	// Auth issuance. `AuthConfig` is host-only (signing key, Google client, refresh
	// TTLs); with no `AUTH_SIGNING_KEY_PEM` configured the service runs inert. The
	// provisioner channel is the auth → directory seam: auth holds the `Provisioner`
	// (called from `Exchange`/`Refresh`), and the directory keeps the receiver and
	// drains it against Postgres — provisioning/looking-up/revoking the matching user.
	let auth_config = AuthConfig::from_env().context("failed to load auth configuration")?;
	let (provisioner, provision_rx) = provisioner_channel();
	tokio::spawn(directory::run_provisioner(provision_rx, users.clone()));
	let auth_service = AuthService::try_new(auth_config, provisioner).await.context("failed to build the auth service")?;

	// Inbound verification choke point: a `Verifier` over this plane's own `Jwks` RPC.
	// Built lazily so boot does not block on a self-dial; the first verify warms the
	// cache. With no signing key, the served JWKS is empty and every inbound verify
	// fails closed (`UnknownKid`/`JwksFetch` → UNAUTHENTICATED/UNAVAILABLE), so no
	// directory/admin mutation can run unauthenticated.
	let verifier_config = VerifierConfig {
		issuer: auth_config_issuer(),
		audiences: client_audiences(),
		allowed_types: vec![evconcierge_auth::TokenType::Access],
		jwks_grpc_endpoint: jwks_grpc_endpoint(&config.bind_addr),
	};
	verifier_config.assert_plane().context("verifier config carries a cross-plane identity")?;
	let verifier = Verifier::try_new(verifier_config).context("failed to build the inbound token verifier")?;

	// `tonic-web` (`GrpcWebLayer` + `accept_http1`) lets browser/WASM clients reach
	// the services over gRPC-Web with no separate proxy. `TraceLayer` emits a span
	// per request through the same `tracing` subscriber (and Sentry integration).
	//
	// The auth choke point: every non-public service is wrapped in `auth.layer(...)`,
	// which authenticates the inbound bearer token before any handler gets a body and
	// injects the verified `Claims`. `HealthService` (BFF liveness) and `AuthService`
	// (the token-issuance surface: `Exchange`/`Refresh`/`Jwks`) are deliberately left
	// UNWRAPPED — they are public.
	let auth = grpc_auth_layer(verifier);

	// The cross-plane bridge producer: the one-way identity→money seam the banking
	// plane PULLS from. Mounted OUTSIDE the user `auth` layer — it is a
	// service-to-service seam authenticated by its own shared bridge service token, not
	// a user access token. Unconfigured (`BRIDGE_SERVICE_TOKEN` unset) it fails closed.
	let bridge = bridge::Bridge::new(pool.clone(), config.bridge_service_token);

	Server::builder()
		.accept_http1(true)
		.layer(ServiceBuilder::new().layer(TraceLayer::new_for_grpc()).layer(GrpcWebLayer::new()).into_inner())
		.add_service(HealthServiceServer::new(Health))
		.add_service(AuthServiceServer::new(auth_service))
		.add_service(UserEventsServer::new(bridge))
		.add_service(auth.layer(UserDirectoryServer::new(directory::Directory::new(users, config.admin_subjects.into()))))
		.add_service(auth.layer(NotificationServiceServer::new(notification::Notifications::new())))
		.add_service(auth.layer(LogServiceServer::new(log::Logs::new())))
		.serve(config.bind_addr)
		.await
		.context("concierge gRPC server error")
}

/// The plane's issuer, read with the same default `evconcierge_auth` uses, so the
/// inbound verifier expects exactly what issuance stamps.
fn auth_config_issuer() -> String {
	std::env::var("AUTH_ISSUER").unwrap_or_else(|_| "https://auth.concierge.ev".to_string())
}

/// The client audience(s) the inbound choke point accepts — user access tokens only.
fn client_audiences() -> Vec<String> {
	let raw = std::env::var("AUTH_CLIENT_AUDIENCE").unwrap_or_else(|_| "concierge".to_string());
	raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

/// Where the inbound verifier dials the `Jwks` RPC: an override env, else this plane's
/// own bind address (it serves its own JWKS in the same process).
fn jwks_grpc_endpoint(bind_addr: &std::net::SocketAddr) -> String {
	std::env::var("AUTH_JWKS_GRPC_ENDPOINT").unwrap_or_else(|_| format!("http://{bind_addr}"))
}

/// Liveness probe for the gRPC surface.
#[derive(Default)]
struct Health;

#[tonic::async_trait]
impl HealthService for Health {
	async fn check(&self, _request: Request<CheckRequest>) -> Result<Response<CheckResponse>, Status> {
		Ok(Response::new(CheckResponse { status: "ok".to_string() }))
	}
}

fn init_tracing() {
	use tracing_subscriber::{EnvFilter, fmt, prelude::*};

	let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,concierge=debug,evconcierge_auth=debug"));
	tracing_subscriber::registry().with(filter).with(fmt::layer()).with(error_monitoring::tracing_layer()).init();
}
