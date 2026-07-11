//! Composition root for the `concierge` modular monolith.
//!
//! `concierge` is the identity/platform plane (a sibling to the banking money
//! plane). One runner binary mounts its internal modules — `auth` (token issuance,
//! served by [`evconcierge_auth::AuthService`]), `directory` (user profile/admin),
//! `bridge` (the cross-plane producer), `platform` (platform/cabinet config),
//! `notification`, and `log` — on a single tonic server. It opens the Postgres
//! control plane and applies its migrations on boot (the identity records + the
//! cross-plane bridge outbox). Notifications and logs are DEFERRED stubs. There is
//! no money plane here.

use std::sync::Arc;

use clap::Parser;
use color_eyre::{
	Result,
	eyre::{Context, ensure},
};
use concierge::{bridge, config, config::AppConfig, directory, infrastructure, log, notification, platform, web};
use ev::error_monitoring::{self, Config as SentryConfig};
use evconcierge_auth::{AuthConfig, AuthService, Verifier, VerifierConfig, grpc_auth_layer, provisioner_channel};
use evconcierge_contracts::concierge::v1::{
	CheckRequest, CheckResponse,
	auth_service_server::AuthServiceServer,
	health_service_server::{HealthService, HealthServiceServer},
	log_service_server::LogServiceServer,
	notification_service_server::NotificationServiceServer,
	platform_service_server::PlatformServiceServer,
	user_directory_server::UserDirectoryServer,
	user_events_server::UserEventsServer,
};
use tonic::{Request, Response, Status, transport::Server};
use tonic_web::GrpcWebLayer;
use tower::{Layer, ServiceBuilder};
use tower_http::trace::TraceLayer;

#[derive(Parser)]
struct Cli {
	#[clap(flatten)]
	settings_flags: config::SettingsFlags,
}

// Sentry must be initialised before the async runtime starts — no #[tokio::main].
fn main() -> Result<()> {
	color_eyre::install()?;
	dotenvy::dotenv().ok();

	let cli = Cli::parse();
	// One snapshot at boot; hot reload is unused. A missing `{ env = "VAR" }` ref
	// in the prod config fails HERE, before anything binds.
	let config = config::LiveSettings::new(cli.settings_flags, std::time::Duration::from_secs(60))?.config()?;

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

async fn run(config: AppConfig) -> Result<()> {
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

	tracing::info!(bind = %config.bind, "concierge listening");

	// The user directory repository: the only writer of the identity control plane and
	// the cross-plane outbox. Shared by the directory service and the provisioner loop,
	// both of which see only the port.
	let users: Arc<dyn concierge::ports::UserDirectoryRepository> = Arc::new(infrastructure::users::PgUsers::new(pool.clone()));

	// Auth issuance. `AuthConfig` is host-only (signing key, Google client, refresh
	// TTLs); with no `AUTH_SIGNING_KEY_PEM` configured the service runs inert. The
	// provisioner channel is the auth → directory seam: auth holds the `Provisioner`
	// (called from `Exchange`/`Refresh`), and the directory keeps the receiver and
	// drains it against Postgres — provisioning/looking-up/revoking the matching user.
	let auth_config = AuthConfig::from_env().context("failed to load auth configuration")?;
	// The auth crate's optional seams (absent ⇒ inert plane) are a dev/CI
	// affordance; production must never boot inert. Same for the session/refresh
	// stores' in-process fallback — restart-lossy, dev-only.
	if config.app_env == "production" {
		ensure!(
			auth_config.signing.is_some(),
			"production requires the auth signing triple (AUTH_SIGNING_KEY_PEM/AUTH_SIGNING_KID/AUTH_JWKS_JSON)"
		);
		ensure!(auth_config.google.is_some(), "production requires GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET");
		ensure!(
			std::env::var("REDIS_URL").is_ok_and(|v| !v.is_empty()),
			"production requires REDIS_URL (web sessions + refresh state must survive restarts)"
		);
	}
	// The inbound verifier must expect exactly what issuance stamps, so read the
	// issuer/audience off the loaded (env-resolved, plane-asserted) `auth_config`
	// before it moves into the service — never re-read the env with copied defaults.
	let issuer = auth_config.issuer.clone();
	let audiences = auth_config.client_audience.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
	// The admin allowlist is shared by the directory and platform services (the
	// break-glass superadmin bootstrap for the RBAC gate) and by the provisioner loop,
	// so issued sessions carry the effective role.
	let admins: Arc<[String]> = config.admin_subjects.into();
	let (provisioner, provision_rx) = provisioner_channel();
	tokio::spawn(directory::run_provisioner(provision_rx, users.clone(), admins.clone()));
	let auth_service = AuthService::try_new(auth_config, provisioner).await.context("failed to build the auth service")?;

	// Inbound verification choke point: a `Verifier` over this plane's own `Jwks` RPC.
	// Built lazily so boot does not block on a self-dial; the first verify warms the
	// cache. With no signing key, the served JWKS is empty and every inbound verify
	// fails closed (`UnknownKid`/`JwksFetch` → UNAUTHENTICATED/UNAVAILABLE), so no
	// directory/admin mutation can run unauthenticated. The JWKS is dialed at an
	// override env, else this plane's own bind address (it serves its own JWKS
	// in-process).
	let verifier_config = VerifierConfig {
		issuer,
		audiences,
		allowed_types: vec![evconcierge_auth::TokenType::Access],
		jwks_grpc_endpoint: std::env::var("AUTH_JWKS_GRPC_ENDPOINT").unwrap_or_else(|_| format!("http://{}", config.bind)),
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
	// a user access token.
	let bridge = bridge::Bridge::new(pool.clone(), Some(config.bridge_service_token));

	let platform_repo: Arc<dyn concierge::ports::PlatformConfigRepository> = Arc::new(infrastructure::platform::PgPlatform::new(pool.clone()));

	// The site-level auth HTTP surface: the conductor rewrites the shared origin's
	// `/api/auth/*` + `/api/callback/auth/*` here, so login/session cookies land
	// first-party for every zone. Calls the SAME issuance service in-process.
	let web_state = web::WebState::new(auth_service.clone(), config.public_origin.clone(), config.app_env == "production");
	let web_listener = tokio::net::TcpListener::bind(config.web_bind).await.context("failed to bind the auth web listener")?;
	tracing::info!(bind = %config.web_bind, "auth web surface listening");
	let web_server = async {
		axum::serve(web_listener, web::router(web_state))
			.with_graceful_shutdown(await_signal())
			.await
			.context("concierge auth web server error")
	};

	let grpc_server = async {
		Server::builder()
			.accept_http1(true)
			.layer(ServiceBuilder::new().layer(TraceLayer::new_for_grpc()).layer(GrpcWebLayer::new()).into_inner())
			.add_service(HealthServiceServer::new(Health))
			.add_service(AuthServiceServer::new(auth_service))
			.add_service(UserEventsServer::new(bridge))
			.add_service(auth.layer(UserDirectoryServer::new(directory::Directory::new(users.clone(), admins.clone()))))
			.add_service(auth.layer(PlatformServiceServer::new(platform::Platform::new(users, admins, platform_repo))))
			.add_service(auth.layer(NotificationServiceServer::new(notification::Notifications::new())))
			.add_service(auth.layer(LogServiceServer::new(log::Logs::new())))
			.serve_with_shutdown(config.bind, await_signal())
			.await
			.context("concierge gRPC server error")
	};

	tokio::try_join!(grpc_server, web_server)?;
	Ok(())
}

/// Resolve on SIGTERM or ctrl-c so the server drains in-flight RPCs instead of
/// dropping them (banking's `await_signal`, scaled down to the one listener this
/// plane runs). If a listener can't be installed, never resolve — the server then
/// runs until the process is killed, exactly the pre-graceful behaviour.
async fn await_signal() {
	#[cfg(unix)]
	{
		use tokio::signal::unix::{SignalKind, signal};
		match signal(SignalKind::terminate()) {
			Ok(mut term) => {
				tokio::select! {
					result = tokio::signal::ctrl_c() => {
						if let Err(err) = result {
							tracing::error!("failed to listen for ctrl_c: {err}");
							std::future::pending::<()>().await;
						}
					},
					_ = term.recv() => {},
				}
			}
			Err(err) => {
				tracing::error!("failed to install SIGTERM handler: {err}");
				std::future::pending::<()>().await;
			}
		}
	}
	#[cfg(not(unix))]
	if let Err(err) = tokio::signal::ctrl_c().await {
		tracing::error!("failed to listen for ctrl_c: {err}");
		std::future::pending::<()>().await;
	}
	tracing::info!("shutdown signal received — draining");
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
