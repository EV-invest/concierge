//! Composition root for the `concierge` modular monolith.
//!
//! `concierge` is the identity/platform plane (a sibling to the banking money
//! plane). One runner binary mounts its internal modules — `auth` (token issuance,
//! served by [`evconcierge_auth::AuthService`]), `directory` (user profile/admin),
//! `notification`, and `log` — on a single tonic server. Notifications and logs are
//! DEFERRED stubs. There is no DB and no money plane here.

use anyhow::Context;
use ev::error_monitoring::{self, Config as SentryConfig};
use evconcierge_contracts::concierge::v1::{
	CheckRequest, CheckResponse,
	auth_service_server::AuthServiceServer,
	health_service_server::{HealthService, HealthServiceServer},
	log_service_server::LogServiceServer,
	notification_service_server::NotificationServiceServer,
	user_directory_server::UserDirectoryServer,
};
use tonic::{Request, Response, Status, transport::Server};
use tonic_web::GrpcWebLayer;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::config::Config;

mod config;
mod directory;
mod log;
mod notification;

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
	// Product-analytics capture (native PostHog). A `None` key makes capture a
	// silent no-op, so this is safe to construct unconfigured.
	let _analytics = ev::analytics::Analytics::new(config.posthog_key.clone(), config.posthog_host.clone());

	tracing::info!(bind = %config.bind_addr, "concierge listening");

	// `tonic-web` (`GrpcWebLayer` + `accept_http1`) lets browser/WASM clients reach
	// the services over gRPC-Web with no separate proxy. `TraceLayer` emits a span
	// per request through the same `tracing` subscriber (and Sentry integration).
	Server::builder()
		.accept_http1(true)
		.layer(ServiceBuilder::new().layer(TraceLayer::new_for_grpc()).layer(GrpcWebLayer::new()).into_inner())
		.add_service(HealthServiceServer::new(Health))
		.add_service(AuthServiceServer::new(evconcierge_auth::AuthService::unconfigured()))
		.add_service(UserDirectoryServer::new(directory::Directory::new()))
		.add_service(NotificationServiceServer::new(notification::Notifications::new()))
		.add_service(LogServiceServer::new(log::Logs::new()))
		.serve(config.bind_addr)
		.await
		.context("concierge gRPC server error")
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
