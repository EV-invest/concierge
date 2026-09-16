//! The bridge TLS listener, exercised with REAL handshakes (banking#199, phase 2).
//!
//! The listener is the same `Server::builder().tls_config(..)` shape the composition
//! root mounts, over the same [`bridge_tls::Files::load`] path a deployment takes, and
//! the client is the tonic client banking builds — a pinned CA plus `domain_name`. What
//! is asserted is the property the issue is about: a peer that does not hold the pinned
//! CA's trust cannot complete a handshake, and (under mTLS) a peer that cannot show a
//! certificate this CA signed is refused before any RPC runs.
//!
//! Fixtures live in `fixtures/tls/` (regenerate with `regen.sh` there). The pull tests
//! hit a real Postgres like `bridge.rs` does and skip without `DATABASE_URL`; the
//! refusal tests never reach a handler, so they run everywhere.

mod common;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use concierge::{
	bridge::Bridge,
	bridge_tls::{self, Files, Listener},
	infrastructure::db,
};
use evconcierge_contracts::concierge::v1::{PullUserLifecycleRequest, user_events_client::UserEventsClient, user_events_server::UserEventsServer};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tonic::{
	Request,
	metadata::MetadataValue,
	transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, server::TcpIncoming},
};

const TOKEN: &str = "test-bridge-token";

fn fixture(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls").join(name)
}

fn fixture_pem(name: &str) -> String {
	std::fs::read_to_string(fixture(name)).unwrap_or_else(|err| panic!("read fixture {name}: {err}"))
}

fn files(client_ca: Option<&str>) -> Files {
	Files {
		// Placeholder: the tests bind an ephemeral port themselves (see `serve`).
		bind: "127.0.0.1:0".parse().unwrap(),
		cert_pem_file: fixture("server.pem").to_string_lossy().into_owned(),
		key_pem_file: fixture("server.key").to_string_lossy().into_owned(),
		client_ca_pem_file: client_ca.map(|name| fixture(name).to_string_lossy().into_owned()),
	}
}

/// A pool for the tests where the handler is never reached: the handshake fails
/// first, so no connection is ever opened. `connect_lazy` makes that explicit.
fn detached_pool() -> PgPool {
	PgPoolOptions::new().connect_lazy("postgres://127.0.0.1:1/never-connected").expect("a lazy pool needs no server")
}

async fn real_pool() -> Option<PgPool> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some(pool)
}

/// Serve the bridge over the listener's TLS config on an ephemeral loopback port —
/// the production `Server::builder().tls_config(..)` shape, minus the fixed bind.
fn serve(listener: &Listener, pool: PgPool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
	// What `main` does before the runtime starts; the test process has no `main`.
	bridge_tls::install_crypto_provider();
	let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind an ephemeral port");
	let addr = incoming.local_addr().expect("local addr");
	let server = Server::builder()
		.tls_config(listener.tls_config())
		.expect("server tls config")
		.add_service(UserEventsServer::new(Bridge::new(pool, Some(TOKEN.to_string()))))
		.serve_with_incoming(incoming);
	let handle = tokio::spawn(async move {
		server.await.expect("bridge tls server");
	});
	(addr, handle)
}

async fn connect(addr: SocketAddr, tls: ClientTlsConfig) -> Result<Channel, tonic::transport::Error> {
	Channel::from_shared(format!("https://{addr}"))
		.unwrap()
		.tls_config(tls)
		.unwrap()
		.connect_timeout(Duration::from_secs(5))
		.connect()
		.await
}

/// Exactly what banking builds from `BRIDGE_TLS_CA_PEM_FILE`: this CA and nothing
/// else, with the name pinned to what the server certificate carries.
fn pinned(ca: &str) -> ClientTlsConfig {
	ClientTlsConfig::new().ca_certificate(Certificate::from_pem(fixture_pem(ca))).domain_name("localhost")
}

fn authed_pull() -> Request<PullUserLifecycleRequest> {
	// `after_position` past anything a shared database holds: the pull must be REAL
	// (it runs the query) and still return an empty page.
	let mut request = Request::new(PullUserLifecycleRequest {
		after_position: i64::MAX - 1,
		limit: 10,
	});
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {TOKEN}")).unwrap());
	request
}

#[tokio::test]
async fn a_client_pinning_the_ca_completes_a_pull_over_tls() {
	let Some(pool) = real_pool().await else {
		return;
	};
	let listener = files(None).load().expect("load fixtures");
	let (addr, server) = serve(&listener, pool);

	let channel = connect(addr, pinned("ca.pem")).await.expect("handshake against the pinned CA");
	let response = UserEventsClient::new(channel).pull_user_lifecycle(authed_pull()).await.expect("pull over tls").into_inner();
	assert!(response.events.is_empty(), "nothing lives past i64::MAX - 1");

	server.abort();
}

#[tokio::test]
async fn a_client_trusting_a_different_ca_cannot_complete_the_handshake() {
	let listener = files(None).load().expect("load fixtures");
	let (addr, server) = serve(&listener, detached_pool());

	let err = connect(addr, pinned("other-ca.pem")).await.expect_err("an unrelated CA must not verify the server");
	// The refusal is the transport's, before any RPC: the token never gets a chance to
	// be presented to a server that is not the one banking pinned.
	assert!(format!("{err:?}").contains("InvalidCertificate(UnknownIssuer)"), "{err:?}");

	server.abort();
}

#[tokio::test]
async fn without_a_pinned_ca_the_public_roots_do_not_vouch_for_the_bridge() {
	let listener = files(None).load().expect("load fixtures");
	let (addr, server) = serve(&listener, detached_pool());

	// No `ca_certificate`: whatever roots the platform offers, none of them signed
	// `fixtures/tls/server.pem`, so an unpinned client is refused exactly as a pinned
	// one trusting the wrong CA. This is the state banking is in with
	// `BRIDGE_TLS_CA_PEM_FILE` unset and an `https://` address.
	connect(addr, ClientTlsConfig::new().domain_name("localhost"))
		.await
		.expect_err("no public root signed the test server certificate");

	server.abort();
}

#[tokio::test]
async fn under_mtls_a_client_without_a_certificate_is_refused_before_any_rpc() {
	let listener = files(Some("ca.pem")).load().expect("load fixtures");
	assert!(listener.is_mutual());
	let (addr, server) = serve(&listener, detached_pool());

	// rustls surfaces the server's `CertificateRequired` alert either at connect or on the
	// first request, depending on which side notices first — so drive one RPC and
	// require a failure somewhere along the way, and never a response.
	let outcome = match connect(addr, pinned("ca.pem")).await {
		Err(_) => Err(()),
		Ok(channel) => UserEventsClient::new(channel).pull_user_lifecycle(authed_pull()).await.map(|_| ()).map_err(|_| ()),
	};
	assert!(outcome.is_err(), "an mTLS listener answered a client that showed no certificate");

	server.abort();
}

#[tokio::test]
async fn under_mtls_a_certificate_from_another_ca_is_refused() {
	let listener = files(Some("ca.pem")).load().expect("load fixtures");
	let (addr, server) = serve(&listener, detached_pool());

	let identity = Identity::from_pem(fixture_pem("other-client.pem"), fixture_pem("other-client.key"));
	let outcome = match connect(addr, pinned("ca.pem").identity(identity)).await {
		Err(_) => Err(()),
		Ok(channel) => UserEventsClient::new(channel).pull_user_lifecycle(authed_pull()).await.map(|_| ()).map_err(|_| ()),
	};
	assert!(outcome.is_err(), "an mTLS listener accepted a certificate the client CA never signed");

	server.abort();
}

#[tokio::test]
async fn under_mtls_a_certificate_from_the_client_ca_completes_a_pull() {
	let Some(pool) = real_pool().await else {
		return;
	};
	let listener = files(Some("ca.pem")).load().expect("load fixtures");
	let (addr, server) = serve(&listener, pool);

	let identity = Identity::from_pem(fixture_pem("client.pem"), fixture_pem("client.key"));
	let channel = connect(addr, pinned("ca.pem").identity(identity)).await.expect("mtls handshake");
	let response = UserEventsClient::new(channel).pull_user_lifecycle(authed_pull()).await.expect("pull over mtls").into_inner();
	assert!(response.events.is_empty());

	server.abort();
}

/// TLS proves the PEER; the token still proves the CALLER. A handshake that succeeds
/// must not be mistaken for authentication of the pull itself.
#[tokio::test]
async fn tls_does_not_replace_the_bridge_token() {
	let Some(pool) = real_pool().await else {
		return;
	};
	let listener = files(None).load().expect("load fixtures");
	let (addr, server) = serve(&listener, pool);

	let channel = connect(addr, pinned("ca.pem")).await.expect("handshake");
	let status = UserEventsClient::new(channel)
		.pull_user_lifecycle(Request::new(PullUserLifecycleRequest { after_position: 0, limit: 1 }))
		.await
		.expect_err("a pull with no token must be refused even over tls");
	assert_eq!(status.code(), tonic::Code::Unauthenticated);

	server.abort();
}

/// The boot-time half, end to end: the variables a deployment sets → the listener it
/// gets, and the refusal it gets for a path that does not exist.
#[test]
fn the_configured_files_load_and_a_bad_path_refuses_the_boot() {
	let cert = fixture("server.pem");
	let key = fixture("server.key");
	let settings = bridge_tls::Settings {
		bind: Some("127.0.0.1:55672".parse().unwrap()),
		cert_pem_file: Some(cert.to_str().unwrap()),
		key_pem_file: Some(key.to_str().unwrap()),
		client_ca_pem_file: None,
	};
	let files = bridge_tls::configure(settings).unwrap().expect("configured");
	assert!(!files.load().expect("fixtures load").is_mutual());

	let missing = fixture("does-not-exist.pem");
	let files = Files {
		key_pem_file: missing.to_string_lossy().into_owned(),
		..files
	};
	let Err(err) = files.load() else {
		panic!("a missing key file must fail the boot");
	};
	assert!(format!("{err:#}").contains("BRIDGE_TLS_KEY_PEM_FILE"), "{err:#}");
}
