use std::net::SocketAddr;

use smart_default::SmartDefault;
use v_utils::macros as v_macros;

/// Runner configuration (LiveSettings). Prod runs `--config` on the baked
/// `deploy/config.nix` result — `{ env = "VAR" }` refs there assert the var's
/// presence at startup. Dev runs config-less from the flake-exported env
/// (`#[settings(use_env = true)]` aliases each field to its SHOUTY name).
#[derive(Clone, Debug, v_macros::LiveSettings, v_macros::MyConfigPrimitives, v_macros::Settings, SmartDefault)]
#[settings(use_env = true)]
pub struct AppConfig {
	pub database_url: String,
	/// gRPC listener address for the modular-monolith surface (auth + directory +
	/// notification + log + health, all mounted on one server).
	#[default(SocketAddr::from(([127, 0, 0, 1], 50061)))]
	pub bind: SocketAddr,
	/// Max connections for the request-serving Postgres pool (the directory handlers
	/// and the bridge outbox reads).
	#[default(10)]
	pub db_max_connections: u32,
	/// Break-glass superadmin allowlist: a listed subject is treated as
	/// [`Role::Owner`](domain::authz::Role) — a ROLE override surfaced everywhere the plane
	/// reports a role (the issued session's `UserSummary`, `GetMe`/`GetUser`, `ListUsers`),
	/// not only the RPC gate, so a listed subject can open the cabinet admin console before
	/// any role is persisted. It never exempts from status/`token_version` enforcement and
	/// never writes `users.role` (`SetRole` is the only writer) — empty the list once the
	/// bootstrap operator has persisted a real role. Comma-separated (empty ⇒ no bootstrap
	/// admins). NOTE: these are CONCIERGE canonical user ids — the banking plane's identical
	/// env is keyed on its OWN (disjoint) user id space, so the same human is a different
	/// UUID on each plane; a wrong id fails closed to Investor.
	#[serde(default)]
	pub admin_subjects: Vec<String>,
	/// Shared bearer token the banking money plane presents on the cross-plane bridge
	/// (`UserEvents.PullUserLifecycle`). Graduate to mTLS/SPIFFE at platform scale.
	pub bridge_service_token: String,
	pub sentry_dsn: Option<String>,
	/// PostHog project key for native product-analytics capture. `None` disables
	/// capture (a silent no-op), so the same code runs unconfigured (local, CI).
	pub posthog_key: Option<String>,
	/// PostHog ingestion host; `None` falls back to the library default.
	pub posthog_host: Option<String>,
	// No Rust-side default: published v_utils_macros can't synthesize serde
	// defaults for PrivateValue-wrapped (String) fields. Dev exports APP_ENV /
	// PUBLIC_ORIGIN (flake run script); prod sets literals in deploy/config.nix.
	pub app_env: String,
	/// HTTP listener for the site-level auth surface (`web` module). The conductor
	/// rewrites `/api/auth/*` + `/api/callback/auth/*` here.
	#[default(SocketAddr::from(([127, 0, 0, 1], 55671)))]
	pub web_bind: SocketAddr,
	/// The user-facing origin the conductor serves; builds the OAuth redirect_uri
	/// (`{public_origin}/api/callback/auth/google` — register it with Google).
	pub public_origin: String,
}
