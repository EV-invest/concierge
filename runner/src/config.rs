ev::settings! {
	/// Runner configuration for the concierge modular monolith — reads every field
	/// from the environment (env-only, no config files, no hot reload).
	pub struct AppConfig {
		database_url: String,
		/// gRPC listener address for the modular-monolith surface.
		bind: std::net::SocketAddr = "127.0.0.1:50061",
		/// Max connections for the request-serving Postgres pool.
		db_max_connections: u32 = "10",
		/// Break-glass superadmin allowlist (comma-separated canonical user ids).
		/// Empty ⇒ no bootstrap admins. NOTE: these are CONCIERGE canonical user ids.
		admin_subjects: Vec<String> = "",
		/// Shared bearer token for the cross-plane bridge (`UserEvents.PullUserLifecycle`).
		#[secret]
		bridge_service_token: String,
		sentry_dsn: Option<String>,
		/// PostHog project key for native product-analytics capture.
		posthog_key: Option<String>,
		/// PostHog ingestion host; `None` falls back to the library default.
		posthog_host: Option<String>,
		app_env: String = "development",
		/// HTTP listener for the site-level auth surface (`web` module).
		web_bind: std::net::SocketAddr = "127.0.0.1:55671",
		/// The user-facing origin the conductor serves; builds the OAuth redirect_uri.
		public_origin: String,
	}
}
