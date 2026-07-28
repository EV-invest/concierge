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
		/// SMTP host for outbound notification mail. Unset ⇒ mail is logged, not sent
		/// (the whole emit → queue → render path still runs).
		smtp_host: Option<String>,
		smtp_port: u16 = "587",
		smtp_username: Option<String>,
		#[secret]
		smtp_password: Option<String>,
		/// `From:` mailbox for outgoing mail.
		mail_from: String = "EV Investment <notifications@evinvest.ltd>",
		/// Origin the cabinet is served from; builds the links inside emails.
		cabinet_url: String = "https://evinvest.ltd/cabinet",
		/// Trailing-24h send ceiling. Gmail's relay caps daily volume and throttles the
		/// account past it, so the dispatcher stops SENDING (never queueing) at this
		/// number. Raise it in step with whatever provider is actually behind the port.
		notification_daily_email_budget: i64 = "1500",
		/// How often the dispatcher looks for due mail.
		notification_dispatch_interval_secs: u64 = "15",
		/// Account-less subscribe attempts allowed per client IP per window.
		subscribe_rate_limit: u32 = "5",
		subscribe_rate_window_secs: u64 = "3600",
	}
}
