ev::settings! {
	/// Runner configuration for the concierge modular monolith — reads every field
	/// from the environment (env-only, no config files, no hot reload).
	///
	/// The `#[required_in("production")]` fields are the ones whose absence is a
	/// *silent* no-op rather than a crash — mail that only gets logged, error
	/// reports and analytics nobody receives. Unset is right locally (the whole
	/// emit → queue → render path still runs); in production it is an outage
	/// that never pages, so there it fails the boot instead.
	pub struct AppConfig {
		database_url: String,
		/// gRPC listener address for the modular-monolith surface.
		bind: std::net::SocketAddr = "127.0.0.1:50061",
		/// Max connections for the request-serving Postgres pool.
		db_max_connections: u32 = "10",
		/// The fund's genesis owners (comma-separated). Each entry is either a CONCIERGE
		/// canonical user id (a UUID) or an e-mail address — an operator knows the mailbox
		/// long before the person's first sign-in mints their id, so the list can be filled
		/// in ahead of time and resolves itself once they log in.
		///
		/// It does TWO things, both of which switch themselves off for good the moment the
		/// persisted owner registry stops being empty:
		///   * the genesis seed writes these people into `users.role` (see `crate::genesis`);
		///   * until that lands, a listed subject authorizes as `Role::Owner` so the console
		///     is not locked out of a fund that has no owners yet (`crate::authz`).
		///
		/// Empty ⇒ neither happens. After genesis it is inert forever: the roster can never
		/// return to zero, because both expulsion and `ResignOwnership` stop at
		/// `MIN_OWNERS`.
		owner_subjects: Vec<String> = "",
		/// Shared bearer token for the cross-plane bridge (`UserEvents.PullUserLifecycle`).
		#[secret]
		bridge_service_token: String,
		#[required_in("production")]
		sentry_dsn: Option<String>,
		/// PostHog project key for native product-analytics capture.
		///
		/// Deliberately NOT `required_in("production")`, unlike `sentry_dsn`: a
		/// missing error reporter hides failures, while missing product analytics
		/// only forgoes a metric. That must never be the reason a service refuses
		/// to boot.
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
		#[required_in("production")]
		smtp_host: Option<String>,
		smtp_port: u16 = "587",
		#[required_in("production")]
		smtp_username: Option<String>,
		#[secret]
		#[required_in("production")]
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
		/// Base URL of the owner-removal approval page; the emailed token is appended as
		/// the final path segment, so a message carries `<this>/<token>`.
		///
		/// It is a CABINET route (`/{locale}/cabinet/owner-removal/{token}`) served
		/// publicly — the person opening it is the one being removed and may well not be
		/// signed in, but there is no `/governance/*` surface on the site and a link into
		/// one would 404 every removal invitation ever sent.
		governance_approval_url: String = "https://evinvest.ltd/cabinet/owner-removal",
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// What a production deploy must provide. The gitops preflight diffs the
	/// cluster Secret against this list (`--print-required-vars`), so a change
	/// here is a change to the deploy contract.
	#[test]
	fn production_requires_the_silent_failure_surface() {
		assert_eq!(
			AppConfig::required_var_names("production"),
			// POSTHOG_KEY is read (it is in the env surface above) but never
			// required: analytics is a metric, not a safety net, so it must not be
			// able to keep a service from booting. See the field's comment.
			vec![
				"DATABASE_URL",
				"BRIDGE_SERVICE_TOKEN",
				"SENTRY_DSN",
				"PUBLIC_ORIGIN",
				"SMTP_HOST",
				"SMTP_USERNAME",
				"SMTP_PASSWORD",
			]
		);
		// Locally, only what the process genuinely cannot start without.
		assert_eq!(AppConfig::required_var_names("development"), vec!["DATABASE_URL", "BRIDGE_SERVICE_TOKEN", "PUBLIC_ORIGIN"]);
	}

	fn minimal_env(var: &str) -> Option<String> {
		match var {
			"DATABASE_URL" => Some("postgres://localhost/concierge"),
			"BRIDGE_SERVICE_TOKEN" => Some("token"),
			"PUBLIC_ORIGIN" => Some("https://evinvest.ltd"),
			_ => None,
		}
		.map(str::to_string)
	}

	#[test]
	fn a_production_deploy_without_mail_fails_to_boot() {
		let error = AppConfig::from_source(|var| if var == "APP_ENV" { Some("production".to_string()) } else { minimal_env(var) }).expect_err("production without a mailer must not boot");

		let vars: Vec<&str> = error.errors.iter().map(|e| e.var.as_str()).collect();
		assert_eq!(vars, vec!["SENTRY_DSN", "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"]);
	}

	/// The emailed link must point at a page that exists. It is a CABINET route served
	/// publicly, NOT a `/governance/*` path — there is no such surface on the site, and
	/// an invitation linking into one would 404 for every owner who ever received it.
	///
	/// The token is appended as the final segment, so the base must carry no trailing
	/// slash and no query string.
	#[test]
	fn the_approval_link_points_into_the_cabinet() {
		let config = AppConfig::from_source(minimal_env).expect("boot");
		let base = &config.governance_approval_url;
		let path = base.strip_prefix("https://evinvest.ltd").expect("the public site: {base}");
		assert_eq!(path, "/cabinet/owner-removal", "the cabinet serves /{{locale}}/cabinet/owner-removal/{{token}}");
		assert!(!base.ends_with('/'), "the token is appended as `<base>/<token>`");
		assert!(!base.contains('?'), "a query string would swallow the token segment");
	}

	#[test]
	fn the_same_environment_is_fine_in_development() {
		let config = AppConfig::from_source(minimal_env).expect("a laptop needs no mailer");
		assert!(config.smtp_host.is_none());
		assert_eq!(config.app_env, "development");
	}
}
