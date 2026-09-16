# Prod config reference (secret-free) — kept for documentation only.
# The actual values are set as direct env vars in the container contract
# (flake.nix -> containerStd.containers."".env) and read by ev::settings!
# from_env() at runtime. No longer baked to JSON or mounted as a config file.
{
  database_url.env = "DATABASE_URL";
  bind = "0.0.0.0:55670";
  web_bind = "0.0.0.0:55671";
  public_origin = "https://evinvest.ltd";
  app_env = "production";
  bridge_service_token.env = "BRIDGE_SERVICE_TOKEN";
  # The bridge seams over TLS on a second port (banking#199 phase 2); the PEM
  # files are the mounted Secret keys BRIDGE_TLS_CERT_PEM / BRIDGE_TLS_KEY_PEM.
  bridge_tls_bind = "0.0.0.0:55672";
  bridge_tls_cert_pem_file = "/etc/settings/BRIDGE_TLS_CERT_PEM";
  bridge_tls_key_pem_file = "/etc/settings/BRIDGE_TLS_KEY_PEM";
}
