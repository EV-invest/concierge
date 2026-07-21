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
}
