# Prod config (secret-free, committable). Evaluated to JSON at image-build time
# by the flake — the runtime container carries no `nix`, only the baked result.
# `{ env = ... }` refs resolve at startup from the container env (the image's
# baked contract env + gitops' k8s Secret `envFrom`); a missing var fails the
# boot loudly, which is the whole point.
{
  database_url.env = "DATABASE_URL";
  bind = "0.0.0.0:55670";
  web_bind = "0.0.0.0:55671";
  public_origin = "https://evinvest.ltd";
  app_env = "production";
  bridge_service_token.env = "BRIDGE_SERVICE_TOKEN";
}
