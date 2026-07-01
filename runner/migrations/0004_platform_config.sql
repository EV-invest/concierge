-- Platform/cabinet control-plane config: the operator console's "Cabinet" screen.
--
-- Non-money platform state owned by the identity plane: maintenance mode (the
-- cabinet holding page), the live announcement banner, and feature flags. The
-- money-plane "read-only mode" is NOT here — that kill-switch lives in banking.

-- Singleton row (id is always TRUE), mirroring the bridge_cursor singleton pattern.
CREATE TABLE platform_config (
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE,
    maintenance_mode    BOOLEAN NOT NULL DEFAULT FALSE,
    announcement_title  TEXT NOT NULL DEFAULT '',
    announcement_body   TEXT NOT NULL DEFAULT '',
    announcement_active BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT platform_config_singleton CHECK (id)
);

INSERT INTO platform_config (id) VALUES (TRUE) ON CONFLICT DO NOTHING;

CREATE TABLE feature_flags (
    key         TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    rollout     INTEGER NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
