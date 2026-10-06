-- Permission-scope IAM: tenants, their published catalogs, and grants over them. Replaces
-- scoped grants and relying-party access policies outright.
--
--   tenants  — a namespace a relying party owns (`sa`). The four namespaces seats are
--              made of are not claimable, so nothing granted here can reach a seat's
--              permissions. `granting_seats_hold_all`: a seat holding `iam:tenants:grant`
--              holds every permission of the tenant without a grant row.
--   catalogs — every catalog the tenant's client ever published (`concierge_iam::Catalog`);
--              the current one is the highest `version`. `published_by` is the client,
--              NULL only for the seed below.
--   grants   — one row per grant EVER made, revoked by stamping. `target` is stored as
--              named (an alias, a permission or a `*` pattern), so a republished alias
--              reaches every holder. A target the current catalog no longer defines
--              grants nothing and stays as history.
--
-- Backfill: every `allocation:service_arb` grant, revoked history included, becomes the
-- `sa` alias of the same name — except a grant someone made to themselves, which this
-- plane no longer allows; a NOTICE counts those. No other scope was ever granted.
-- `scoped_grants` and `rp_clients.access_policy` are dropped: every client signs in any
-- active account, and what they may do there is the tenant's permissions.
--
-- `lock_timeout`: the foreign keys take SHARE ROW EXCLUSIVE on `users` and `rp_clients`,
-- and migrations run ON BOOT. SET LOCAL, not SET: sqlx runs this on a connection
-- borrowed from the service's pool, and a session SET would outlive it.
--
-- REVERSIBILITY: `0026_iam.down.sql` (`sqlx migrate revert`, which also deletes this
-- version from `_sqlx_migrations`, without which the older binary refuses to boot). It
-- rebuilds `scoped_grants` and `access_policy` from what `grants` says NOW, so a
-- revocation made after this migration stays revoked; grants of anything but
-- `sa:operator`/`sa:admin` have no older form and are lost.
SET LOCAL lock_timeout = '3s';

CREATE TABLE tenants (
    id                       TEXT PRIMARY KEY,
    namespace                TEXT NOT NULL UNIQUE,
    granting_seats_hold_all  BOOLEAN NOT NULL,
    created_at               BIGINT NOT NULL,
    CONSTRAINT tenants_id_format CHECK (id ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT tenants_namespace_format CHECK (namespace ~ '^[a-z][a-z0-9_]{0,31}$' AND namespace NOT IN ('iam', 'concierge', 'bank', 'seat'))
);

CREATE TABLE catalogs (
    tenant_id     TEXT NOT NULL REFERENCES tenants (id),
    version       BIGINT NOT NULL,
    catalog       JSONB NOT NULL,
    published_at  BIGINT NOT NULL,
    published_by  TEXT REFERENCES rp_clients (client_id),
    PRIMARY KEY (tenant_id, version),
    CONSTRAINT catalogs_version CHECK (version >= 0)
);

CREATE TABLE grants (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id),
    namespace   TEXT NOT NULL REFERENCES tenants (namespace),
    target      TEXT NOT NULL,
    granted_by  UUID NOT NULL REFERENCES users (id),
    granted_at  BIGINT NOT NULL,
    revoked_at  BIGINT,
    revoked_by  UUID REFERENCES users (id),
    reason      TEXT,
    -- Mirrors `domain::iam::Target::parse`.
    CONSTRAINT grants_target_format CHECK (char_length(target) <= 128 AND target ~ '^[a-z][a-z0-9_]*(:([a-z0-9_]+|\*))+$'),
    CONSTRAINT grants_target_namespace CHECK (split_part(target, ':', 1) = namespace),
    CONSTRAINT grants_not_to_self CHECK (user_id <> granted_by),
    CONSTRAINT grants_revocation CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT grants_reason_len CHECK (char_length(reason) <= 500)
);

CREATE UNIQUE INDEX grants_active_idx ON grants (user_id, target) WHERE revoked_at IS NULL;
CREATE INDEX grants_namespace_idx ON grants (namespace) WHERE revoked_at IS NULL;

-- The global admin has always been the panel's admin.
INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at)
VALUES ('sa', 'sa', TRUE, extract(epoch FROM now())::BIGINT);

ALTER TABLE rp_clients ADD COLUMN tenant_id TEXT REFERENCES tenants (id);
UPDATE rp_clients SET tenant_id = 'sa' WHERE client_id = 'sa';
ALTER TABLE rp_clients ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE rp_clients DROP COLUMN access_policy;

-- The panel's catalog at the time of writing, so the backfilled aliases resolve before
-- the panel first publishes its own (any version beats 0).
INSERT INTO catalogs (tenant_id, version, catalog, published_at, published_by)
VALUES ('sa', 0, '{
  "version": 0,
  "permissions": [
    "sa:admin:sources:manage",
    "sa:analysis:experiments:edit", "sa:analysis:experiments:read",
    "sa:analysis:grafana:edit", "sa:analysis:grafana:read",
    "sa:work:leads:edit", "sa:work:leads:read", "sa:work:pii:see",
    "sa:work:places:edit", "sa:work:pricing:edit"
  ],
  "aliases": {
    "sa:admin": [
      "sa:admin:sources:manage",
      "sa:analysis:experiments:edit", "sa:analysis:experiments:read",
      "sa:analysis:grafana:edit", "sa:analysis:grafana:read",
      "sa:work:leads:edit", "sa:work:leads:read", "sa:work:pii:see",
      "sa:work:places:edit", "sa:work:pricing:edit"
    ],
    "sa:operator": [
      "sa:analysis:experiments:read", "sa:analysis:grafana:read",
      "sa:work:leads:edit", "sa:work:leads:read", "sa:work:pii:see"
    ]
  },
  "delegations": { "sa:admin": ["sa:operator"] }
}'::JSONB, extract(epoch FROM now())::BIGINT, NULL);

INSERT INTO grants (user_id, namespace, target, granted_by, granted_at, revoked_at, revoked_by)
SELECT user_id, 'sa', 'sa:' || role, granted_by, granted_at, revoked_at, revoked_by
FROM scoped_grants
WHERE scope = 'allocation:service_arb' AND user_id <> granted_by
ORDER BY id;

DO $$
DECLARE
    dropped BIGINT;
BEGIN
    SELECT count(*) INTO dropped FROM scoped_grants WHERE scope <> 'allocation:service_arb' OR user_id = granted_by;
    IF dropped > 0 THEN
        RAISE NOTICE '0026_iam: % scoped grants (self-granted, or on a scope with no tenant) were not carried over', dropped;
    END IF;
END $$;

DROP TABLE scoped_grants;
