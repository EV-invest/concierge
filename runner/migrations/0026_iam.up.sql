-- Permission-scope IAM: tenants, their published catalogs, and grants over them.
--
--   tenants  — a namespace a relying party owns (`sa`). The four namespaces seats are
--              made of are not claimable, so nothing granted here can reach a seat's
--              permissions. `legacy_scope` maps the `allocation:<service>` scope the old
--              GrantScope/RevokeScope still speak onto the tenant; it goes with them.
--   catalogs — the tenant's current catalog as its client last published it: concrete
--              permissions and aliases over them (`concierge_iam::Catalog`). One row per
--              tenant; `version` only moves forward.
--   grants   — one row per grant EVER made, revoked by stamping, like `scoped_grants`.
--              `target` is stored as named (an alias, a permission or a `*` pattern), so
--              a republished alias reaches every holder. A target the current catalog no
--              longer defines grants nothing and stays as history.
--
-- Backfill: every `allocation:service_arb` grant, revoked history included, becomes the
-- `sa` alias of the same name. `scoped_grants` is no longer written; it is dropped once
-- GrantScope is. Grants on any other scope have no tenant to land in and stay behind; a
-- NOTICE counts them.
--
-- `lock_timeout`: the foreign keys take SHARE ROW EXCLUSIVE on `users` and `rp_clients`,
-- and migrations run ON BOOT. SET LOCAL, not SET: sqlx runs this on a connection
-- borrowed from the service's pool, and a session SET would outlive it.
--
-- REVERSIBILITY. Nothing older references these tables:
--   ALTER TABLE rp_clients DROP COLUMN tenant_id;
--   DROP TABLE grants; DROP TABLE catalogs; DROP TABLE tenants;
-- loses every grant made since; `scoped_grants` still holds the state of this moment.
SET LOCAL lock_timeout = '3s';

CREATE TABLE tenants (
    id            TEXT PRIMARY KEY,
    namespace     TEXT NOT NULL UNIQUE,
    legacy_scope  TEXT UNIQUE,
    created_at    BIGINT NOT NULL,
    CONSTRAINT tenants_id_format CHECK (id ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT tenants_namespace_format CHECK (namespace ~ '^[a-z][a-z0-9_]{0,31}$' AND namespace NOT IN ('iam', 'concierge', 'bank', 'seat')),
    CONSTRAINT tenants_legacy_scope_format CHECK (legacy_scope IS NULL OR legacy_scope ~ '^allocation:[a-z0-9_]{1,64}$')
);

ALTER TABLE rp_clients ADD COLUMN tenant_id TEXT REFERENCES tenants (id);

CREATE TABLE catalogs (
    tenant_id     TEXT PRIMARY KEY REFERENCES tenants (id),
    version       BIGINT NOT NULL,
    catalog       JSONB NOT NULL,
    published_at  BIGINT NOT NULL,
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
    CONSTRAINT grants_revocation CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT grants_reason_len CHECK (char_length(reason) <= 500)
);

CREATE UNIQUE INDEX grants_active_idx ON grants (user_id, target) WHERE revoked_at IS NULL;
CREATE INDEX grants_namespace_idx ON grants (namespace) WHERE revoked_at IS NULL;

INSERT INTO tenants (id, namespace, legacy_scope, created_at)
VALUES ('sa', 'sa', 'allocation:service_arb', extract(epoch FROM now())::BIGINT);

UPDATE rp_clients SET tenant_id = 'sa' WHERE client_id = 'sa';

-- The panel's catalog at the time of writing, so the backfilled aliases resolve before
-- the panel first publishes its own (any version beats 0).
INSERT INTO catalogs (tenant_id, version, catalog, published_at)
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
  }
}'::JSONB, extract(epoch FROM now())::BIGINT);

INSERT INTO grants (user_id, namespace, target, granted_by, granted_at, revoked_at, revoked_by)
SELECT user_id, 'sa', 'sa:' || role, granted_by, granted_at, revoked_at, revoked_by
FROM scoped_grants
WHERE scope = 'allocation:service_arb'
ORDER BY id;

DO $$
DECLARE
    stranded BIGINT;
BEGIN
    SELECT count(*) INTO stranded FROM scoped_grants WHERE scope <> 'allocation:service_arb' AND revoked_at IS NULL;
    IF stranded > 0 THEN
        RAISE NOTICE '0026_iam: % active scoped grants on scopes with no tenant were not carried over', stranded;
    END IF;
END $$;
