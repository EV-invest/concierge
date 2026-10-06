-- Back to scoped grants and access policies, from what `grants` says now: a revocation
-- made since 0026 stays revoked. Only `sa:operator`/`sa:admin` have an older form; every
-- other grant is lost. A user holding both keeps `admin`, the one active row 0023 allows.
SET LOCAL lock_timeout = '3s';

CREATE TABLE scoped_grants (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id),
    scope       TEXT NOT NULL,
    role        TEXT NOT NULL,
    granted_by  UUID NOT NULL REFERENCES users (id),
    granted_at  BIGINT NOT NULL,
    revoked_at  BIGINT,
    revoked_by  UUID REFERENCES users (id),
    CONSTRAINT scoped_grants_scope_format CHECK (scope ~ '^allocation:[a-z0-9_]{1,64}$'),
    CONSTRAINT scoped_grants_role CHECK (role IN ('operator', 'admin')),
    CONSTRAINT scoped_grants_revocation CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE UNIQUE INDEX scoped_grants_active_idx ON scoped_grants (user_id, scope) WHERE revoked_at IS NULL;
CREATE INDEX scoped_grants_scope_idx ON scoped_grants (scope) WHERE revoked_at IS NULL;

INSERT INTO scoped_grants (user_id, scope, role, granted_by, granted_at, revoked_at, revoked_by)
SELECT user_id, 'allocation:service_arb', split_part(target, ':', 2), granted_by, granted_at, revoked_at, revoked_by
FROM grants
WHERE target IN ('sa:operator', 'sa:admin') AND revoked_at IS NOT NULL
ORDER BY id;

INSERT INTO scoped_grants (user_id, scope, role, granted_by, granted_at)
SELECT DISTINCT ON (user_id) user_id, 'allocation:service_arb', split_part(target, ':', 2), granted_by, granted_at
FROM grants
WHERE target IN ('sa:operator', 'sa:admin') AND revoked_at IS NULL
ORDER BY user_id, target = 'sa:admin' DESC;

ALTER TABLE rp_clients ADD COLUMN access_policy TEXT;
UPDATE rp_clients SET access_policy = 'scope:allocation:service_arb' WHERE tenant_id = 'sa';
UPDATE rp_clients SET access_policy = 'public' WHERE access_policy IS NULL;
ALTER TABLE rp_clients ALTER COLUMN access_policy SET NOT NULL;
ALTER TABLE rp_clients ADD CONSTRAINT rp_clients_access_policy_format CHECK (access_policy = 'public' OR access_policy ~ '^scope:allocation:[a-z0-9_]{1,64}$');
ALTER TABLE rp_clients DROP COLUMN tenant_id;

DROP TABLE grants;
DROP TABLE catalogs;
DROP TABLE tenants;
