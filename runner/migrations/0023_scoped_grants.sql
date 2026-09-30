-- Scoped grants: a user's role over ONE resource (`allocation:<service_id>`), as
-- opposed to `users.role`, which is platform-wide. Non-money access only — a vertical's
-- panel — so it lives in this plane and is never mirrored over the bridge; rights over
-- an allocation's money are banking's own grants.
--
-- One row per grant EVER made, never updated except to stamp its revocation. A role
-- change is the old row revoked and a new one inserted in the same transaction, so "who
-- held this scope, when, and who gave it to them" is answerable from this table alone;
-- the operator's side of the same story goes to `admin_action` in that transaction.
--
-- The partial unique index is the "one ACTIVE grant per (user, scope)" rule at the
-- column, not only in the handler. It also serves GetMe's lookup by user.
--
-- `lock_timeout`: the foreign keys take SHARE ROW EXCLUSIVE on `users` while the table
-- is created, and migrations run ON BOOT. Without a ceiling the migrator queues behind a
-- long user transaction and every request queues behind the migrator. SET LOCAL, not
-- SET: sqlx runs this on a connection borrowed from the service's pool, and a session
-- SET would outlive the migration on it.
--
-- REVERSIBILITY. A new table nothing else references:
--   DROP TABLE scoped_grants;
-- loses every grant made since, and with them the record of who held which scope.
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
    -- Mirrors `domain::scopes::Scope::parse`; a row the domain cannot read back would
    -- fail every GetMe of its holder.
    CONSTRAINT scoped_grants_scope_format CHECK (scope ~ '^allocation:[a-z0-9_]{1,64}$'),
    CONSTRAINT scoped_grants_role CHECK (role IN ('viewer', 'operator', 'admin')),
    CONSTRAINT scoped_grants_revocation CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE UNIQUE INDEX scoped_grants_active_idx ON scoped_grants (user_id, scope) WHERE revoked_at IS NULL;
-- A scope's current roster, for ListScopedGrants.
CREATE INDEX scoped_grants_scope_idx ON scoped_grants (scope) WHERE revoked_at IS NULL;
