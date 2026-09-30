-- Scope roles narrow to `operator | admin`: `viewer` is gone. A read-only holder of a
-- scope would be exactly an ordinary signed-in user (a global `investor`), and that user
-- has no access to the service at all — so a `viewer` grant opened nothing while looking
-- as if it did. `domain::scopes::ScopeRole` no longer has the variant and refuses
-- 'viewer' as an unknown role; this file makes the column agree, because a row the domain
-- cannot read back would fail every GetMe of its holder.
--
-- DELETE, not a revocation. Revoking would stamp `revoked_at`/`revoked_by` and leave
-- `role = 'viewer'` on the row, and the CHECK below binds EVERY row, the revoked history
-- included — so the rows would still block it. Keeping them would take a CHECK that
-- carves out revoked viewers, i.e. a value the domain cannot parse living on in the
-- table, plus a `revoked_by` to put on the stamp when nobody revoked anything (the
-- constraint `scoped_grants_revocation` demands one); inventing that actor would forge
-- the very audit trail the table exists to keep. And there is nothing to lose: 0023
-- has never been applied in production (it ships in the same release as this file), so
-- the only viewer rows are on dev and test databases. Nothing references
-- `scoped_grants.id` by foreign key.
--
-- `lock_timeout`, as in 0023 and for the same reason: migrations run ON BOOT, and the
-- DROP/ADD CONSTRAINT takes ACCESS EXCLUSIVE on a table GetMe reads on every call.
-- Better to fail the boot in three seconds and retry than to queue every request behind
-- the migrator. SET LOCAL, not SET: sqlx runs this file in its own transaction on a
-- connection borrowed from the service's pool, and a session SET would outlive it.
--
-- REVERSIBILITY. The constraint widens back freely --
--   ALTER TABLE scoped_grants DROP CONSTRAINT scoped_grants_role;
--   ALTER TABLE scoped_grants ADD CONSTRAINT scoped_grants_role
--       CHECK (role IN ('viewer', 'operator', 'admin'));
-- -- but the deleted viewer rows do not come back; on a database that held any, only a
-- restore from backup returns them. Production held none.

SET LOCAL lock_timeout = '3s';

DELETE FROM scoped_grants WHERE role = 'viewer';

ALTER TABLE scoped_grants DROP CONSTRAINT scoped_grants_role;
ALTER TABLE scoped_grants ADD CONSTRAINT scoped_grants_role CHECK (role IN ('operator', 'admin'));
