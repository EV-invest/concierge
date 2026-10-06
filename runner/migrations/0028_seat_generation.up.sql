-- The database, not the writing binary, decides `user_outbox.permissions`: during a rollout
-- or a rollback, binaries of different ages write side by side, and each would otherwise
-- stamp its own idea of a seat.
--
--   seat_meanings.generation — orders meanings across binaries (`domain::authz::SEAT_GENERATION`);
--                              an update that does not raise it is skipped, so an older
--                              binary's unconditional upsert is a no-op rather than a crash.
--   user_outbox.permissions  — stamped on INSERT from `seat_meanings`, overriding whatever
--                              the writer sent. A role with no meaning row is refused.
--
-- Rows already written keep what they reported; NULL stays NULL.
SET LOCAL lock_timeout = '3s';

-- The default is what v0.13.1's upsert, which names no generation, lands at: NOT NULL is
-- checked before ON CONFLICT, so without it that binary could not boot.
ALTER TABLE seat_meanings ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE seat_meanings DROP CONSTRAINT seat_meanings_role;

-- v0.13.1 recorded a seat only once it held something, so `investor` may be missing, and
-- a write between this migration and the boot's announce would otherwise be refused.
INSERT INTO seat_meanings (role, bank_permissions, announced_at, generation)
VALUES ('investor', '{}', extract(epoch FROM now())::BIGINT, 0)
ON CONFLICT (role) DO NOTHING;

CREATE FUNCTION seat_meanings_only_newer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.generation > OLD.generation THEN
        RETURN NEW;
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER seat_meanings_only_newer BEFORE UPDATE ON seat_meanings
    FOR EACH ROW EXECUTE FUNCTION seat_meanings_only_newer();

CREATE FUNCTION user_outbox_stamp_permissions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT bank_permissions INTO NEW.permissions FROM seat_meanings WHERE role = NEW.role;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'seat % has no meaning in seat_meanings', NEW.role;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER user_outbox_stamp_permissions BEFORE INSERT ON user_outbox
    FOR EACH ROW EXECUTE FUNCTION user_outbox_stamp_permissions();
