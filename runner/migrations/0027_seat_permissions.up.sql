-- The money plane learns a seat's `bank:*` permissions over the bridge
-- (PERMISSIONS_CHANGED), carried on the outbox row.
--
--   user_outbox.permissions — the seat's set when the row was written, on every row;
--                             NULL on rows written before this migration.
--   seat_meanings           — the set last announced for each seat. A boot whose code
--                             gives a seat a different set re-announces it for everyone
--                             holding that seat, then records it; a missing row is a seat
--                             never announced, so the first boot announces every seat
--                             that holds anything.
--
-- `lock_timeout`, SET LOCAL: migrations run ON BOOT, and the ALTER takes ACCESS EXCLUSIVE
-- on the outbox every write appends to.
SET LOCAL lock_timeout = '3s';

ALTER TABLE user_outbox ADD COLUMN permissions TEXT[];

CREATE TABLE seat_meanings (
    role              TEXT PRIMARY KEY,
    bank_permissions  TEXT[] NOT NULL,
    announced_at      BIGINT NOT NULL,
    CONSTRAINT seat_meanings_role CHECK (role IN ('investor', 'operator', 'admin', 'owner'))
);
