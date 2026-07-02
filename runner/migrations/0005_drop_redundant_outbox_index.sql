-- Drop the redundant secondary index on user_outbox.position.
--
-- `position BIGSERIAL NOT NULL UNIQUE` (0002_user_outbox.sql) already creates a unique
-- btree index that fully serves the bridge cursor read
-- (`WHERE position > $1 ORDER BY position ASC`). The separate non-unique index only
-- added write amplification on the outbox insert path and was never chosen over the
-- unique index for the read.
DROP INDEX IF EXISTS user_outbox_position_idx;
