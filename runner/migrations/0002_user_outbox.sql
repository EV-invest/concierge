-- The cross-plane bridge's transactional outbox.
--
-- The directory writes a row here in the SAME transaction as the user mutation that
-- produced it; the bridge serves it to the banking money plane over
-- `UserEvents.PullUserLifecycle`, which reads rows with `position > after_position`
-- oldest-first, capped by `limit`. Each row carries everything the banking consumer
-- needs to materialize/gate a user without a synchronous callback (one-way bridge).
--
-- Delivery is at-least-once: `event_id` is the dedupe key, `sequence` (the user's
-- `row_version` at emit time) is the per-user ORDER key. `position` is the global
-- monotonic cursor the puller advances.
CREATE TABLE user_outbox (
    event_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    position       BIGSERIAL NOT NULL UNIQUE,
    user_id        UUID NOT NULL,
    kind           TEXT NOT NULL,
    kyc_level      INTEGER NOT NULL DEFAULT 0,
    occurred_at    BIGINT NOT NULL,
    sequence       BIGINT NOT NULL,
    auth_subject   TEXT NOT NULL,
    email          TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    token_version  BIGINT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX user_outbox_position_idx ON user_outbox (position);
