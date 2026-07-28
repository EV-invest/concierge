-- The notification plane: who we may contact, about what, and the durable record
-- of everything we said.
--
-- This is the IDENTITY plane — nothing here knows about balances or the ledger.
-- Money-shaped notifications arrive as text the banking plane already rendered,
-- pushed over `NotificationService.Emit`; concierge stores and delivers, and never
-- reads back into banking.
--
-- ONE SUBSCRIBER TABLE, TWO POPULATIONS. A subscriber with `user_id` is a signed-in
-- cabinet user; a subscriber with `user_id IS NULL` is an account-less address that
-- subscribed from the public site. They are deliberately the same row shape so the
-- fan-out has one path and the read paths filter, rather than two parallel systems
-- drifting apart. The account-less half can only ever receive email, and only after
-- `confirmed_at` is set (double opt-in) — which is also what stops a subscribe flood
-- from turning us into someone else's spam cannon.
--
-- EVERY CHANNEL IS OPT-OUT. `in_app_enabled` and `email_enabled` may BOTH be false.
-- That is a valid, fully-supported "stop contacting me" state, not a broken record.

CREATE TABLE notification_subscribers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL ⇒ account-less (public-site) subscriber: email-only, confirmation-gated.
    user_id           UUID,
    -- Delivery address. For signed-in subscribers this mirrors `users.email` at
    -- subscribe time; the service re-reads the live address before every send, so
    -- this column is a fallback for the account-less half, not a source of truth.
    email             TEXT NOT NULL,
    email_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Master switches. Both false is legal — see the header.
    in_app_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    email_enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    -- Double opt-in. Signed-in subscribers are confirmed on creation (Google already
    -- verified the address); account-less ones must click through.
    confirm_token     TEXT,
    -- When the last confirmation mail went out. The per-address send throttle reads
    -- this, so a repeated subscribe for the same address cannot re-mail on demand.
    confirm_sent_at   TIMESTAMPTZ,
    confirmed_at      TIMESTAMPTZ,
    -- Opaque one-click List-Unsubscribe target. Never guessable, never reused.
    unsubscribe_token TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notification_subscribers_email_len CHECK (char_length(email) <= 320)
);

-- At most one subscriber per account, and one per address among the account-less.
-- Partial uniqueness rather than a plain UNIQUE: a signed-in user and an old
-- account-less subscription may legitimately share an address until they are merged.
CREATE UNIQUE INDEX notification_subscribers_user_idx
    ON notification_subscribers (user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX notification_subscribers_anon_email_idx
    ON notification_subscribers (lower(email)) WHERE user_id IS NULL;
CREATE UNIQUE INDEX notification_subscribers_unsub_idx
    ON notification_subscribers (unsubscribe_token);
CREATE UNIQUE INDEX notification_subscribers_confirm_idx
    ON notification_subscribers (confirm_token) WHERE confirm_token IS NOT NULL;

-- What a subscriber follows. Absence of a row means "not subscribed"; the row's
-- `email_enabled` is the per-topic email copy, gated by the subscriber master switch.
CREATE TABLE notification_subscriptions (
    subscriber_id UUID NOT NULL,
    topic         TEXT NOT NULL,
    email_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subscriber_id, topic),
    CONSTRAINT notification_subscriptions_topic_len CHECK (char_length(topic) <= 64)
);

-- The in-app inbox. Rows are never deleted by the application: this is the durable
-- record of what the platform told a user and when. Retention is an ops concern.
CREATE TABLE notifications (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id UUID NOT NULL,
    topic         TEXT NOT NULL,
    kind          TEXT NOT NULL,
    title         TEXT NOT NULL,
    body          TEXT NOT NULL DEFAULT '',
    link          TEXT NOT NULL DEFAULT '',
    -- Idempotency key scoped to the subscriber; the emitter owns its shape.
    dedupe_key    TEXT NOT NULL,
    -- Domain time of the underlying event, unix seconds — same convention as
    -- `user_outbox.occurred_at`. `created_at` is the row's own wall clock.
    occurred_at   BIGINT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at       TIMESTAMPTZ,
    CONSTRAINT notifications_topic_len  CHECK (char_length(topic) <= 64),
    CONSTRAINT notifications_kind_len   CHECK (char_length(kind) <= 64),
    CONSTRAINT notifications_title_len  CHECK (char_length(title) <= 200),
    CONSTRAINT notifications_body_len   CHECK (char_length(body) <= 2000),
    CONSTRAINT notifications_link_len   CHECK (char_length(link) <= 512),
    CONSTRAINT notifications_dedupe_len CHECK (char_length(dedupe_key) <= 128)
);

-- Makes Emit idempotent: a retried at-least-once emit collides here and is dropped.
CREATE UNIQUE INDEX notifications_dedupe_idx ON notifications (subscriber_id, dedupe_key);
-- The inbox read path: newest first, id as the tiebreaker so the keyset cursor is total.
CREATE INDEX notifications_inbox_idx ON notifications (subscriber_id, created_at DESC, id DESC);
-- The unread badge is polled on every cabinet page; keep it off the wide index.
CREATE INDEX notifications_unread_idx ON notifications (subscriber_id) WHERE read_at IS NULL;

-- The outbound email queue. Unlike `user_outbox` there is no external puller and no
-- global cursor — concierge drains this itself — so rows are CLAIMED with
-- `FOR UPDATE SKIP LOCKED` and no advisory lock is needed: commit order is irrelevant
-- when nothing reads by position.
CREATE TABLE notification_deliveries (
    id              BIGSERIAL PRIMARY KEY,
    -- NULL for lifecycle mail that has no inbox row (the confirmation message).
    notification_id UUID,
    subscriber_id   UUID NOT NULL,
    -- 'notification' (a copy of an inbox row) | 'confirm' (double opt-in).
    kind            TEXT NOT NULL DEFAULT 'notification',
    -- Frozen at enqueue time so a later address change cannot silently redirect
    -- mail that was already authorised to a different recipient.
    recipient       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT NOT NULL DEFAULT '',
    sent_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notification_deliveries_status CHECK (status IN ('pending', 'sent', 'failed')),
    CONSTRAINT notification_deliveries_kind   CHECK (kind IN ('notification', 'confirm')),
    CONSTRAINT notification_deliveries_recipient_len CHECK (char_length(recipient) <= 320)
);

-- The dispatcher's claim query: due, pending, oldest first.
CREATE INDEX notification_deliveries_due_idx
    ON notification_deliveries (next_attempt_at) WHERE status = 'pending';
-- The daily send-budget check counts recent sends; keep that scan narrow.
CREATE INDEX notification_deliveries_sent_idx
    ON notification_deliveries (sent_at) WHERE status = 'sent';
