-- The ownership plane's two consilia: taking a fund owner's seat away, and granting
-- one. Both are here because BOTH must be, and admission is the load-bearing half: if
-- one owner could mint another, they could mint four, and then carry any quorum
-- legitimately. Every snapshot and re-validation below would work exactly as designed
-- and the fund would still be robbed.
--
-- WHY THIS LIVES HERE. A seat is `users.role = 'owner'`, a concierge-owned fact, and
-- the bridge to the money plane is one-way. Only this plane may mutate it, so only
-- this plane may authorize the mutation. There is deliberately NO second owner
-- registry: these tables reference `users.id` and nothing else confers ownership.
--
-- WHY THE CONSTRAINTS ARE THIS TIGHT. A wrong row here is not a bug you notice in
-- staging — it is someone's seat, and it cannot be undone. Every rule the domain
-- enforces is ALSO expressed as a CHECK, so a future adapter, a migration, or a
-- console `UPDATE` cannot write a state the rules forbid:
--
--   * a proposal against yourself is unrepresentable (resignation is a separate RPC);
--   * a proposal that could never legally execute is unrepresentable — a removal must
--     leave at least MIN_OWNERS = 2 behind (so it starts at 3), and an admission needs
--     a non-empty `owners \ {initiator}` (so it starts at 2);
--   * two open proposals about the same person are unrepresentable (partial UNIQUE),
--     which is what removes the mutual-expulsion race rather than trying to win it;
--   * a closed proposal without a decision time, or an open one carrying one, is
--     unrepresentable, so "is this still answerable" has exactly one answer.
--
-- WHAT IS NOT STORED. Never the emailed token, never the secret code — only their
-- SHA-256 digests. The plaintext of both exists in the delivery row until the message
-- is sent and is nulled on success, so an attacker with a database copy inherits
-- neither. Nothing is ever deleted: a rejected, expired or void proposal stays
-- readable, because the audit trail must outlive the decision.
--
-- Domain time is BIGINT unix seconds throughout (matching `user_outbox.occurred_at`
-- and `notifications.occurred_at`) — the domain layer is clock-free, so every instant
-- here was supplied by the application rather than by `now()`.

CREATE TABLE owner_removal (
    id                UUID PRIMARY KEY,
    target_user_id    UUID NOT NULL REFERENCES users (id),
    initiator_user_id UUID NOT NULL REFERENCES users (id),
    -- Why, in the initiator's words. Shown to the target and to every peer.
    reason            TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open',
    -- Owners at the moment of opening. The initiator is COUNTED here even though they
    -- get no vote: if opening a proposal shrank the denominator, opening one would be
    -- a way to lower the bar you have to clear.
    owner_count       INTEGER NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    decided_at        BIGINT,
    void_reason       TEXT NOT NULL DEFAULT '',
    -- Monotonic per row: bumped by every transition, and the value the live feed's
    -- clients compare against so a replayed frame cannot move them backwards.
    version           BIGINT NOT NULL DEFAULT 0,
    -- How the target answered from their mailbox. 'remove' ACCEPTS the expulsion.
    target_decision   TEXT NOT NULL DEFAULT 'pending',
    target_decided_at BIGINT,
    target_notified   BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT owner_removal_not_self CHECK (target_user_id <> initiator_user_id),
    CONSTRAINT owner_removal_state CHECK (state IN ('open', 'executed', 'rejected', 'expired', 'cancelled', 'void')),
    CONSTRAINT owner_removal_target_decision CHECK (target_decision IN ('pending', 'remove', 'keep')),
    CONSTRAINT owner_removal_reason_len CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT owner_removal_void_reason_len CHECK (char_length(void_reason) <= 200),
    -- domain::governance::MIN_OWNERS = 2 must REMAIN, so three must be present. The
    -- floor is 2 rather than 3 deliberately: at three owners a floor of three made a bad
    -- actor unremovable forever, and a recoverable payout pause beats a deadlock.
    CONSTRAINT owner_removal_floor CHECK (owner_count >= 3),
    CONSTRAINT owner_removal_ttl CHECK (expires_at > created_at),
    CONSTRAINT owner_removal_decided CHECK ((state = 'open') = (decided_at IS NULL)),
    CONSTRAINT owner_removal_target_decided CHECK ((target_decision = 'pending') = (target_decided_at IS NULL)),
    CONSTRAINT owner_removal_void_reason_only_void CHECK (state = 'void' OR void_reason = '')
);

-- At most ONE open proposal per target. Two owners each opening one against the other
-- is a race with no good winner, so the second write simply fails.
CREATE UNIQUE INDEX owner_removal_open_target_idx ON owner_removal (target_user_id) WHERE state = 'open';
-- The console's list and the expiry sweep both read only the open ones.
CREATE INDEX owner_removal_open_idx ON owner_removal (expires_at) WHERE state = 'open';
CREATE INDEX owner_removal_recent_idx ON owner_removal (created_at DESC);

-- The SNAPSHOTTED eligible-peer set, written once when the proposal opens: every owner
-- except the target and the initiator. Freezing it is what closes roster stuffing (an
-- owner minted afterwards is not here, so they get no say) and what makes "the
-- initiator cannot vote" structural rather than a check somebody can forget.
CREATE TABLE owner_removal_peer (
    removal_id UUID NOT NULL REFERENCES owner_removal (id),
    user_id    UUID NOT NULL REFERENCES users (id),
    vote       TEXT NOT NULL DEFAULT 'pending',
    voted_at   BIGINT,
    PRIMARY KEY (removal_id, user_id),
    CONSTRAINT owner_removal_peer_vote CHECK (vote IN ('pending', 'remove', 'keep')),
    CONSTRAINT owner_removal_peer_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

-- "What am I still being asked to answer?" on every cabinet load.
CREATE INDEX owner_removal_peer_pending_idx ON owner_removal_peer (user_id) WHERE vote = 'pending';

-- The target's emailed credential. ONE row per proposal.
--
-- The token alone can only READ (mail scanners issue automatic GETs for every URL in a
-- message, so the read must be side-effect free); answering additionally needs the
-- secret code, which only a human who opened the message can type. Five failed
-- attempts burn the row permanently, and the counter is incremented in the SAME
-- transaction as the comparison, before it — otherwise concurrent requests slip past
-- the limit.
CREATE TABLE owner_removal_token (
    removal_id UUID PRIMARY KEY REFERENCES owner_removal (id),
    token_hash BYTEA NOT NULL,
    code_hash  BYTEA NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    burned_at  BIGINT,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT,
    CONSTRAINT owner_removal_token_digest CHECK (octet_length(token_hash) = 32 AND octet_length(code_hash) = 32),
    CONSTRAINT owner_removal_token_attempts CHECK (attempts BETWEEN 0 AND 5),
    CONSTRAINT owner_removal_token_burn CHECK (burned_at IS NULL OR attempts >= 5)
);

CREATE UNIQUE INDEX owner_removal_token_hash_idx ON owner_removal_token (token_hash);

-- GRANTING a seat. The same shape as a removal minus the mailbox: there is no token
-- and no candidate vote, because the candidate is not yet an owner and has no say in
-- their own admission, and every voter is a signed-in owner.
--
-- Unanimity of `owners \ {initiator}`, never a majority: a minority able to add owners
-- by majority would simply grow itself into a majority, which is the sock-puppet attack
-- with extra steps.
CREATE TABLE owner_admission (
    id                UUID PRIMARY KEY,
    candidate_user_id UUID NOT NULL REFERENCES users (id),
    initiator_user_id UUID NOT NULL REFERENCES users (id),
    reason            TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open',
    -- Owners at the moment of opening; the initiator is counted but does not vote.
    owner_count       INTEGER NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    decided_at        BIGINT,
    void_reason       TEXT NOT NULL DEFAULT '',
    version           BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT owner_admission_not_self CHECK (candidate_user_id <> initiator_user_id),
    CONSTRAINT owner_admission_state CHECK (state IN ('open', 'executed', 'rejected', 'expired', 'cancelled', 'void')),
    CONSTRAINT owner_admission_reason_len CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT owner_admission_void_reason_len CHECK (char_length(void_reason) <= 200),
    -- `owners \ {initiator}` must be non-empty, so a LONE owner cannot open one. This is
    -- pitfall 21 expressed as a constraint: unanimity over nobody is vacuously true, and
    -- a rule that passes for nobody is a rule that lets one owner mint a second.
    CONSTRAINT owner_admission_needs_a_peer CHECK (owner_count >= 2),
    CONSTRAINT owner_admission_ttl CHECK (expires_at > created_at),
    CONSTRAINT owner_admission_decided CHECK ((state = 'open') = (decided_at IS NULL)),
    CONSTRAINT owner_admission_void_reason_only_void CHECK (state = 'void' OR void_reason = '')
);

-- At most ONE open admission per candidate, so the same person cannot be seated twice
-- by two proposals resolving concurrently.
CREATE UNIQUE INDEX owner_admission_open_candidate_idx ON owner_admission (candidate_user_id) WHERE state = 'open';
CREATE INDEX owner_admission_open_idx ON owner_admission (expires_at) WHERE state = 'open';
CREATE INDEX owner_admission_recent_idx ON owner_admission (created_at DESC);

-- The snapshotted voter set: every owner except the initiator, frozen at open for the
-- same reason the removal's is.
CREATE TABLE owner_admission_peer (
    admission_id UUID NOT NULL REFERENCES owner_admission (id),
    user_id      UUID NOT NULL REFERENCES users (id),
    vote         TEXT NOT NULL DEFAULT 'pending',
    voted_at     BIGINT,
    PRIMARY KEY (admission_id, user_id),
    CONSTRAINT owner_admission_peer_vote CHECK (vote IN ('pending', 'admit', 'reject')),
    CONSTRAINT owner_admission_peer_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

CREATE INDEX owner_admission_peer_pending_idx ON owner_admission_peer (user_id) WHERE vote = 'pending';

-- The audit log, shared by both consilia. Every transition, who caused it, and — for an
-- answer that arrived from a mailbox — from which address and user agent. Append-only.
--
-- Exactly ONE of the two proposal ids is set on every row. A single log rather than two
-- keeps the ownership history readable in one ordering: "who has held a seat, and by
-- whose decision" is one question, not two.
CREATE TABLE governance_event (
    position      BIGSERIAL PRIMARY KEY,
    removal_id    UUID REFERENCES owner_removal (id),
    admission_id  UUID REFERENCES owner_admission (id),
    kind          TEXT NOT NULL,
    actor_user_id UUID REFERENCES users (id),
    -- The aggregate version this event was minted at, so the log and the row agree.
    version       BIGINT NOT NULL,
    occurred_at   BIGINT NOT NULL,
    client_ip     TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    CONSTRAINT governance_event_kind_len CHECK (char_length(kind) <= 64),
    CONSTRAINT governance_event_client_ip_len CHECK (char_length(client_ip) <= 64),
    CONSTRAINT governance_event_user_agent_len CHECK (char_length(user_agent) <= 256),
    CONSTRAINT governance_event_one_subject CHECK ((removal_id IS NULL) <> (admission_id IS NULL))
);

CREATE INDEX governance_event_removal_idx ON governance_event (removal_id, position);
CREATE INDEX governance_event_admission_idx ON governance_event (admission_id, position);

-- The live feed's clock, shared by BOTH consilia. A single counter bumped in the SAME
-- transaction as any governance write — removal or admission — so a reader that sees a
-- committed change also sees the number move, and one subscription covers the whole
-- ownership surface rather than needing one per proposal kind.
--
-- Deliberately a counter table and not a SEQUENCE: `nextval` is non-transactional, so
-- a sequence read could hand out a value for a write that later rolls back, and
-- `last_value` cannot be read consistently alongside the data it is meant to describe.
-- The row lock this takes also serializes governance writes, which at this volume is a
-- feature — the ordering is total.
CREATE TABLE governance_revision (
    id       BOOLEAN PRIMARY KEY DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT governance_revision_singleton CHECK (id)
);

INSERT INTO governance_revision (id) VALUES (TRUE) ON CONFLICT DO NOTHING;

-- Governance mail rides the EXISTING delivery queue (backoff, leases, the daily send
-- budget) rather than standing up a second mailer. Two columns are new:
--
--   * `dedupe_key` makes the money plane's at-least-once relay idempotent — the same
--     key never sends twice;
--   * `payload` carries the typed fields the renderer consumes, including the ONE
--     plaintext copy of the secret code. The dispatcher nulls it on a successful send,
--     so the code does not linger in Postgres after it has been delivered.
ALTER TABLE notification_deliveries ADD COLUMN dedupe_key TEXT;
ALTER TABLE notification_deliveries ADD COLUMN payload JSONB;

CREATE UNIQUE INDEX notification_deliveries_dedupe_idx ON notification_deliveries (dedupe_key) WHERE dedupe_key IS NOT NULL;

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome'));
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_dedupe_len
    CHECK (dedupe_key IS NULL OR char_length(dedupe_key) BETWEEN 1 AND 128);
