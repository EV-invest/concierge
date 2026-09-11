-- Governance over a PERSON's standing: permanent suspension, reinstatement from one,
-- and the `admin` seat — plus the emergency hold that had to exist first, and the audit
-- row none of these decisions has ever written.
--
-- WHY THE HOLD COMES FIRST. Suspension used to be one admin's call, and that was the
-- only control that stops money ALREADY queued: the money plane re-reads the frozen flag
-- at dispatch, so a suspension catches a withdrawal inside the dispatcher's sweep. Moving
-- it wholesale to a quorum by mail would have traded a ~30s brake for one that takes
-- hours, and in those hours a compromised account can have a broadcast on chain, which is
-- irreversible. So the verb SPLITS: `users.suspended_by = 'admin_hold'` is one actor's
-- brake and carries its own deadline, and `'governance'` is the owners' verdict and
-- carries none. One actor may stop money temporarily; one actor may never stop it
-- permanently, and one actor may never LIFT what the owners decided.
--
-- WHY ONE PROPOSAL TABLE AND NOT THREE. Suspension, reinstatement and admin admission are
-- the same question — "do the owners agree to change this person's standing?" — differing
-- only in which column of `users` the verdict writes. `0009_governance.sql` already
-- argues this for its own two consilia (one `governance_event` log, one `Lifecycle`,
-- one `unanimity`); three near-identical tables here would drift the first time one of
-- them was edited.
--
-- THE PASSING RULE IS A MAJORITY, not the unanimity the OWNER consilia use, and the
-- difference is deliberate. Unanimity guards the roster because a minority able to add
-- owners by majority grows itself into a majority. Neither thing decided here has that
-- property: `admin` cannot vote in any consilium and cannot be granted `owner`, and a
-- suspension is defensive and reversible by the same body. Against that, unanimity here
-- would COST safety — a hold lapses in 24h, so ratifying one races a clock, and under
-- unanimity one unreachable owner does not delay the verdict, they decide it by releasing
-- a compromised account at the deadline. What is preserved is the property that matters:
-- the initiator is excluded from the voter set and the threshold is at least one, so no
-- single actor ever acts alone. `domain::governance::majority` carries the full argument.
--
-- Domain time is BIGINT unix seconds throughout, matching `owner_removal` and
-- `user_outbox` — the domain layer is clock-free, so every instant here was supplied by
-- the application rather than by `now()`.

-- WHY BOTH COLUMNS ARE NULLABLE AND CARRY NO CROSS-COLUMN CHECK AGAINST `status`.
-- Migrations run at service BOOT, so for the length of a rollout the PREVIOUS build is
-- still serving with this schema already applied, and it writes `status = 'disabled'`
-- knowing nothing about these columns. A CHECK tying the two together would turn that
-- into a constraint violation on every suspension the old pods handled. The columns are
-- therefore additive only, and the pairing is an invariant of the aggregate
-- (`domain::users::User`), which is the one writer of both.
--
-- A disabled row with `suspended_by IS NULL` is consequently a real and expected state:
-- every account suspended before this migration reads as one. It is deliberately given
-- the OLD semantics — liftable by one admin, lapsing never — because that is the rule
-- those accounts were actually suspended under, and silently promoting them to a
-- governance verdict nobody voted on would be a worse lie than leaving them as they are.
-- There is no backfill for the same reason.
ALTER TABLE users ADD COLUMN suspended_by TEXT;
-- When an 'admin_hold' lapses. NULL for a governance verdict (nothing lapses) and for the
-- legacy rows above.
ALTER TABLE users ADD COLUMN hold_expires_at BIGINT;

ALTER TABLE users ADD CONSTRAINT users_suspended_by
    CHECK (suspended_by IS NULL OR suspended_by IN ('admin_hold', 'governance'));
-- A deadline only ever belongs to a hold. A governance suspension carrying one would be
-- a verdict that quietly expires, which is the exact failure this whole migration exists
-- to prevent.
ALTER TABLE users ADD CONSTRAINT users_hold_expiry_is_a_hold
    CHECK (hold_expires_at IS NULL OR suspended_by = 'admin_hold');

-- The sweep reads this and nothing else: due holds, cheapest possible.
CREATE INDEX users_due_hold_idx ON users (hold_expires_at) WHERE hold_expires_at IS NOT NULL;

-- The owners' verdict over one person's standing. Same shape as `owner_admission` minus
-- the mailbox — every voter is a signed-in owner and the subject has no say — plus a
-- `kind` and the threshold that kind is measured against.
CREATE TABLE user_proposal (
    id                UUID PRIMARY KEY,
    kind              TEXT NOT NULL,
    -- Any user, NOT necessarily an owner: that is the difference from `owner_admission`,
    -- and the reason none of its roster checks (the floor, "already holds a seat") have
    -- an analogue here.
    subject_user_id   UUID NOT NULL REFERENCES users (id),
    initiator_user_id UUID NOT NULL REFERENCES users (id),
    -- Why, in the initiator's words. Shown to every voter. Required — a decision to
    -- freeze somebody's account with no stated cause is not auditable afterwards.
    reason            TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open',
    -- Owners at the moment of opening. The initiator is COUNTED even though they get no
    -- vote: if opening a proposal shrank the denominator, opening one would be a way to
    -- lower the bar you have to clear.
    owner_count       INTEGER NOT NULL,
    -- How many of the snapshotted peers must vote FOR, frozen at open so a surface shows
    -- the bar this proposal is actually measured against rather than re-deriving it from
    -- a roster that has since moved.
    threshold         INTEGER NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    decided_at        BIGINT,
    void_reason       TEXT NOT NULL DEFAULT '',
    -- Monotonic per row, bumped by every transition; the value the live feed's clients
    -- compare against so a replayed frame cannot move them backwards.
    version           BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT user_proposal_kind CHECK (kind IN ('suspension', 'reinstatement', 'admin_admission')),
    CONSTRAINT user_proposal_not_self CHECK (subject_user_id <> initiator_user_id),
    CONSTRAINT user_proposal_state CHECK (state IN ('open', 'executed', 'rejected', 'expired', 'cancelled', 'void')),
    CONSTRAINT user_proposal_reason_len CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT user_proposal_void_reason_len CHECK (char_length(void_reason) <= 200),
    -- `owners \ {initiator}` must be non-empty, so a LONE owner cannot open one. The same
    -- rule `owner_admission_needs_a_peer` states: a threshold met by nobody is a
    -- threshold that lets one person act alone.
    CONSTRAINT user_proposal_needs_a_peer CHECK (owner_count >= 2),
    -- floor(peers/2)+1 over a non-empty set is at least one, and can never exceed the
    -- peers there are. Expressed against `owner_count - 1` because that IS the peer set.
    CONSTRAINT user_proposal_threshold CHECK (threshold BETWEEN 1 AND owner_count - 1),
    CONSTRAINT user_proposal_ttl CHECK (expires_at > created_at),
    CONSTRAINT user_proposal_decided CHECK ((state = 'open') = (decided_at IS NULL)),
    CONSTRAINT user_proposal_void_reason_only_void CHECK (state = 'void' OR void_reason = '')
);

-- At most ONE open proposal per subject PER KIND. Scoped by kind rather than by subject
-- alone on purpose: a suspension and an admin admission about the same person are
-- unrelated questions, and blocking one on the other would be an accident of storage. Two
-- open suspensions on one person, by contrast, is the race with no good winner that the
-- removal table closes the same way.
CREATE UNIQUE INDEX user_proposal_open_subject_idx ON user_proposal (subject_user_id, kind) WHERE state = 'open';
CREATE INDEX user_proposal_open_idx ON user_proposal (expires_at) WHERE state = 'open';
CREATE INDEX user_proposal_recent_idx ON user_proposal (created_at DESC);

-- The snapshotted voter set: every owner except the initiator, frozen at open. Freezing
-- it is what closes roster stuffing (an owner seated afterwards is not here, so they get
-- no say) and what makes "the initiator cannot vote" structural rather than a check
-- somebody can forget.
--
-- The verbs are neutral. Three kinds share this table, so a kind-specific verb would only
-- mean something when cross-referenced against `user_proposal.kind`, and a vocabulary
-- that is correct only when cross-referenced is one that eventually gets rendered wrong.
-- The stored fact is which way the voter pushed; the verb belongs on the surface, which
-- knows the kind.
CREATE TABLE user_proposal_peer (
    proposal_id UUID NOT NULL REFERENCES user_proposal (id),
    user_id     UUID NOT NULL REFERENCES users (id),
    vote        TEXT NOT NULL DEFAULT 'pending',
    voted_at    BIGINT,
    PRIMARY KEY (proposal_id, user_id),
    CONSTRAINT user_proposal_peer_vote CHECK (vote IN ('pending', 'for', 'against')),
    CONSTRAINT user_proposal_peer_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

CREATE INDEX user_proposal_peer_pending_idx ON user_proposal_peer (user_id) WHERE vote = 'pending';

-- A user proposal's OWN history — opened, voted, rejected, executed — belongs in the
-- consilium log beside the other two, because "what happened to this proposal" is the
-- same question whichever consilium raised it, and `governance_revision` already orders
-- all three. The one-subject CHECK widens from two columns to three rather than being
-- dropped: it is what stops a row claiming to describe two proposals at once, and every
-- row already written still satisfies it.
ALTER TABLE governance_event ADD COLUMN user_proposal_id UUID REFERENCES user_proposal (id);
ALTER TABLE governance_event DROP CONSTRAINT governance_event_one_subject;
ALTER TABLE governance_event ADD CONSTRAINT governance_event_one_subject
    CHECK (num_nonnulls(removal_id, admission_id, user_proposal_id) = 1);

CREATE INDEX governance_event_user_proposal_idx ON governance_event (user_proposal_id, position);

-- Every operator decision about one person, append-only. NONE of these wrote a row before
-- this migration: suspension, reinstatement, role changes and KYC edits all happened with
-- no record of who did them or why.
--
-- WHY NOT `governance_event`. That log answers "what happened to this PROPOSAL", is keyed
-- by the two proposal ids with a CHECK demanding exactly one of them, and its header says
-- in as many words why it is one log and not two: "who has held a seat, and by whose
-- decision" is a single question. `SetKycLevel` and `RevokeTokens` have no proposal at
-- all, so putting them there would mean making both id columns nullable and deleting the
-- constraint that gives that table its meaning. This log answers a different question —
-- "what has been done TO this person, by whom" — and is therefore keyed by the subject.
-- The two are complementary: a governance-executed action writes to both, the proposal's
-- own history to `governance_event` and its effect on the person here.
CREATE TABLE admin_action (
    position        BIGSERIAL PRIMARY KEY,
    subject_user_id UUID NOT NULL REFERENCES users (id),
    -- NULL when no human acted: the hold sweep is the only such writer today. Recording
    -- the sweep as though some operator had pressed a button would be the one kind of
    -- audit row that is worse than none.
    actor_user_id   UUID REFERENCES users (id),
    action          TEXT NOT NULL,
    -- The proposal that authorized this, when one did. It is what connects a suspension
    -- row here to the vote that carried it in `governance_event`.
    proposal_id     UUID REFERENCES user_proposal (id),
    -- Free text from the actor. Empty where the surface does not ask for one; never NULL,
    -- so a reader never has to distinguish "no reason given" from "no reason column".
    reason          TEXT NOT NULL DEFAULT '',
    -- What the action did, in the vocabulary of the action itself (the level set, the
    -- role granted, the deadline a hold was given). JSONB rather than columns because
    -- every action names a different thing and a table of mostly-NULL columns reads as
    -- though the nulls meant something.
    detail          JSONB,
    occurred_at     BIGINT NOT NULL,
    client_ip       TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    CONSTRAINT admin_action_action_len CHECK (char_length(action) BETWEEN 1 AND 64),
    CONSTRAINT admin_action_reason_len CHECK (char_length(reason) <= 500),
    CONSTRAINT admin_action_client_ip_len CHECK (char_length(client_ip) <= 64),
    CONSTRAINT admin_action_user_agent_len CHECK (char_length(user_agent) <= 256)
);

-- The user-detail drawer's history, newest first.
CREATE INDEX admin_action_subject_idx ON admin_action (subject_user_id, position DESC);
-- "What has this operator been doing?" — the question an investigation starts from.
CREATE INDEX admin_action_actor_idx ON admin_action (actor_user_id, position DESC) WHERE actor_user_id IS NOT NULL;
