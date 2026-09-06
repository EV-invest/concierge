-- One row per identity-verification attempt: who asked, which vendor was asked, what
-- the vendor called the session, and how it ended.
--
-- WHY A TABLE AND NOT JUST THE LEVEL. `users.kyc_level` is the ANSWER; this is the
-- QUESTION and its provenance. The webhook that carries a provider's verdict is an
-- unauthenticated, internet-facing POST, so the identity it acts on may NEVER come out
-- of the request body — it is read back from the row this table opened when the
-- signed-in user started the flow. `provider_ref` (the vendor's session id) is the only
-- thing the callback is allowed to look a case up by.
--
-- WHY (provider, provider_ref) IS UNIQUE. It is the idempotency key. Providers retry
-- webhooks at-least-once, and a redelivered `Approved` must not re-emit a KYC_CHANGED
-- onto the cross-plane outbox. The unique index makes "the case for this session" a
-- single row that a decision transaction can take `FOR UPDATE`, so two concurrent
-- redeliveries serialize instead of both applying.
--
-- WHAT IS NOT STORED. No documents, no images, no document numbers, no dates of birth —
-- there is no object store in this plane and this task is not the place to grow one.
-- `payload` carries only decision METADATA the adapter allowlists field by field
-- (document country, document type, per-check outcomes), never the vendor's raw body.
--
-- TIER CEILING. A provider may only ever be asked for tier 1 or 2. Tier 3 is the
-- ceiling of a HUMAN decision (`UserDirectory.SetKycLevel` under `KycManage`), and so
-- is every downgrade — a user who holds 2 and fails an attempt at 3 must keep their 2.
-- The application clamps this; the CHECK is here so a future adapter, a backfill or a
-- console UPDATE cannot write a case that would grant more than a vendor may.
CREATE TABLE kyc_cases (
    id             UUID PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users (id),
    -- Vendor key, e.g. 'didit'. Part of the idempotency key so a second provider's
    -- session ids can never collide with this one's.
    provider       TEXT NOT NULL,
    -- The vendor's own session identifier (Didit: `session_id`). The ONLY handle the
    -- webhook resolves a case by.
    provider_ref   TEXT NOT NULL,
    requested_tier INTEGER NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    -- Set exactly when `status` is one the flow cannot leave (see the CHECK below), so
    -- "is this case still running" has one answer rather than two that can disagree.
    decision_at    TIMESTAMPTZ,
    payload        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT kyc_cases_provider_len     CHECK (char_length(provider) <= 32),
    CONSTRAINT kyc_cases_provider_ref_len CHECK (char_length(provider_ref) BETWEEN 1 AND 128),
    CONSTRAINT kyc_cases_requested_tier   CHECK (requested_tier BETWEEN 1 AND 2),
    CONSTRAINT kyc_cases_status CHECK (
        status IN ('pending', 'in_progress', 'in_review', 'approved', 'declined', 'abandoned', 'expired', 'not_finished', 'kyc_expired')
    ),
    CONSTRAINT kyc_cases_decision_at CHECK (
        (decision_at IS NULL) = (status IN ('pending', 'in_progress', 'in_review'))
    )
);

-- The webhook idempotency key, and the lookup the callback resolves a case by.
CREATE UNIQUE INDEX kyc_cases_provider_ref_idx ON kyc_cases (provider, provider_ref);
-- "this user's attempts, newest first" — the operator console's per-user KYC history.
CREATE INDEX kyc_cases_user_idx ON kyc_cases (user_id, created_at DESC);
