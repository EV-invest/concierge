-- The concierge plane's identity control plane: the canonical user record.
--
-- This is the IDENTITY plane — no money, balances, or ledger anywhere here; those
-- are the banking money plane's concern, reached one-way over the cross-plane
-- bridge (see 0002_user_outbox.sql).
--
-- `auth_subject` (Google's immutable `sub`) is the UNIQUE provisioning key and the
-- shared correlation key both planes key their users on; `email` is NOT unique (a
-- person may change it behind a stable subject). `token_version` backs coarse
-- "revoke all". `row_version` is bumped on every mutation and stamped onto each
-- outbox event as the bridge `sequence`, giving the banking consumer per-user ORDER.
CREATE TABLE users (
    id                  UUID PRIMARY KEY,
    auth_subject        TEXT NOT NULL,
    email               TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    status              TEXT NOT NULL DEFAULT 'active',
    token_version       BIGINT NOT NULL DEFAULT 0,
    -- KYC level surfaced to the banking money plane on the bridge (KYC_CHANGED).
    kyc_level           INTEGER NOT NULL DEFAULT 0,
    -- Editable profile fields (control plane; NULL = unset), full-replaced by
    -- UpdateProfile. email and status above stay read-only at the service boundary.
    legal_name          TEXT,
    preferred_name      TEXT,
    phone               TEXT,
    date_of_birth       TEXT,
    nationality         TEXT,
    tax_residence       TEXT,
    residential_address TEXT,
    language            TEXT,
    base_currency       TEXT,
    timezone            TEXT,
    -- Per-user mutation counter; the bridge `sequence`. Bumped on every write.
    row_version         BIGINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_auth_subject_idx ON users (auth_subject);
