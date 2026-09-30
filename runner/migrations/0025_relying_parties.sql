-- Relying parties: first-party applications on ANOTHER origin that sign users in
-- through this plane with an authorization code + PKCE (S256) instead of sharing the
-- `evinvest.ltd` cookies. The first is the Service-Arb panel on `sa.evinvest.ltd`
-- (`service_arb/SA-PANEL-SPEC.md` §4, variant B).
--
-- Three tables, one per lifetime:
--
--   rp_clients  — the registry. Exact redirect URIs (no wildcard, no prefix match: a
--                 redirect_uri that is not byte-equal to a registered one is answered
--                 with an error PAGE, never a redirect), the audience its access tokens
--                 carry, and who may be signed into it (`access_policy`, mirroring
--                 `domain::clients::AccessPolicy::parse`). The client SECRET is not
--                 here: `secret_hash` is written at boot from the operator's
--                 `RP_CLIENT_SECRET_<CLIENT_ID>` and cleared when that is unset, so a
--                 secret never passes through a migration or a repository.
--   rp_codes    — one row per authorization code: SHA-256 of the code (never the code),
--                 bound to client, redirect_uri, PKCE challenge, user and the user's
--                 token_version, 60s to live, single-use. `redeemed_at` burns it;
--                 `replayed_at` records that it was presented AGAIN, which is also what
--                 stops a family being opened off it afterwards. Rows are reaped a day
--                 past expiry, by the insert path — a replay later than that is simply
--                 an unknown code.
--   rp_sessions — a client's refresh family, one per redeemed code: the current and
--                 previous secret (hashes), rotated on use; presenting the previous one
--                 is theft and revokes the family. Kept after revocation or expiry as the
--                 record of who was signed into which client, and when.
--
-- The audience CHECK keeps a client from ever being minted this plane's or the money
-- plane's own audience: a token under one of those would be accepted by every RPC here
-- or by the cabinet BFF, which is exactly what a relying party's token must not be.
--
-- `lock_timeout`: the foreign keys take SHARE ROW EXCLUSIVE on `users` while the tables
-- are created, and migrations run ON BOOT. SET LOCAL, not SET: sqlx runs this on a
-- connection borrowed from the service's pool, and a session SET would outlive it.
--
-- REVERSIBILITY. New tables nothing else references:
--   DROP TABLE rp_sessions; DROP TABLE rp_codes; DROP TABLE rp_clients;
-- signs every relying-party session out and loses the record of past sign-ins. The
-- `evinvest.ltd` sessions are untouched.
SET LOCAL lock_timeout = '3s';

CREATE TABLE rp_clients (
    client_id      TEXT PRIMARY KEY,
    audience       TEXT NOT NULL UNIQUE,
    redirect_uris  TEXT[] NOT NULL,
    access_policy  TEXT NOT NULL,
    secret_hash    BYTEA,
    secret_set_at  BIGINT,
    created_at     BIGINT NOT NULL,
    disabled_at    BIGINT,
    CONSTRAINT rp_clients_client_id_format CHECK (client_id ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT rp_clients_audience_format CHECK (audience ~ '^[a-z][a-z0-9_]{0,31}$' AND audience !~ '^(concierge|banking)'),
    CONSTRAINT rp_clients_redirect_uris_count CHECK (cardinality(redirect_uris) BETWEEN 1 AND 16),
    CONSTRAINT rp_clients_access_policy_format CHECK (access_policy = 'public' OR access_policy ~ '^scope:allocation:[a-z0-9_]{1,64}$'),
    CONSTRAINT rp_clients_secret_hash_len CHECK (secret_hash IS NULL OR octet_length(secret_hash) = 32),
    CONSTRAINT rp_clients_secret_stamp CHECK ((secret_hash IS NULL) = (secret_set_at IS NULL))
);

CREATE TABLE rp_codes (
    code_hash       BYTEA PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES rp_clients (client_id),
    redirect_uri    TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    user_id         UUID NOT NULL REFERENCES users (id),
    token_version   BIGINT NOT NULL,
    issued_at       BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    redeemed_at     BIGINT,
    replayed_at     BIGINT,
    client_ip       TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    CONSTRAINT rp_codes_code_hash_len CHECK (octet_length(code_hash) = 32),
    -- base64url(SHA-256(verifier)) without padding is exactly 43 characters.
    CONSTRAINT rp_codes_code_challenge_format CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT rp_codes_client_ip_len CHECK (char_length(client_ip) <= 64),
    CONSTRAINT rp_codes_user_agent_len CHECK (char_length(user_agent) <= 256)
);

-- The reaper's range scan.
CREATE INDEX rp_codes_expires_idx ON rp_codes (expires_at);

CREATE TABLE rp_sessions (
    id                   UUID PRIMARY KEY,
    client_id            TEXT NOT NULL REFERENCES rp_clients (client_id),
    user_id              UUID NOT NULL REFERENCES users (id),
    -- Not a foreign key: codes are reaped, sessions are kept.
    code_hash            BYTEA NOT NULL,
    current_hash         BYTEA NOT NULL,
    prev_hash            BYTEA,
    token_version        BIGINT NOT NULL,
    created_at           BIGINT NOT NULL,
    last_used_at         BIGINT NOT NULL,
    expires_at           BIGINT NOT NULL,
    absolute_expires_at  BIGINT NOT NULL,
    revoked_at           BIGINT,
    revoked_reason       TEXT,
    client_ip            TEXT NOT NULL DEFAULT '',
    user_agent           TEXT NOT NULL DEFAULT '',
    CONSTRAINT rp_sessions_hash_len CHECK (octet_length(current_hash) = 32 AND (prev_hash IS NULL OR octet_length(prev_hash) = 32)),
    CONSTRAINT rp_sessions_revocation CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CONSTRAINT rp_sessions_revoked_reason CHECK (revoked_reason IN ('refresh_reuse', 'code_replay', 'access_denied', 'tokens_revoked')),
    CONSTRAINT rp_sessions_client_ip_len CHECK (char_length(client_ip) <= 64),
    CONSTRAINT rp_sessions_user_agent_len CHECK (char_length(user_agent) <= 256)
);

-- A replayed code revokes what was issued off it.
CREATE INDEX rp_sessions_code_idx ON rp_sessions (code_hash);
CREATE INDEX rp_sessions_user_idx ON rp_sessions (user_id) WHERE revoked_at IS NULL;

-- The Service-Arb panel: holders of the `allocation:service_arb` scope (any scope role)
-- and the global admins/owners. No secret: the boot writes it from
-- `RP_CLIENT_SECRET_SA`, and until then the client can obtain no token.
INSERT INTO rp_clients (client_id, audience, redirect_uris, access_policy, created_at)
VALUES ('sa', 'sa', ARRAY['https://sa.evinvest.ltd/auth/callback'], 'scope:allocation:service_arb', extract(epoch FROM now())::BIGINT);
