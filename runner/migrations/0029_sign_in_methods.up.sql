-- Sign-in methods beyond Google: email codes, passwords, GitHub — and the account handles
-- they name an account by.
--
--   users.username            — a second handle beside the email. Defaulted from the email,
--                               changeable by the user; never required by any surface.
--   user_identities           — provider subjects (google, github) → account. Takes over
--                               the provisioning role of users.auth_subject, which stays as
--                               the account's opaque cross-plane subject (banking keys on it).
--   users_verified_email_idx  — a PROVEN mailbox is the linking key between methods, so one
--                               verified address names at most one account. Unverified
--                               duplicates stay legal.
--   users_kyc_needs_verified_email — KYC above 0 is held only by a proven mailbox.
--   email_codes               — one-time codes for code sign-in and email verification.
--   password_credentials      — argon2id hashes, with a lockout that never blocks a code.
--
-- Fails loudly, on purpose: a duplicate verified email or a verified level on an
-- unverified address has no automatic answer, and NOT VALID would only postpone the
-- question to the first write that touches the row.
SET LOCAL lock_timeout = '3s';

ALTER TABLE users ADD COLUMN username TEXT;
ALTER TABLE users ADD CONSTRAINT users_username_shape CHECK (username = lower(username) AND char_length(username) BETWEEN 1 AND 254);
CREATE UNIQUE INDEX users_username_idx ON users (username);

-- The default a new account gets (domain::users::Username::defaults_for): the local part,
-- else the whole address, else nothing. Oldest account first, so the earlier claim wins.
DO $$
DECLARE
    r RECORD;
    local_part TEXT;
BEGIN
    FOR r IN SELECT id, lower(email) AS email FROM users WHERE email IS NOT NULL ORDER BY created_at, id LOOP
        local_part := split_part(r.email, '@', 1);
        IF local_part <> '' AND NOT EXISTS (SELECT 1 FROM users WHERE username = local_part) THEN
            UPDATE users SET username = local_part WHERE id = r.id;
        ELSIF NOT EXISTS (SELECT 1 FROM users WHERE username = r.email) THEN
            UPDATE users SET username = r.email WHERE id = r.id;
        END IF;
    END LOOP;
END $$;

CREATE TABLE user_identities (
    provider  TEXT NOT NULL,
    subject   TEXT NOT NULL,
    user_id   UUID NOT NULL REFERENCES users (id),
    linked_at BIGINT NOT NULL,
    PRIMARY KEY (provider, subject),
    CONSTRAINT user_identities_provider CHECK (provider IN ('google', 'github')),
    CONSTRAINT user_identities_subject_len CHECK (char_length(subject) BETWEEN 1 AND 255)
);
CREATE INDEX user_identities_user_idx ON user_identities (user_id);

-- Every account before this one was provisioned by Google, under its sub.
INSERT INTO user_identities (provider, subject, user_id, linked_at)
SELECT 'google', auth_subject, id, extract(epoch FROM created_at)::BIGINT FROM users;

-- Rollout bridge: the previous binary provisions by `users.auth_subject = <google sub>`. An
-- account it creates is mirrored here, and one whose sub this binary already linked to
-- another account fails to insert instead of becoming a duplicate. Accounts this binary
-- creates carry `auth_subject = id::text` and are skipped. Dropped by a later migration
-- once no binary older than this one runs.
CREATE FUNCTION users_mirror_google_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.auth_subject <> NEW.id::TEXT THEN
        INSERT INTO user_identities (provider, subject, user_id, linked_at)
        VALUES ('google', NEW.auth_subject, NEW.id, extract(epoch FROM now())::BIGINT);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER users_mirror_google_subject AFTER INSERT ON users
    FOR EACH ROW EXECUTE FUNCTION users_mirror_google_subject();

CREATE UNIQUE INDEX users_verified_email_idx ON users (lower(email)) WHERE email_verified;

ALTER TABLE users ADD CONSTRAINT users_kyc_needs_verified_email CHECK (kyc_level = 0 OR email_verified);

CREATE TABLE email_codes (
    id         UUID PRIMARY KEY,
    -- Normalized (domain::users::Email). The address the code proves.
    email      TEXT NOT NULL,
    purpose    TEXT NOT NULL,
    -- `verify` proves the mailbox FOR a signed-in account; `login` proves it for whoever asks.
    user_id    UUID REFERENCES users (id),
    code_hash  BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    burned_at  BIGINT,
    created_at BIGINT NOT NULL,
    CONSTRAINT email_codes_purpose CHECK (purpose IN ('login', 'verify')),
    CONSTRAINT email_codes_owner CHECK ((purpose = 'verify') = (user_id IS NOT NULL)),
    CONSTRAINT email_codes_hash_len CHECK (octet_length(code_hash) = 32),
    CONSTRAINT email_codes_attempts CHECK (attempts BETWEEN 0 AND 5),
    CONSTRAINT email_codes_email_len CHECK (char_length(email) <= 254)
);
CREATE INDEX email_codes_latest_idx ON email_codes (email, purpose, created_at DESC);

CREATE TABLE password_credentials (
    user_id         UUID PRIMARY KEY REFERENCES users (id),
    phc             TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    BIGINT,
    updated_at      BIGINT NOT NULL,
    CONSTRAINT password_credentials_argon2id CHECK (phc LIKE '$argon2id$%')
);

-- A code mail is addressed to a mailbox, not to a subscriber: the address may belong to no
-- account yet, and nobody unsubscribes from their own sign-in code.
ALTER TABLE notification_deliveries ALTER COLUMN subscriber_id DROP NOT NULL;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_subscriber CHECK (subscriber_id IS NOT NULL OR kind = 'email_code');
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome', 'email_code'));
