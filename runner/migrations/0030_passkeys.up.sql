-- Passkeys: WebAuthn credentials an account signs in with, beside its password
-- (`password_credentials`) — a credential this plane checks itself, not a provider subject,
-- so not a `user_identities` row. `passkey` is the verifier's serialized key (public key,
-- counter, backup flags); `credential_id` is the authenticator's id for it, base64url.
SET LOCAL lock_timeout = '3s';

CREATE TABLE passkey_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users (id),
    passkey       JSONB NOT NULL,
    name          TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    last_used_at  BIGINT,
    CONSTRAINT passkey_credentials_name_len CHECK (char_length(name) BETWEEN 1 AND 64),
    CONSTRAINT passkey_credentials_id_len CHECK (char_length(credential_id) BETWEEN 1 AND 1366)
);
CREATE INDEX passkey_credentials_user_idx ON passkey_credentials (user_id);
