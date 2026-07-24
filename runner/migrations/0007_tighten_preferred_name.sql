-- Tighten preferred_name from 256 to 64 chars to match the domain cap in
-- domain/src/users.rs (the frontend zod schema also caps at 64). Rows in the
-- 65-256 range are loadable (rehydrate skips re-parsing) but cannot be re-saved
-- — clear them so a profile save doesn't surprise the user with a validation
-- error for a value they didn't knowingly set.

UPDATE users SET preferred_name = NULL WHERE char_length(preferred_name) > 64;

ALTER TABLE users
    DROP CONSTRAINT users_preferred_name_len,
    ADD CONSTRAINT users_preferred_name_len CHECK (char_length(preferred_name) <= 64);
