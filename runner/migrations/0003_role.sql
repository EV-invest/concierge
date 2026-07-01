-- Adds the platform access role to the identity record and the cross-plane bridge.
--
-- `role` is this plane's SOURCE OF TRUTH for a user's access level (investor by
-- default). A change is mirrored to the banking money plane over user_outbox
-- (ROLE_CHANGED), so the money plane gates its operator RPCs on the same role —
-- only the string crosses the one-way bridge, never a shared permission set.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'investor';

-- The role snapshot stamped onto each outbox row at emit time (like kyc_level).
-- NULL for rows written before this migration; the banking puller treats an
-- absent/empty value as 'investor'.
ALTER TABLE user_outbox ADD COLUMN role TEXT;
