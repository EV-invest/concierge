-- A keyed, one-way fingerprint of the DOCUMENT a verification was performed on, so that
-- two accounts verified by the same physical person can be detected.
--
-- WHAT THIS DOES NOT CHANGE. 0010 says no document numbers, no dates of birth, no names,
-- no images -- and that still holds exactly as written. This column stores none of them:
-- it is HMAC-SHA256(KYC_IDENTITY_PEPPER, issuing_state || ':' || document_number), a
-- value from which the document number cannot be recovered without the pepper, and the
-- pepper is a platform-tier secret that never reaches this database. The allowlist in
-- `didit::metadata_of` is untouched, and the test asserting that `document_number` never
-- appears in `payload` still passes -- the digest is a COLUMN precisely so that it does
-- not become another key in a JSON blob whose discipline is "copy nothing unless named".
--
-- WHY IT IS NEEDED. Nothing linked two accounts verified by the same person, and by
-- construction nothing could (#51). The scenario needs no forgery: one person registers
-- N accounts through Google OAuth and honestly completes verification on each with their
-- own real passport. Liveness and face-match pass, because it really is them. Every
-- account reaches level >= 1 -- a deposit address and the right to withdraw -- and
-- neither plane holds any data that could tie them together, before or after the fact.
--
-- WHY A DIGEST AND NOT THE VENDOR'S OWN DEDUPLICATION. Didit's Face Search is a separate
-- BILLED 1:N call on every approval, it needs a stored face image, and its
-- DUPLICATED_FACE result is advisory. This is one HMAC over data we already receive and
-- immediately discard.
--
-- WHY NULLABLE, AND WHY NO UNIQUE INDEX.
--   * NULL is the normal state for every row written before this, for every case whose
--     verdict carried no document number, and for every deployment with no
--     `KYC_IDENTITY_PEPPER` set. Absent a pepper the digest is not computed and the
--     duplicate check is skipped -- concierge must boot and verify people either way, so
--     this is a detection that degrades, never a gate that fails closed on an absent
--     secret.
--   * The index is NOT unique, deliberately. A unique constraint would make the SECOND
--     honest re-verification of the same person fail at the database, which is a
--     write error on a path that is supposed to end in a human reading a case. Duplicates
--     are routed to `in_review` by the application instead: the level is not raised, and
--     an operator decides.
--   * Partial, because the lookup only ever asks about approved cases and most rows will
--     carry no digest at all.
--
-- ROTATING THE PEPPER invalidates every stored digest: the same document hashes to a new
-- value, so old rows stop matching new ones and detection silently restarts from empty.
-- That is the cost of the property that makes the column safe to store, and it is the
-- reason the pepper is not derived from anything else.

ALTER TABLE kyc_cases ADD COLUMN identity_digest TEXT;

ALTER TABLE kyc_cases ADD CONSTRAINT kyc_cases_identity_digest_len
    CHECK (identity_digest IS NULL OR char_length(identity_digest) = 64);

-- "has this document already been approved for somebody else?" -- the one question asked,
-- inside the decision transaction, before a level is raised.
CREATE INDEX kyc_cases_identity_digest_idx ON kyc_cases (identity_digest)
    WHERE identity_digest IS NOT NULL AND status = 'approved';
