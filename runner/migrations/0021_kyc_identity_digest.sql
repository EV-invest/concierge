-- A keyed, one-way fingerprint of the DOCUMENT a verification was performed on, so that
-- two accounts verified by the same physical person can be detected -- plus the decided
-- status the detection records, `held_duplicate`.
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
--   * The index is NOT unique, deliberately. `UNIQUE (identity_digest) WHERE status =
--     'approved'` is the obvious way to make the race impossible in the schema, and it
--     cannot be used here: the same person re-verifying their OWN account is legitimate
--     and routine (the first attempt expired, a reviewer asked for a resubmission), it
--     produces a second approved row carrying the same digest, and a unique index cannot
--     be told the difference -- the account that owns the row is exactly the distinction
--     the constraint may not express. It would turn that honest second approval into a
--     23505 on the webhook path, where the only available answers are a 5xx the vendor
--     retries into the same error or a hold on somebody who did nothing wrong. Mutual
--     exclusion between two verdicts landing on the same document at once is bought
--     instead by `pg_advisory_xact_lock(hashtextextended(digest, 0))`, taken inside the
--     decision transaction just before the lookup (`infrastructure::kyc::cases`).
--     Without it the two transactions do not see each other's uncommitted rows under
--     READ COMMITTED, both find no twin, and both grant a level -- and the check never
--     runs again, because it only ever runs on a status transition. The lock is only
--     worth as much as the question asked under it, which is the next paragraph.
--   * Partial on `identity_digest IS NOT NULL` only -- not on a status. The lookup asks
--     about two statuses' worth of fact plus the joined level, and the digest alone is
--     the column all of it hangs off.
--
-- WHAT THE LOOKUP ASKS: TWO FACTS, OR-ED. The guarded fact is "this document has already
-- bought somebody a level", and no single column holds it.
--   * `kyc_level >= 1` on the joined `users` row, because a case LEAVES `approved` by
--     routes the vendor drives on its own -- `approved` -> `kyc_expired` when a
--     verification ages out, `approved` -> `declined` on a post-hoc review -- and neither
--     takes the level back down, since only a human under `Permission::KycManage` ever
--     lowers one. A status-only question would stop protecting a document the moment the
--     vendor expired the first verification, while the first account kept the deposit
--     address and the right to withdraw that its level bought.
--   * `status = 'approved'` on the case, because the level is written by ANOTHER
--     transaction (`web::kyc::apply` -> `raise_kyc_level_to`) that only begins after the
--     decision transaction has committed -- which is the same instant the advisory lock
--     is released. A level-only question would hand the waiting twin the one window in
--     which the first account's verdict is recorded and its level is not, and the same
--     split state survives indefinitely whenever `apply` fails between the two writes.
-- Hence `decision_at IS NOT NULL AND (status = 'approved' OR kyc_level >= 1)`: the status
-- arm covers a verdict already recorded, the level arm covers a grant that outlived the
-- verdict which bought it. The index covers the digest alone and serves both.
--
-- WHY `held_duplicate` IS A DECIDED STATUS. It carries a `decision_at` like every other
-- decided value, and that is load-bearing twice over. The vendor has spoken its last word
-- on the session, so a running status would be a row claiming an attempt that no event can
-- ever move again -- and `start_gate` hands running cases back, which would pin
-- `/kyc/start` to a spent vendor session for ever, leaving exactly the honest people this
-- hold exists for (a lost account remade, a family) with no way to try again and no
-- operator handle in this plane that closes a case. Decided, the user may start a fresh
-- attempt and an operator may raise the level with `SetKycLevel` once they have looked.
-- It is the one status no vendor word maps to: this plane writes it, nothing else does.
--
-- ROTATING THE PEPPER invalidates every stored digest: the same document hashes to a new
-- value, so old rows stop matching new ones and detection silently restarts from empty.
-- That is the cost of the property that makes the column safe to store, and it is the
-- reason the pepper is not derived from anything else.
--
-- AND THE SAME BLIND SPOT EXISTS FROM DAY ONE, not only after a rotation. Every case
-- decided before this column existed -- and every case decided while no pepper was set --
-- carries NULL, and there is no backfill, because the document number was never stored and
-- by design never will be. Those people can open a second account today and nothing will
-- mark it. The detection covers verifications performed AFTER the secret is in place and
-- nothing earlier; `SELECT count(*) FROM kyc_cases WHERE decision_at IS NOT NULL AND
-- identity_digest IS NULL` is the size of that set before rollout.
--
-- ROLLING DEPLOY. `identity_digest` is nullable and unread by the previous image, so the
-- old code is unaffected by it. The new `status` value is the one asymmetry: only new pods
-- write `held_duplicate`, and an old pod that received a webhook for such a case would fail
-- to rehydrate the status and answer 5xx, which Didit retries into a new pod. Nothing is
-- lost and the window is the rollout.
--
-- REVERSIBILITY. Reverting the IMAGE is safe on its own; reverting the SCHEMA is a new
-- migration dropping the column and the index and restoring the status CHECK, and it must
-- first rewrite any `held_duplicate` rows (to `declined`, the decided status that grants
-- nothing) or the restored constraint will not validate. No data is destroyed either way.

-- A migration that WAITS is a service that does not come up: these statements take an
-- ACCESS EXCLUSIVE lock, and queueing behind somebody's open transaction would stall every
-- boot behind it. Fail fast instead and retry on the next start.
--
-- LOCAL, because sqlx borrows this connection from the service's pool and returns it after
-- the migration: a session-level SET would survive into the requests served on that
-- connection and cap every row lock they wait for at 3s.
SET LOCAL lock_timeout = '3s';

ALTER TABLE kyc_cases ADD COLUMN identity_digest TEXT;

ALTER TABLE kyc_cases ADD CONSTRAINT kyc_cases_identity_digest_len
    CHECK (identity_digest IS NULL OR char_length(identity_digest) = 64);

-- The status vocabulary gains `held_duplicate`. 0010's CHECK enumerates that vocabulary and
-- cannot be edited in place -- sqlx checksums an applied migration and every environment
-- that already ran it would refuse to boot (0014 is the precedent) -- so it is dropped and
-- restated here in full.
--
-- `kyc_cases_decision_at` is deliberately LEFT ALONE. It names the RUNNING statuses, and
-- `held_duplicate` is not one of them, so it already reads "this status must carry a
-- decision_at" without a word changed. Restating a constraint that needs no change would
-- only add a second place for the two to disagree.
--
-- Validated immediately rather than `NOT VALID`: sqlx runs this file in ONE transaction, so
-- a NOT VALID plus VALIDATE would hold the same lock across both steps and buy nothing, and
-- the scan is over a table with one row per verification attempt.
ALTER TABLE kyc_cases DROP CONSTRAINT kyc_cases_status;
ALTER TABLE kyc_cases ADD CONSTRAINT kyc_cases_status CHECK (
    status IN ('pending', 'in_progress', 'in_review', 'resubmitted', 'approved', 'declined', 'abandoned', 'expired', 'kyc_expired', 'held_duplicate')
);

-- "has this document already bought somebody else a level?" -- the one question asked,
-- inside the decision transaction, before a level is raised. Not predicated on a status:
-- the rows the lookup must find include one that has LEFT `approved` and one that has not
-- yet been applied.
CREATE INDEX kyc_cases_identity_digest_idx ON kyc_cases (identity_digest)
    WHERE identity_digest IS NOT NULL;

-- 0014's other half: the correction goes into the object's own comment as well as into this
-- file, where `\d+` and `pg_dump` show it to a reader who never opens this directory. 0010's
-- "WHAT IS NOT STORED" note stays true -- a digest is not a number -- but a reader looking
-- at the table needs to know a column derived from one now exists, and under what key.
COMMENT ON COLUMN kyc_cases.identity_digest IS
    'HMAC-SHA256(KYC_IDENTITY_PEPPER, issuing_state || '':'' || document_number), hex. A keyed one-way fingerprint of the DOCUMENT, and the only cross-account handle this plane holds (#51). NOT a document number and not reversible without the pepper, which is a platform-tier secret this database never sees; 0010''s "no document numbers" discipline is unchanged. NULL means no detection for that row: written before the column existed, no pepper configured, or a verdict naming no document. Rotating the pepper invalidates every stored value. See 0021_kyc_identity_digest.sql.';

COMMENT ON CONSTRAINT kyc_cases_identity_digest_len ON kyc_cases IS
    'Hex SHA-256 is 64 characters. The column takes a digest or nothing -- never a truncation, and never a raw document number, which this length would not admit anyway.';

COMMENT ON CONSTRAINT kyc_cases_status ON kyc_cases IS
    'Didit''s documented vocabulary mapped to snake_case, PLUS held_duplicate, which no vendor word maps to: this plane writes it when an approval names a document that has already raised a different account''s level (#51). It is DECIDED -- it carries a decision_at, it grants no level, and it leaves the user free to start a new attempt. resubmitted is RUNNING: a reviewer asked for specific steps and the attempt is back in the user''s hands. See 0021_kyc_identity_digest.sql.';
