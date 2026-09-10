-- WHEN the vendor said it, as the vendor signed it — the ordering key a verdict is
-- judged by.
--
-- WHY A CASE NEEDS ONE. Until now `record_decision` compared only the stored status
-- against the incoming one: different ⇒ write it. That makes the LAST delivery to
-- arrive the winner, and webhook deliveries do not arrive in the order they were sent.
-- Didit retries at roughly one and four minutes, so a retried `in_review` overtaking the
-- `approved` that superseded it is an ordinary network event, not a rare one. Under the
-- old rule that retry reopened a decided case: `decision_at` was cleared, the audit row
-- lost the moment the verdict landed, and — because the level is only ever RAISED — the
-- user kept a tier whose case row no longer claimed one. Comparing signed timestamps is
-- what makes the outcome depend on what the vendor decided rather than on which packet
-- won the race.
--
-- WHY THE SIGNED COPY AND NOT `updated_at`. `updated_at` records when WE wrote, which is
-- exactly the arrival order the problem is about. The value here comes from the webhook
-- body's `timestamp`, which is covered by the HMAC — an attacker replaying a captured
-- delivery cannot move it, and (since the change that made a missing body timestamp a
-- rejection) cannot omit it either.
--
-- NULLABLE, AND STAYING THAT WAY THIS RELEASE. Rows written before this column existed
-- have no signed timestamp and none can be invented for them: the vendor's original body
-- is not retained (`payload` holds only allowlisted metadata). NULL therefore means "not
-- known", and the application reads it as "no ordering evidence, allow the transition" —
-- the pre-existing behaviour, so a case opened by the old code keeps working under the
-- new. A `NOT NULL` here would also break the running instance during a rolling deploy:
-- the old binary's INSERT in `open_case` does not mention this column.
--
-- BIGINT, not TIMESTAMPTZ: it is the vendor's Unix-seconds integer, compared against
-- another Unix-seconds integer from the next delivery. Storing it as an instant would
-- add a conversion at both ends and invite a timezone question that does not exist here.
--
-- LOCK COST. `ADD COLUMN` that is nullable with no DEFAULT is catalogue-only in every
-- supported Postgres — no table rewrite, no scan — so the ACCESS EXCLUSIVE lock is held
-- for the statement's duration and nothing more. `lock_timeout` is set anyway: these
-- migrations run at service start, and waiting behind an open transaction would turn a
-- fast deploy into a boot that hangs.
--
-- REVERSIBILITY. Dropping the column loses only ordering evidence for cases decided
-- after it landed; no verdict and no user level is derived from it alone. `ALTER TABLE
-- kyc_cases DROP COLUMN event_at;` is a complete `down`, and the release before this one
-- runs unchanged against a schema that still has the column.
SET lock_timeout = '3s';

ALTER TABLE kyc_cases ADD COLUMN event_at BIGINT;

COMMENT ON COLUMN kyc_cases.event_at IS
    'Vendor-signed Unix seconds of the verdict currently stored in `status`. NULL for cases last written before this column existed. A delivery whose own signed timestamp is strictly older is refused as out-of-order rather than applied.';
