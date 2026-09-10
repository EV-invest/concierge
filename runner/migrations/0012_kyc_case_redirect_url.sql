-- Where the vendor sent the browser for this attempt — the thing that makes a still-open
-- case RESUMABLE instead of a reason to buy a second one.
--
-- WHY A CASE NEEDS ONE. `/kyc/start` had nothing between the session check and Didit's
-- billable `POST /v3/session/`: every call opened a new vendor session and inserted a new
-- row, so a signed-in account looping the route drained the platform's quota, and past
-- that point the route degrades fail-closed — one user could stop verification for
-- everyone, silently, because to a user a 503 here just reads as "try later". The fix is
-- to hand a caller who already has a running attempt the attempt they already have. That
-- needs the vendor's session URL, and until now nothing kept it: `provider_ref` is the
-- session ID, the URL is a separate field of the vendor's response, and there is no
-- read-back call in the integration that would fetch it again.
--
-- WHY IT IS NOT A SECRET WORTH SPECIAL HANDLING. The URL is a capability — whoever holds
-- it can walk that session's flow — but it is one we hand to the user's own browser by
-- design, and the only outcome it can reach is raising THAT user's own level, monotonically,
-- through a signed webhook. It is stored beside the case it belongs to and nowhere else.
--
-- NULLABLE, AND STAYING THAT WAY. Rows opened before this column existed have no URL and
-- none can be reconstructed. NULL means "not resumable": such a case is still counted
-- against the per-user window cap, but a caller holding one gets a fresh session rather
-- than a dead end. `NOT NULL` would also break a rolling deploy — the old binary's INSERT
-- in `open_case` does not mention this column.
--
-- NO LENGTH CHECK, unlike `provider` and `provider_ref` beside it. Those are keys we look
-- cases up by; this is an opaque value we only ever hand back. Adding a validated CHECK to
-- a populated table costs a full scan under ACCESS EXCLUSIVE, which is not a price worth
-- paying to bound a string the vendor chose and TEXT already stores.
--
-- LOCK COST. Nullable `ADD COLUMN` with no DEFAULT is catalogue-only in every supported
-- Postgres — no rewrite, no scan. `lock_timeout` is set anyway: migrations run at service
-- start, so queueing behind an open transaction would turn a deploy into a hung boot.
--
-- REVERSIBILITY. `ALTER TABLE kyc_cases DROP COLUMN redirect_url;` is a complete `down`;
-- it loses only the ability to resume cases opened after this landed, and the release
-- before this one runs unchanged against a schema that still has the column.
SET lock_timeout = '3s';

ALTER TABLE kyc_cases ADD COLUMN redirect_url TEXT;

COMMENT ON COLUMN kyc_cases.redirect_url IS
    'The vendor URL this attempt was opened with. Handed back when the user restarts a case that is still running, so a second billable session is never bought. NULL for cases opened before this column existed — those are counted but cannot be resumed.';
