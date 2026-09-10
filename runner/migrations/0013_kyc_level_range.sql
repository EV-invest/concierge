-- The KYC tier range, enforced where the value LIVES rather than where it happens to
-- arrive (#45).
--
-- WHY THE COLUMN NEEDED THIS. Until now the only bound on `users.kyc_level` anywhere in
-- the plane was `if req.kyc_level > 3` inside ONE gRPC handler. The aggregate took any
-- `u32` and the column took any `integer`, so every other writer — a backfill, a console
-- UPDATE, a future adapter — could put 999 (or, since the column is signed and the
-- domain reads it as `u32`, -1, which rehydrates as 4294967295) into the record. That
-- value is not inert here: it is copied onto `user_outbox` and mirrored verbatim by the
-- banking money plane, where the tier is what gates a money operation. An account at 999
-- clears every threshold there is. 0006_input_limits.sql added a CHECK to every profile
-- field "so no future caller can bypass them" and 0010_kyc_cases.sql constrained
-- `requested_tier`, `status` and `decision_at`; both walked past the one column on this
-- table that the other plane actually spends.
--
-- SANITIZE FIRST, AND TELL BANKING. `ADD CONSTRAINT` validates existing rows, so a single
-- surviving out-of-range row would fail the migration — and migrations run at service
-- start, which turns that into a boot loop rather than a failed deploy. Violating rows
-- are therefore cleared to 0 the way 0006 cleared violating profile values: an
-- out-of-range level cannot have come from the validated path, so it is not evidence that
-- anyone was verified, and on the money plane the fail-safe direction is down. Clearing it
-- in SQL alone would not be enough: banking mirrors the OUTBOX, not this table, so a
-- correction that emits no event leaves the money plane holding the bad tier forever. The
-- UPDATE therefore bumps `row_version` and appends the KYC_CHANGED that the aggregate
-- would have emitted, under the same advisory lock every other outbox append takes
-- (`USER_OUTBOX_ADVISORY_LOCK`), so `position` order still equals commit order for a
-- bridge consumer reading concurrently during a rolling deploy.
--
-- WHY `users` IS VALIDATED IMMEDIATELY AND NOT `NOT VALID`. `NOT VALID` skips the seq scan
-- while ACCESS EXCLUSIVE is held; it does not skip the lock. It only pays off when the ADD
-- and the VALIDATE land in DIFFERENT transactions, and sqlx runs each migration file in
-- one transaction unless it opens with `-- no-transaction` — so a two-step here would hold
-- exactly the same lock across both statements and buy nothing. Splitting it across two
-- migration files would not help either: both would still be applied back-to-back by the
-- same booting process. Against that, `users` holds one row per person who has ever signed
-- in to this platform and is scanned in milliseconds. The real boot risk is not the scan
-- but QUEUEING behind someone else's open transaction, which `lock_timeout` — not
-- `NOT VALID` — is what answers.
--
-- WHY `user_outbox` STAYS `NOT VALID`, DELIBERATELY AND PERMANENTLY. It is the second place
-- the value lives and the one banking actually reads, so leaving it unbounded would leave
-- the mirrored copy reachable even with `users` locked down. But it is an append-only LOG:
-- its rows record what the level was at the moment an event was emitted, and editing old
-- rows so a constraint can validate would be falsifying that record. `NOT VALID` is exactly
-- the right shape — every future append is checked from this statement onward, which is the
-- entire ask, while history keeps saying what happened. A historically bad level is
-- corrected by the new KYC_CHANGED above, which carries a higher `position` and a higher
-- per-user `sequence`, not by rewriting the row that reported it. It also keeps the plane's
-- largest and fastest-growing table off the boot path: no scan, no rewrite. Do not "finish
-- the job" with a later VALIDATE CONSTRAINT.
--
-- REVERSIBILITY. The DDL is fully reversible —
--   ALTER TABLE users DROP CONSTRAINT users_kyc_level_range;
--   ALTER TABLE user_outbox DROP CONSTRAINT user_outbox_kyc_level_range;
-- — and the release before this one runs unchanged against a schema that still has both.
-- The sanitizing UPDATE is NOT reversible: the levels it clears were never recoverable
-- from this database (nothing recorded what they were before they went out of range), so
-- restoring one means a backup or a fresh operator decision under `Permission::KycManage`.
-- It is expected to touch zero rows; the `KYC_CHANGED` rows it would leave behind are how
-- anyone finds out it did not.
SET lock_timeout = '3s';

-- Same ordering guarantee as `drain_outbox`: taken BEFORE the INSERT that assigns the
-- BIGSERIAL `position`, so a concurrently committing appender cannot leave a lower
-- position committing after the bridge cursor has already passed a higher one.
SELECT pg_advisory_xact_lock(87227904446296);

WITH cleared AS (
	UPDATE users
	SET kyc_level = 0,
		row_version = row_version + 1,
		updated_at = now()
	WHERE kyc_level NOT BETWEEN 0 AND 3
	RETURNING id, auth_subject, email, email_verified, token_version, role, row_version
)
INSERT INTO user_outbox (user_id, kind, kyc_level, occurred_at, sequence, auth_subject, email, email_verified, token_version, role)
SELECT id, 'KYC_CHANGED', 0, extract(epoch FROM now())::bigint, row_version, auth_subject, email, email_verified, token_version, role
FROM cleared;

ALTER TABLE users
	ADD CONSTRAINT users_kyc_level_range CHECK (kyc_level BETWEEN 0 AND 3);

ALTER TABLE user_outbox
	ADD CONSTRAINT user_outbox_kyc_level_range CHECK (kyc_level BETWEEN 0 AND 3) NOT VALID;

COMMENT ON CONSTRAINT users_kyc_level_range ON users IS
	'The platform KYC tiers (domain::users::MAX_KYC_LEVEL). The aggregate refuses the same range; this backstops every writer that does not go through it.';
COMMENT ON CONSTRAINT user_outbox_kyc_level_range ON user_outbox IS
	'Bounds the level mirrored to the banking money plane. Intentionally NOT VALID: this is an append-only log, so future appends are checked and historical rows keep reporting what they reported.';
