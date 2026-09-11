-- One more value in the delivery queue's `kind` CHECK: `payment_consent`, the mail that
-- asks ONE user to consent to a payment moving their own money.
--
-- WHY A MIGRATION AT ALL. `notification_deliveries.kind` is a closed set enforced at the
-- column, so a renderer this plane does not know about cannot be queued and then sit in
-- the queue forever as an unrenderable row. The list is the contract; adding a kind means
-- amending it here, not just adding a `match` arm.
--
-- COMPATIBILITY, BOTH DIRECTIONS. This only WIDENS the accepted set, so the release
-- running against the old schema is unaffected and keeps working through the rollout: it
-- never writes the new value. The reverse also holds for as long as no `payment_consent`
-- row exists — and stops holding the moment one does, which is the honest statement of
-- reversibility here (see below).
--
-- LOCKS. Postgres has no "add a value to a CHECK" statement, so the constraint is dropped
-- and re-added, and the re-add scans the table under ACCESS EXCLUSIVE. That is acceptable
-- on THIS table and would not be on every table: `notification_deliveries` is the outbound
-- mail queue, bounded by the daily send budget and by what an operator has not yet swept —
-- thousands of rows, scanned in milliseconds. The real boot risk is not the scan but
-- QUEUEING behind someone else's open transaction (migrations run at service start, so a
-- migration that waits is a service that does not come up), which is what `lock_timeout`
-- answers: fail fast and let the restart retry, rather than block the dispatcher behind us.
--
-- NOT `NOT VALID`, deliberately. sqlx runs each migration file in one transaction, so an
-- ADD ... NOT VALID followed by a VALIDATE would hold the same ACCESS EXCLUSIVE lock across
-- both and buy nothing — the same argument 0013 makes for `users`. And unlike `user_outbox`
-- there is nothing here worth leaving unchecked: this is a work queue, not an append-only
-- log of what was true at the time.
--
-- REVERSIBILITY. The DDL is reversible while the new kind is unused —
--   ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
--   ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
--       CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept',
--                       'payout_approval', 'payout_outcome'));
-- — but that narrowing FAILS once a `payment_consent` row has been queued, and deleting
-- those rows to make it pass would drop consent requests people are waiting on. So: roll
-- the code back freely, and leave this constraint where it is.
SET lock_timeout = '3s';

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent'));
