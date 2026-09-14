-- Two more values in the delivery queue's `kind` CHECK: `fee_policy_approval`, the mail
-- that asks a seated OWNER to approve new fee terms for a fund, and `fee_policy_notice`,
-- the mail that tells ONE investor the terms of a fund they hold are changing.
--
-- Everything 0016 argues holds here unchanged and is not restated: the list IS the
-- contract (an unrenderable kind must not be queueable); the change only WIDENS the
-- set, so the release running against the old schema keeps working through the rollout;
-- the drop-and-re-add takes ACCESS EXCLUSIVE over a table bounded by the daily send
-- budget, and `lock_timeout` is what stops a migration that would queue behind an open
-- transaction from taking the service down with it; and `NOT VALID` buys nothing inside
-- sqlx's single transaction per file.
--
-- REVERSIBILITY. The DDL is reversible while the new kinds are unused —
--   ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
--   ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
--       CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept',
--                       'payout_approval', 'payout_outcome', 'payment_consent',
--                       'payment_approval'));
-- — and stops being so the moment a row of either kind is queued: the narrowing fails,
-- and deleting those rows to make it pass would drop approval requests a quorum is
-- waiting on and notices investors are owed. Roll the code back freely; leave this
-- constraint where it is.
SET lock_timeout = '3s';

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice'));
