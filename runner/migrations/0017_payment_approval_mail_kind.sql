-- One more value in the delivery queue's `kind` CHECK: `payment_approval`, the mail that
-- asks a seated OWNER to approve a payment of fund-owned money — the consilium
-- counterpart of 0016's `payment_consent`.
--
-- Everything 0016 argues holds here unchanged and is not restated: the list IS the
-- contract (an unrenderable kind must not be queueable); the change only WIDENS the
-- set, so the release running against the old schema keeps working through the rollout;
-- the drop-and-re-add takes ACCESS EXCLUSIVE over a table bounded by the daily send
-- budget, and `lock_timeout` is what stops a migration that would queue behind an open
-- transaction from taking the service down with it; and `NOT VALID` buys nothing inside
-- sqlx's single transaction per file.
--
-- REVERSIBILITY. The DDL is reversible while the new kind is unused —
--   ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
--   ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
--       CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept',
--                       'payout_approval', 'payout_outcome', 'payment_consent'));
-- — and stops being so the moment a `payment_approval` row is queued: the narrowing
-- fails, and deleting those rows to make it pass would drop approval requests a quorum
-- is waiting on. Roll the code back freely; leave this constraint where it is.
SET lock_timeout = '3s';

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval'));
