-- One more value in the delivery queue's `kind` CHECK: `payment_outcome`, the mail the
-- money plane relays when a payment dies waiting for its subject's consent — the consent
-- link burned on five wrong codes, or was invalidated when the subject's sessions were
-- revoked or their address changed (banking#238). Until now that payment was rejected
-- silently: nobody was told, neither the subject whose link was attacked nor the staff
-- member who opened the order. `payout_outcome` cannot carry it: that kind goes to seated
-- owners only, and neither of the people this one is for usually holds a seat.
--
-- The change only WIDENS the constraint; nothing already queued can violate it. The
-- CHECK exists so an unrenderable kind cannot be queued: `dispatch::governance_mail`
-- answers `None` for a kind it does not know and PARKS the row rather than retrying it,
-- so a kind accepted here without a renderer would be mail that is silently never sent.
--
-- `lock_timeout`, as in 0016/0017/0019/0020 for this same DROP/ADD, and load-bearing for
-- the reason those state: migrations run ON BOOT, the drop-and-re-add takes ACCESS
-- EXCLUSIVE, and the dispatcher holds transactions over this very table while it claims
-- rows on a 300-second lease. Without a timeout the migrator queues behind one of those
-- indefinitely and the boot never finishes, instead of failing honestly in three seconds
-- and retrying on the next start. SET LOCAL, as in 0020: sqlx runs this file in its own
-- transaction on a connection borrowed from the service's pool, and a session-level SET
-- would outlive the migration on that connection.
--
-- REVERSIBILITY. Reversible while the new kind is unused --
--   ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
--   ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
--       CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept',
--                       'payout_approval', 'payout_outcome', 'payment_consent',
--                       'payment_approval', 'fee_policy_approval', 'fee_policy_notice',
--                       'kyc_verdict_alert'));
-- -- and stops being so the moment a row of this kind is queued: the narrowing fails,
-- and forcing it would silently strand a mail somebody is owed.

SET LOCAL lock_timeout = '3s';

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome'));
