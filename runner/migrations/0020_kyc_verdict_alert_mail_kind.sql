-- One more value in the delivery queue's `kind` CHECK: `kyc_verdict_alert`, the mail the
-- owners get when a verification vendor reports a verdict that CONTRADICTS a level the
-- account already holds.
--
-- WHY A MAIL AND NOT JUST A LOG. `web/kyc.rs::apply` leaves the level alone on every
-- terminal verdict, and that is the policy: a downgrade is a human act under
-- `Permission::KycManage`, and a vendor must never be able to take a level away. But the
-- case where the verdict says "this person's verification has lapsed" while the account
-- still stands at the level that verification bought is not a state anyone is watching.
-- It lived as one row in a table nobody reads, so "a human decides" was in practice
-- "nobody decides" (#49). An `error!` reaches Sentry; a mail reaches the people who hold
-- `KycManage`, which is who actually has to decide.
--
-- WHY THE QUEUE AND NOT THE NOTIFICATION TOPIC. The user's own notice about the same
-- verdict goes through `account:verification`, which a subscriber can switch off — as
-- they should be able to. The owners' copy is operational and must not be mutable by its
-- recipient, so it takes the governance-mail path, which carries no unsubscribe target.
--
-- The change only WIDENS the constraint; nothing already queued can violate it. The
-- CHECK exists so an unrenderable kind cannot be queued: `dispatch::governance_mail`
-- answers `None` for a kind it does not know and PARKS the row rather than retrying it,
-- so a kind accepted here without a renderer would be mail that is silently never sent.
--
-- `lock_timeout`, as in 0016/0017/0019 for this same DROP/ADD, and load-bearing here for
-- the reason those state: migrations run ON BOOT, the drop-and-re-add takes ACCESS
-- EXCLUSIVE, and the dispatcher holds transactions over this very table while it claims
-- rows on a 300-second lease. Without a timeout the migrator queues behind one of those
-- indefinitely, the boot never finishes and the deploy stops with no error at all —
-- instead of failing honestly in three seconds and retrying on the next start.
--
-- SET LOCAL, not SET — the one way this differs from 0016/0017/0019. sqlx runs this file
-- in its own transaction on a connection BORROWED from the service's pool and hands that
-- connection back afterwards, so a session-level SET outlives the migration and puts a 3s
-- ceiling on every row lock the next request served on that connection waits for. LOCAL
-- ends the setting with the transaction. 0011–0019 predate the rule and stay as they are:
-- sqlx checksums an applied migration at every boot, so editing one is a refusal to start.
--
-- REVERSIBILITY. Reversible while the new kind is unused --
--   ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
--   ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
--       CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept',
--                       'payout_approval', 'payout_outcome', 'payment_consent',
--                       'payment_approval', 'fee_policy_approval', 'fee_policy_notice'));
-- -- and stops being so the moment a row of this kind is queued: the narrowing fails,
-- and forcing it would silently strand a mail an owner is waiting on.

SET LOCAL lock_timeout = '3s';

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert'));
