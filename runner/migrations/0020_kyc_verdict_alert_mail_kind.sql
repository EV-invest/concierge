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
-- REVERSIBILITY. Reversible while the new kind is unused --
--   ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
--   ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
--       CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept',
--                       'payout_approval', 'payout_outcome', 'payment_consent',
--                       'payment_approval', 'fee_policy_approval', 'fee_policy_notice'));
-- -- and stops being so the moment a row of this kind is queued: the narrowing fails,
-- and forcing it would silently strand a mail an owner is waiting on.

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert'));
