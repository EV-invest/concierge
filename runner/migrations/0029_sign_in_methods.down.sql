-- Lossy: an account created by sign-in methods carries auth_subject = id::text and loses
-- its provider link here, so the previous binary would provision its Google sub anew.
SET LOCAL lock_timeout = '3s';

DELETE FROM notification_deliveries WHERE kind = 'email_code';
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome'));
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_subscriber;
ALTER TABLE notification_deliveries ALTER COLUMN subscriber_id SET NOT NULL;

DROP TABLE password_credentials;
DROP TABLE email_codes;
ALTER TABLE users DROP CONSTRAINT users_kyc_needs_verified_email;
DROP INDEX users_verified_email_idx;
DROP TRIGGER users_mirror_google_subject ON users;
DROP FUNCTION users_mirror_google_subject();
DROP TABLE user_identities;
DROP INDEX users_username_idx;
ALTER TABLE users DROP COLUMN username;
