SET LOCAL lock_timeout = '3s';

DROP TRIGGER user_outbox_stamp_permissions ON user_outbox;
DROP FUNCTION user_outbox_stamp_permissions();
DROP TRIGGER seat_meanings_only_newer ON seat_meanings;
DROP FUNCTION seat_meanings_only_newer();
ALTER TABLE seat_meanings DROP COLUMN generation;
ALTER TABLE seat_meanings ADD CONSTRAINT seat_meanings_role CHECK (role IN ('investor', 'operator', 'admin', 'owner'));
