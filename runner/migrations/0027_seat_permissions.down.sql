-- Banking keeps what it mirrored and is told nothing new.
SET LOCAL lock_timeout = '3s';

DROP TABLE seat_meanings;
ALTER TABLE user_outbox DROP COLUMN permissions;
