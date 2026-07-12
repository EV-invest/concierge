-- Defense-in-depth for the input-validation pass (#25): the domain now
-- parse-validates every profile / platform-config string; these CHECKs backstop
-- the same length caps at the store so no future caller can bypass them.
--
-- Sanitize FIRST: live rows already carry junk (https URLs in phone, full words
-- in language, bare words in timezone), and ADD CONSTRAINT validates existing
-- rows. Length is enforced for every column; charset/shape is cleared via regex
-- where expressible in SQL (phone, date_of_birth, language, base_currency,
-- timezone). Profile columns are nullable with NULL = unset, so a violating
-- value is cleared, not truncated.

UPDATE users SET legal_name = NULL WHERE char_length(legal_name) > 256;
UPDATE users SET preferred_name = NULL WHERE char_length(preferred_name) > 256;

UPDATE users SET phone = NULL WHERE char_length(phone) > 32
	OR phone !~ '^[0-9+() -]+$'
	OR phone !~ '^([^0-9]*[0-9]){5}';

-- CASE forces evaluation order so the casts only run on shape-matched values.
UPDATE users SET date_of_birth = NULL WHERE CASE
	WHEN date_of_birth IS NULL THEN FALSE
	WHEN date_of_birth !~ '^\d{4}-\d{2}-\d{2}$' THEN TRUE
	WHEN substring(date_of_birth, 1, 4)::int NOT BETWEEN 1900 AND 2100 THEN TRUE
	WHEN substring(date_of_birth, 6, 2)::int NOT BETWEEN 1 AND 12 THEN TRUE
	WHEN substring(date_of_birth, 9, 2)::int NOT BETWEEN 1 AND extract(day FROM (
		make_date(substring(date_of_birth, 1, 4)::int, substring(date_of_birth, 6, 2)::int, 1)
		+ interval '1 month' - interval '1 day'))::int THEN TRUE
	ELSE FALSE
END;

UPDATE users SET nationality = NULL WHERE char_length(nationality) > 64;
UPDATE users SET tax_residence = NULL WHERE char_length(tax_residence) > 64;
UPDATE users SET residential_address = NULL WHERE char_length(residential_address) > 256;

UPDATE users SET language = NULL WHERE char_length(language) > 16
	OR language !~ '^[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})*$';

UPDATE users SET base_currency = NULL WHERE base_currency !~ '^[A-Za-z]{3}$';
-- Align surviving values with the domain's uppercase normalization.
UPDATE users SET base_currency = upper(base_currency) WHERE base_currency ~ '[a-z]';

UPDATE users SET timezone = NULL WHERE char_length(timezone) > 64
	OR timezone !~ '^(UTC|GMT|(Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Etc|Europe|Indian|Pacific)(/[A-Za-z0-9_+-]+)+)$';

-- The announcement columns are NOT NULL (empty = cleared banner) and operator
-- authored, so over-long values are truncated rather than dropped.
UPDATE platform_config SET announcement_title = left(announcement_title, 200) WHERE char_length(announcement_title) > 200;
UPDATE platform_config SET announcement_body = left(announcement_body, 2000) WHERE char_length(announcement_body) > 2000;

UPDATE feature_flags SET description = left(description, 500) WHERE char_length(description) > 500;
-- The key is the PRIMARY KEY — an over-long one cannot be truncated (collision
-- risk), and a flag nobody can address by a sane key is junk.
DELETE FROM feature_flags WHERE char_length(key) > 64;

ALTER TABLE users
	ADD CONSTRAINT users_legal_name_len CHECK (char_length(legal_name) <= 256),
	ADD CONSTRAINT users_preferred_name_len CHECK (char_length(preferred_name) <= 256),
	ADD CONSTRAINT users_phone_len CHECK (char_length(phone) <= 32),
	ADD CONSTRAINT users_date_of_birth_len CHECK (char_length(date_of_birth) <= 10),
	ADD CONSTRAINT users_nationality_len CHECK (char_length(nationality) <= 64),
	ADD CONSTRAINT users_tax_residence_len CHECK (char_length(tax_residence) <= 64),
	ADD CONSTRAINT users_residential_address_len CHECK (char_length(residential_address) <= 256),
	ADD CONSTRAINT users_language_len CHECK (char_length(language) <= 16),
	ADD CONSTRAINT users_base_currency_len CHECK (char_length(base_currency) <= 3),
	ADD CONSTRAINT users_timezone_len CHECK (char_length(timezone) <= 64);

ALTER TABLE platform_config
	ADD CONSTRAINT platform_config_announcement_title_len CHECK (char_length(announcement_title) <= 200),
	ADD CONSTRAINT platform_config_announcement_body_len CHECK (char_length(announcement_body) <= 2000);

ALTER TABLE feature_flags
	ADD CONSTRAINT feature_flags_key_len CHECK (char_length(key) <= 64),
	ADD CONSTRAINT feature_flags_description_len CHECK (char_length(description) <= 500);
