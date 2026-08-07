ALTER TABLE users
    ADD COLUMN email_verified boolean NOT NULL DEFAULT false;

ALTER TABLE users
    ADD CONSTRAINT users_verified_email_present
    CHECK (NOT email_verified OR email IS NOT NULL);
