ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_unique;

CREATE UNIQUE INDEX users_username_unique
    ON users (lower(username));
