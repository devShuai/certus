ALTER TABLE oauth_clients
    ADD COLUMN access_token_lifetime_seconds integer NOT NULL DEFAULT 900,
    ADD COLUMN refresh_token_lifetime_seconds integer NOT NULL DEFAULT 2592000;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_access_token_lifetime_valid CHECK (
        access_token_lifetime_seconds BETWEEN 60 AND 86400
    ),
    ADD CONSTRAINT oauth_clients_refresh_token_lifetime_valid CHECK (
        refresh_token_lifetime_seconds BETWEEN 3600 AND 31536000
        AND refresh_token_lifetime_seconds >= access_token_lifetime_seconds
    );
