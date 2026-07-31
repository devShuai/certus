ALTER TABLE oauth_clients
    ADD COLUMN favicon_url text NOT NULL DEFAULT '';

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_favicon_url_length
    CHECK (length(favicon_url) <= 2048);
