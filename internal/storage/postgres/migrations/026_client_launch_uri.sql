ALTER TABLE oauth_clients
    ADD COLUMN launch_uri text NOT NULL DEFAULT '';

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_launch_uri_length
    CHECK (length(launch_uri) <= 2048);
