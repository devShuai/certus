ALTER TABLE oauth_clients
    ADD COLUMN archived_at timestamptz;

CREATE INDEX oauth_clients_active
    ON oauth_clients (enabled, name, id)
    WHERE archived_at IS NULL;
