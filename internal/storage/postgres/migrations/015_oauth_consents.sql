CREATE TABLE oauth_consents (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX oauth_consents_by_user
    ON oauth_consents (user_id, updated_at DESC);
