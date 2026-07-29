ALTER TABLE oauth_clients
    ADD COLUMN application_type text NOT NULL DEFAULT 'public',
    ADD COLUMN allowed_scopes text[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email']::text[],
    ADD COLUMN client_secret_hash bytea;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_application_type
        CHECK (application_type IN ('public', 'confidential')),
    ADD CONSTRAINT oauth_clients_secret_policy
        CHECK (
            (application_type = 'public' AND client_secret_hash IS NULL)
            OR
            (application_type = 'confidential' AND client_secret_hash IS NOT NULL)
        ),
    ADD CONSTRAINT oauth_clients_openid_scope
        CHECK ('openid' = ANY(allowed_scopes));
