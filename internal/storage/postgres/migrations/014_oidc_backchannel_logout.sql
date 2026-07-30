ALTER TABLE oauth_clients
    ADD COLUMN backchannel_logout_uri text NOT NULL DEFAULT '',
    ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_backchannel_logout_protocol CHECK (
        backchannel_logout_uri = ''
        OR protocols && ARRAY['oauth2.0', 'oauth2.1']::text[]
    ),
    ADD CONSTRAINT oauth_clients_backchannel_logout_session CHECK (
        NOT backchannel_logout_session_required OR backchannel_logout_uri <> ''
    );

CREATE TABLE oidc_client_sessions (
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, client_id)
);

CREATE INDEX oidc_client_sessions_by_session
    ON oidc_client_sessions (session_id);
