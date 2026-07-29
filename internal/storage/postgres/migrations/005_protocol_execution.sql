ALTER TABLE oauth_authorization_codes
    ADD COLUMN session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,
    ADD COLUMN authenticated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE oauth_access_tokens (
    token_hash bytea PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    scope text[] NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX oauth_access_tokens_expiry
    ON oauth_access_tokens (expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE oauth_device_authorizations (
    device_code_hash bytea PRIMARY KEY,
    user_code_hash bytea NOT NULL UNIQUE,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    scope text[] NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    authenticated_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    interval_seconds integer NOT NULL DEFAULT 5,
    last_poll_at timestamptz,
    decided_at timestamptz,
    consumed_at timestamptz,
    CONSTRAINT oauth_device_status_valid CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    CONSTRAINT oauth_device_interval_positive CHECK (interval_seconds > 0)
);

CREATE INDEX oauth_device_authorizations_expiry
    ON oauth_device_authorizations (expires_at)
    WHERE status IN ('pending', 'approved');

CREATE TABLE cas_service_tickets (
    ticket_hash bytea PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    service_url text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    primary_credentials boolean NOT NULL DEFAULT false,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE INDEX cas_service_tickets_expiry
    ON cas_service_tickets (expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE cas_service_sessions (
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    service_url text NOT NULL,
    ticket text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (session_id, service_url)
);

CREATE TABLE oidc_signing_keys (
    kid text PRIMARY KEY,
    private_key_pem bytea NOT NULL,
    algorithm text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    CONSTRAINT oidc_signing_algorithm_supported CHECK (algorithm = 'RS256')
);

CREATE UNIQUE INDEX oidc_one_active_signing_key
    ON oidc_signing_keys (active)
    WHERE active = true;
