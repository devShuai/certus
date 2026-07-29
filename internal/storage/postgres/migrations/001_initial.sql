CREATE TABLE oauth_clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oauth_clients_id_format CHECK (id ~ '^[a-z0-9][a-z0-9_-]{1,62}$')
);

CREATE TABLE oauth_client_redirect_uris (
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    PRIMARY KEY (client_id, redirect_uri),
    CONSTRAINT redirect_uri_not_blank CHECK (length(redirect_uri) > 0)
);

CREATE TABLE oauth_client_login_methods (
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    method text NOT NULL,
    position smallint NOT NULL DEFAULT 0,
    PRIMARY KEY (client_id, method),
    CONSTRAINT supported_login_method CHECK (method IN ('password', 'ldap', 'oidc'))
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    email text,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_username_unique UNIQUE (username),
    CONSTRAINT users_status_valid CHECK (status IN ('active', 'locked', 'disabled'))
);

CREATE UNIQUE INDEX users_email_unique
    ON users (lower(email))
    WHERE email IS NOT NULL;

CREATE TABLE user_password_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    failed_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    CONSTRAINT failed_attempts_nonnegative CHECK (failed_attempts >= 0)
);

CREATE TABLE external_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id text NOT NULL,
    provider_subject text NOT NULL,
    profile jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, provider_subject)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    authenticated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    ip_address inet,
    user_agent text NOT NULL DEFAULT '',
    revoked_at timestamptz
);

CREATE INDEX sessions_active_by_user
    ON sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE oauth_authorization_codes (
    code_hash bytea PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scope text[] NOT NULL,
    nonce text NOT NULL DEFAULT '',
    code_challenge text NOT NULL,
    code_challenge_method text NOT NULL DEFAULT 'S256',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT authorization_code_pkce_s256 CHECK (code_challenge_method = 'S256')
);

CREATE INDEX oauth_authorization_codes_expiry
    ON oauth_authorization_codes (expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE oauth_refresh_tokens (
    token_hash bytea PRIMARY KEY,
    family_id uuid NOT NULL,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope text[] NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    replaced_by_hash bytea
);

CREATE INDEX oauth_refresh_tokens_family
    ON oauth_refresh_tokens (family_id);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    event_type text NOT NULL,
    client_id text REFERENCES oauth_clients(id) ON DELETE SET NULL,
    ip_address inet,
    request_id text NOT NULL DEFAULT '',
    outcome text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT audit_outcome_valid CHECK (outcome IN ('success', 'failure'))
);

CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_actor ON audit_events (actor_user_id, occurred_at DESC);
