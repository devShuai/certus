CREATE TABLE cas_proxy_granting_tickets (
    pgt_hash bytea PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    callback_url text NOT NULL,
    proxy_chain text[] NOT NULL DEFAULT '{}',
    primary_credentials boolean NOT NULL DEFAULT false,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX cas_proxy_granting_tickets_expiry
    ON cas_proxy_granting_tickets (expires_at);

CREATE TABLE cas_proxy_tickets (
    ticket_hash bytea PRIMARY KEY,
    pgt_hash bytea NOT NULL REFERENCES cas_proxy_granting_tickets(pgt_hash) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    target_service text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    proxy_chain text[] NOT NULL,
    primary_credentials boolean NOT NULL DEFAULT false,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE INDEX cas_proxy_tickets_expiry
    ON cas_proxy_tickets (expires_at)
    WHERE consumed_at IS NULL;
