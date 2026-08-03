CREATE TABLE mfa_trusted_devices (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES mfa_totp_credentials(user_id) ON DELETE CASCADE,
    user_agent_hash bytea NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT mfa_trusted_device_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT mfa_trusted_device_user_agent_hash_length CHECK (octet_length(user_agent_hash) = 32),
    CONSTRAINT mfa_trusted_device_expiry_valid CHECK (expires_at > created_at)
);

CREATE INDEX mfa_trusted_devices_by_user
    ON mfa_trusted_devices (user_id, last_used_at DESC);

CREATE INDEX mfa_trusted_devices_by_expiry
    ON mfa_trusted_devices (expires_at);
