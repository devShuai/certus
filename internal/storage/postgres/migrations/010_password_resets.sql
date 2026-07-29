CREATE TABLE password_reset_tokens (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT password_reset_expiry_valid CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX password_reset_active_by_user
    ON password_reset_tokens (user_id)
    WHERE consumed_at IS NULL;

CREATE INDEX password_reset_expiry
    ON password_reset_tokens (expires_at)
    WHERE consumed_at IS NULL;
