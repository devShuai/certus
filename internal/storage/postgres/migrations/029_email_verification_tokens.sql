CREATE TABLE email_verification_tokens (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT email_verification_expiry_valid CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX email_verification_active_by_user
    ON email_verification_tokens (user_id)
    WHERE consumed_at IS NULL;

CREATE INDEX email_verification_expiry
    ON email_verification_tokens (expires_at)
    WHERE consumed_at IS NULL;
