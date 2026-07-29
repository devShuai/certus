CREATE TABLE mfa_totp_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext bytea NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,
    last_used_step bigint NOT NULL DEFAULT -1,
    failed_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    CONSTRAINT mfa_failed_attempts_nonnegative CHECK (failed_attempts >= 0)
);

CREATE TABLE mfa_recovery_codes (
    user_id uuid NOT NULL REFERENCES mfa_totp_credentials(user_id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

CREATE INDEX mfa_recovery_codes_unused
    ON mfa_recovery_codes (user_id)
    WHERE used_at IS NULL;
