CREATE TABLE rate_limit_buckets (
    scope text NOT NULL,
    subject_hash bytea NOT NULL,
    attempts integer NOT NULL,
    window_ends_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (scope, subject_hash),
    CONSTRAINT rate_limit_scope_valid CHECK (
        scope ~ '^[a-z][a-z0-9_.-]{0,63}$'
    ),
    CONSTRAINT rate_limit_subject_hash_valid CHECK (
        octet_length(subject_hash) = 32
    ),
    CONSTRAINT rate_limit_attempts_positive CHECK (
        attempts > 0
    )
);

CREATE INDEX rate_limit_buckets_by_expiration
    ON rate_limit_buckets (window_ends_at);
