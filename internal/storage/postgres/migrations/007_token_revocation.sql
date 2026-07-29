ALTER TABLE oauth_access_tokens
    ADD COLUMN refresh_family_id uuid;

CREATE INDEX oauth_access_tokens_refresh_family
    ON oauth_access_tokens (refresh_family_id)
    WHERE refresh_family_id IS NOT NULL AND revoked_at IS NULL;
