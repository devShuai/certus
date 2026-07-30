ALTER TABLE oauth_authorization_codes
    ADD COLUMN revoked_at timestamptz;

ALTER TABLE oauth_access_tokens
    ADD COLUMN session_id uuid REFERENCES sessions(id) ON DELETE CASCADE;

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN session_id uuid REFERENCES sessions(id) ON DELETE CASCADE;

-- Existing user tokens cannot be associated with a single login session
-- safely. Revoke them during the upgrade so every active user token after
-- this migration participates in the session revocation invariant.
UPDATE oauth_access_tokens
    SET revoked_at = coalesce(revoked_at, now())
    WHERE user_id IS NOT NULL;

UPDATE oauth_refresh_tokens
    SET revoked_at = coalesce(revoked_at, now());

CREATE INDEX oauth_authorization_codes_active_session
    ON oauth_authorization_codes (user_id, session_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX oauth_access_tokens_active_session
    ON oauth_access_tokens (user_id, session_id)
    WHERE revoked_at IS NULL;

CREATE INDEX oauth_refresh_tokens_active_session
    ON oauth_refresh_tokens (user_id, session_id)
    WHERE revoked_at IS NULL;
