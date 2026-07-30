ALTER TABLE oauth_clients
    ADD COLUMN token_endpoint_auth_method text;

UPDATE oauth_clients
SET token_endpoint_auth_method = CASE application_type
    WHEN 'confidential' THEN 'client_secret_basic'
    ELSE 'none'
END;

ALTER TABLE oauth_clients
    ALTER COLUMN token_endpoint_auth_method SET NOT NULL;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_client_auth_method_valid CHECK (
        (application_type = 'public' AND token_endpoint_auth_method = 'none')
        OR
        (application_type = 'confidential' AND token_endpoint_auth_method IN (
            'client_secret_basic',
            'client_secret_post'
        ))
    );
