ALTER TABLE oauth_clients
    ADD COLUMN protocols text[] NOT NULL DEFAULT ARRAY['oauth2.1']::text[],
    ADD COLUMN grant_types text[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token']::text[],
    ADD COLUMN cas_version text NOT NULL DEFAULT '3.0',
    ADD COLUMN cas_service_urls text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN cas_proxy boolean NOT NULL DEFAULT false,
    ADD COLUMN cas_gateway boolean NOT NULL DEFAULT false,
    ADD COLUMN cas_renew boolean NOT NULL DEFAULT false,
    ADD COLUMN cas_single_logout boolean NOT NULL DEFAULT false;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_protocols_valid CHECK (
        cardinality(protocols) > 0
        AND protocols <@ ARRAY['oauth2.0', 'oauth2.1', 'cas']::text[]
    ),
    ADD CONSTRAINT oauth_clients_grants_valid CHECK (
        grant_types <@ ARRAY[
            'authorization_code',
            'refresh_token',
            'client_credentials',
            'urn:ietf:params:oauth:grant-type:device_code'
        ]::text[]
    ),
    ADD CONSTRAINT oauth_clients_cas_version_valid CHECK (
        cas_version IN ('1.0', '2.0', '3.0')
    ),
    ADD CONSTRAINT oauth_clients_cas_services_required CHECK (
        NOT ('cas' = ANY(protocols)) OR cardinality(cas_service_urls) > 0
    ),
    ADD CONSTRAINT oauth_clients_credentials_confidential CHECK (
        NOT ('client_credentials' = ANY(grant_types)) OR application_type = 'confidential'
    );
