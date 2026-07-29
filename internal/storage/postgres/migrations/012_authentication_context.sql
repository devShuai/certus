ALTER TABLE sessions
    ADD COLUMN authentication_methods text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN assurance_level text NOT NULL DEFAULT 'urn:certus:aal:1';

ALTER TABLE oauth_authorization_codes
    ADD COLUMN authentication_methods text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN assurance_level text NOT NULL DEFAULT 'urn:certus:aal:1';

ALTER TABLE oauth_device_authorizations
    ADD COLUMN authentication_methods text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN assurance_level text NOT NULL DEFAULT 'urn:certus:aal:1';
