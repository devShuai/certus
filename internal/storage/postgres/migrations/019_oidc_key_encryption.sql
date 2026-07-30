ALTER TABLE oidc_signing_keys
    ADD COLUMN encryption_key_id text;

ALTER TABLE oidc_signing_keys
    ADD CONSTRAINT oidc_signing_key_encryption_id_valid CHECK (
        encryption_key_id IS NULL OR
        encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$'
    );
