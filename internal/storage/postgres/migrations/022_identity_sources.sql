CREATE TABLE identity_sources (
    id text PRIMARY KEY,
    name text NOT NULL,
    source_type text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    ldap_url text,
    ldap_start_tls boolean,
    ldap_base_dn text,
    ldap_bind_dn text,
    ldap_user_filter text,
    ldap_username_attribute text,
    ldap_display_name_attribute text,
    ldap_email_attribute text,
    oidc_issuer text,
    oidc_client_id text,
    oidc_scopes text[],
    secret_ciphertext bytea,
    secret_key_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,
    CONSTRAINT identity_sources_id_format
        CHECK (id ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
    CONSTRAINT identity_sources_type_valid
        CHECK (source_type IN ('ldap', 'oidc')),
    CONSTRAINT identity_sources_configuration_shape
        CHECK (
            (
                source_type = 'ldap'
                AND ldap_url IS NOT NULL
                AND ldap_base_dn IS NOT NULL
                AND ldap_user_filter IS NOT NULL
                AND oidc_issuer IS NULL
                AND oidc_client_id IS NULL
                AND oidc_scopes IS NULL
            )
            OR
            (
                source_type = 'oidc'
                AND oidc_issuer IS NOT NULL
                AND oidc_client_id IS NOT NULL
                AND oidc_scopes IS NOT NULL
                AND ldap_url IS NULL
                AND ldap_base_dn IS NULL
                AND ldap_user_filter IS NULL
            )
        ),
    CONSTRAINT identity_sources_secret_metadata
        CHECK (
            (secret_ciphertext IS NULL AND secret_key_id IS NULL)
            OR
            (secret_ciphertext IS NOT NULL AND secret_key_id IS NOT NULL)
        )
);

CREATE INDEX identity_sources_active
    ON identity_sources (source_type, name, id)
    WHERE enabled = true AND archived_at IS NULL;
