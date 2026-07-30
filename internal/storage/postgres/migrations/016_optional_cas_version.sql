ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_cas_version_valid,
    ADD CONSTRAINT oauth_clients_cas_version_valid CHECK (
        cas_version IN ('', '1.0', '2.0', '3.0')
    );
