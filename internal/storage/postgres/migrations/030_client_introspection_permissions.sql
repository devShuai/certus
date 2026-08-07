CREATE TABLE oauth_client_introspection_permissions (
    token_client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    introspector_client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
    position smallint NOT NULL DEFAULT 0,
    PRIMARY KEY (token_client_id, introspector_client_id),
    CONSTRAINT oauth_client_introspection_permissions_distinct_clients
        CHECK (token_client_id <> introspector_client_id)
);

CREATE INDEX oauth_client_introspection_permissions_by_introspector
    ON oauth_client_introspection_permissions (introspector_client_id, token_client_id);
