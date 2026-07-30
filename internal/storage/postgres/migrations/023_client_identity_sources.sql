CREATE TABLE oauth_client_identity_sources (
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    source_id text NOT NULL REFERENCES identity_sources(id) ON DELETE RESTRICT,
    position smallint NOT NULL DEFAULT 0,
    PRIMARY KEY (client_id, source_id)
);

CREATE INDEX oauth_client_identity_sources_by_source
    ON oauth_client_identity_sources (source_id, client_id);
