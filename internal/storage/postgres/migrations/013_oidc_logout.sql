CREATE TABLE oauth_client_post_logout_redirect_uris (
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    PRIMARY KEY (client_id, redirect_uri),
    CONSTRAINT post_logout_redirect_uri_not_blank CHECK (length(redirect_uri) > 0)
);
