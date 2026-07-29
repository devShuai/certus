CREATE TABLE access_roles (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    code text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (client_id, code),
    CONSTRAINT access_roles_code_format CHECK (code ~ '^[a-z][a-z0-9._-]{1,63}$')
);

CREATE TABLE access_permissions (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    code text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (client_id, code),
    CONSTRAINT access_permissions_code_format CHECK (code ~ '^[a-z][a-z0-9._-]{1,63}$')
);

CREATE TABLE access_role_permissions (
    role_id uuid NOT NULL REFERENCES access_roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES access_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE access_user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES access_roles(id) ON DELETE CASCADE,
    granted_at timestamptz NOT NULL,
    granted_by text NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX access_user_roles_active
    ON access_user_roles (user_id, role_id, expires_at);
