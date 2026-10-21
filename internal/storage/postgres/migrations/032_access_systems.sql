CREATE TABLE access_systems (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    favicon_url text NOT NULL DEFAULT '',
    launch_uri text NOT NULL DEFAULT '',
    portal_visible boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT access_systems_id_format CHECK (id ~ '^[a-z0-9][a-z0-9_-]{1,62}$')
);

INSERT INTO access_systems (id, name, description, favicon_url, launch_uri, portal_visible)
SELECT id, name, description, favicon_url, launch_uri, launch_uri <> ''
FROM oauth_clients;

-- Preserve the known production groupings while separating business systems
-- from OAuth clients. Unknown installations keep a one-to-one mapping.
INSERT INTO access_systems (id, name, description, favicon_url, launch_uri, portal_visible)
SELECT
    'codeburn',
    'CodeBurn',
    coalesce(max(description) FILTER (WHERE id = 'burn'), ''),
    coalesce(max(favicon_url) FILTER (WHERE id = 'burn'), ''),
    coalesce(max(launch_uri) FILTER (WHERE id = 'burn'), ''),
    true
FROM oauth_clients
WHERE id IN ('burn', 'codeburn-sync')
HAVING count(*) > 0
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    favicon_url = EXCLUDED.favicon_url,
    launch_uri = EXCLUDED.launch_uri,
    portal_visible = EXCLUDED.portal_visible,
    updated_at = now();

INSERT INTO access_systems (id, name, description, favicon_url, launch_uri, portal_visible)
SELECT
    'conspectus',
    'Conspectus',
    coalesce(max(description) FILTER (WHERE id = 'conspectus-prod'), ''),
    coalesce(max(favicon_url) FILTER (WHERE id = 'conspectus-prod'), ''),
    coalesce(max(launch_uri) FILTER (WHERE id = 'conspectus-prod'), ''),
    true
FROM oauth_clients
WHERE id IN ('conspectus-prod', 'conspectus-cli-prod')
HAVING count(*) > 0
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    favicon_url = EXCLUDED.favicon_url,
    launch_uri = EXCLUDED.launch_uri,
    portal_visible = EXCLUDED.portal_visible,
    updated_at = now();

ALTER TABLE oauth_clients ADD COLUMN system_id text;

UPDATE oauth_clients
SET system_id = CASE
    WHEN id IN ('burn', 'codeburn-sync') THEN 'codeburn'
    WHEN id IN ('conspectus-prod', 'conspectus-cli-prod') THEN 'conspectus'
    ELSE id
END;

ALTER TABLE oauth_clients
    ALTER COLUMN system_id SET NOT NULL,
    ADD CONSTRAINT oauth_clients_system_id_fkey
        FOREIGN KEY (system_id) REFERENCES access_systems(id) ON DELETE RESTRICT;

CREATE INDEX oauth_clients_by_system ON oauth_clients (system_id, name, id);

DELETE FROM access_systems s
WHERE NOT EXISTS (SELECT 1 FROM oauth_clients c WHERE c.system_id = s.id);
