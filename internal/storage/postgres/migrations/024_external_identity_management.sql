ALTER TABLE external_identities
    ADD COLUMN updated_at timestamptz;

UPDATE external_identities
SET updated_at = created_at
WHERE updated_at IS NULL;

ALTER TABLE external_identities
    ALTER COLUMN updated_at SET DEFAULT now(),
    ALTER COLUMN updated_at SET NOT NULL;

CREATE INDEX external_identities_by_user
    ON external_identities (user_id, created_at, id);
