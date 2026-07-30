CREATE TABLE admin_role_grants (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_code text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    granted_by text NOT NULL,
    PRIMARY KEY (user_id, role_code),
    CONSTRAINT admin_role_code_valid CHECK (
        role_code IN (
            'super_admin',
            'identity_admin',
            'application_admin',
            'security_admin',
            'auditor'
        )
    ),
    CONSTRAINT admin_role_granted_by_not_blank CHECK (length(granted_by) > 0)
);

CREATE INDEX admin_role_grants_by_role
    ON admin_role_grants (role_code, user_id);
