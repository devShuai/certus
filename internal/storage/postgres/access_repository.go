package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/access"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AccessRepository struct {
	pool *pgxpool.Pool
}

func NewAccessRepository(pool *pgxpool.Pool) *AccessRepository {
	return &AccessRepository{pool: pool}
}

func (r *AccessRepository) ListRoles(ctx context.Context, clientID string) ([]access.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, client_id, code, name, description, created_at, updated_at
		FROM access_roles
		WHERE client_id = $1
		ORDER BY code`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list access roles: %w", err)
	}
	defer rows.Close()
	result := make([]access.Role, 0)
	for rows.Next() {
		value, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access roles: %w", err)
	}
	return result, nil
}

func (r *AccessRepository) CreateRole(ctx context.Context, value access.Role) (access.Role, error) {
	created, err := scanRole(r.pool.QueryRow(ctx, `
		INSERT INTO access_roles (id, client_id, code, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		RETURNING id::text, client_id, code, name, description, created_at, updated_at`,
		value.ID, value.ClientID, value.Code, value.Name, value.Description, value.CreatedAt,
	))
	if isUniqueViolation(err) {
		return access.Role{}, access.ErrConflict
	}
	if err != nil {
		return access.Role{}, fmt.Errorf("create access role: %w", err)
	}
	return created, nil
}

func (r *AccessRepository) FindRole(ctx context.Context, clientID, roleID string) (access.Role, error) {
	value, err := scanRole(r.pool.QueryRow(ctx, `
		SELECT id::text, client_id, code, name, description, created_at, updated_at
		FROM access_roles
		WHERE id = $1 AND client_id = $2`,
		roleID, clientID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return access.Role{}, access.ErrNotFound
	}
	if err != nil {
		return access.Role{}, fmt.Errorf("find access role: %w", err)
	}
	return value, nil
}

func (r *AccessRepository) ReplaceRole(ctx context.Context, value access.Role) (access.Role, error) {
	updated, err := scanRole(r.pool.QueryRow(ctx, `
		UPDATE access_roles
		SET code = $3, name = $4, description = $5, updated_at = $6
		WHERE id = $1 AND client_id = $2
		RETURNING id::text, client_id, code, name, description, created_at, updated_at`,
		value.ID, value.ClientID, value.Code, value.Name, value.Description, value.UpdatedAt,
	))
	if isUniqueViolation(err) {
		return access.Role{}, access.ErrConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return access.Role{}, access.ErrNotFound
	}
	if err != nil {
		return access.Role{}, fmt.Errorf("replace access role: %w", err)
	}
	return updated, nil
}

func (r *AccessRepository) DeleteRole(ctx context.Context, clientID, roleID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin access role deletion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedID string
	if err := tx.QueryRow(ctx, `
		SELECT id::text
		FROM access_roles
		WHERE id = $1 AND client_id = $2
		FOR UPDATE`,
		roleID, clientID,
	).Scan(&lockedID); errors.Is(err, pgx.ErrNoRows) {
		return access.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("lock access role for deletion: %w", err)
	}
	var inUse bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_user_roles WHERE role_id = $1)`, roleID).Scan(&inUse); err != nil {
		return fmt.Errorf("check access role assignments: %w", err)
	}
	if inUse {
		return access.ErrInUse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM access_roles WHERE id = $1`, roleID); err != nil {
		return fmt.Errorf("delete access role: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit access role deletion: %w", err)
	}
	return nil
}

func (r *AccessRepository) ListPermissions(ctx context.Context, clientID string) ([]access.Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, client_id, code, name, description, created_at, updated_at
		FROM access_permissions
		WHERE client_id = $1
		ORDER BY code`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list access permissions: %w", err)
	}
	defer rows.Close()
	result := make([]access.Permission, 0)
	for rows.Next() {
		value, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access permissions: %w", err)
	}
	return result, nil
}

func (r *AccessRepository) CreatePermission(ctx context.Context, value access.Permission) (access.Permission, error) {
	created, err := scanPermission(r.pool.QueryRow(ctx, `
		INSERT INTO access_permissions (id, client_id, code, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		RETURNING id::text, client_id, code, name, description, created_at, updated_at`,
		value.ID, value.ClientID, value.Code, value.Name, value.Description, value.CreatedAt,
	))
	if isUniqueViolation(err) {
		return access.Permission{}, access.ErrConflict
	}
	if err != nil {
		return access.Permission{}, fmt.Errorf("create access permission: %w", err)
	}
	return created, nil
}

func (r *AccessRepository) FindPermission(ctx context.Context, clientID, permissionID string) (access.Permission, error) {
	value, err := scanPermission(r.pool.QueryRow(ctx, `
		SELECT id::text, client_id, code, name, description, created_at, updated_at
		FROM access_permissions
		WHERE id = $1 AND client_id = $2`,
		permissionID, clientID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return access.Permission{}, access.ErrNotFound
	}
	if err != nil {
		return access.Permission{}, fmt.Errorf("find access permission: %w", err)
	}
	return value, nil
}

func (r *AccessRepository) ReplacePermission(ctx context.Context, value access.Permission) (access.Permission, error) {
	updated, err := scanPermission(r.pool.QueryRow(ctx, `
		UPDATE access_permissions
		SET code = $3, name = $4, description = $5, updated_at = $6
		WHERE id = $1 AND client_id = $2
		RETURNING id::text, client_id, code, name, description, created_at, updated_at`,
		value.ID, value.ClientID, value.Code, value.Name, value.Description, value.UpdatedAt,
	))
	if isUniqueViolation(err) {
		return access.Permission{}, access.ErrConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return access.Permission{}, access.ErrNotFound
	}
	if err != nil {
		return access.Permission{}, fmt.Errorf("replace access permission: %w", err)
	}
	return updated, nil
}

func (r *AccessRepository) DeletePermission(ctx context.Context, clientID, permissionID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin access permission deletion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedID string
	if err := tx.QueryRow(ctx, `
		SELECT id::text
		FROM access_permissions
		WHERE id = $1 AND client_id = $2
		FOR UPDATE`,
		permissionID, clientID,
	).Scan(&lockedID); errors.Is(err, pgx.ErrNoRows) {
		return access.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("lock access permission for deletion: %w", err)
	}
	var inUse bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_role_permissions WHERE permission_id = $1)`, permissionID).Scan(&inUse); err != nil {
		return fmt.Errorf("check access permission references: %w", err)
	}
	if inUse {
		return access.ErrInUse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM access_permissions WHERE id = $1`, permissionID); err != nil {
		return fmt.Errorf("delete access permission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit access permission deletion: %w", err)
	}
	return nil
}

func (r *AccessRepository) SetRolePermissions(ctx context.Context, clientID, roleID string, permissionIDs []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin role permission replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM access_roles WHERE id = $1 AND client_id = $2
		)`,
		roleID, clientID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("find role for permissions: %w", err)
	}
	if !exists {
		return access.ErrNotFound
	}
	seen := make(map[string]struct{}, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		if _, duplicate := seen[permissionID]; duplicate {
			continue
		}
		seen[permissionID] = struct{}{}
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM access_permissions WHERE id = $1 AND client_id = $2
			)`,
			permissionID, clientID,
		).Scan(&exists); err != nil {
			return fmt.Errorf("find permission for role: %w", err)
		}
		if !exists {
			return access.ErrNotFound
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM access_role_permissions WHERE role_id = $1`, roleID); err != nil {
		return fmt.Errorf("delete role permissions: %w", err)
	}
	for permissionID := range seen {
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_role_permissions (role_id, permission_id)
			VALUES ($1, $2)`,
			roleID, permissionID,
		); err != nil {
			return fmt.Errorf("insert role permission: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit role permission replacement: %w", err)
	}
	return nil
}

func (r *AccessRepository) ListRolePermissions(ctx context.Context, clientID, roleID string) ([]access.Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.id::text, p.client_id, p.code, p.name, p.description, p.created_at, p.updated_at
		FROM access_roles r
		JOIN access_role_permissions rp ON rp.role_id = r.id
		JOIN access_permissions p ON p.id = rp.permission_id
		WHERE r.id = $1 AND r.client_id = $2
		ORDER BY p.code`,
		roleID, clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}
	defer rows.Close()
	result := make([]access.Permission, 0)
	for rows.Next() {
		value, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role permissions: %w", err)
	}
	if len(result) == 0 {
		var exists bool
		if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_roles WHERE id = $1 AND client_id = $2)`, roleID, clientID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, access.ErrNotFound
		}
	}
	return result, nil
}

func (r *AccessRepository) ReplaceUserRoles(ctx context.Context, userID string, grants []access.RoleGrant, grantedBy string, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin user role replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, grant := range grants {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_roles WHERE id = $1)`, grant.RoleID).Scan(&exists); err != nil {
			return fmt.Errorf("find role for user: %w", err)
		}
		if !exists {
			return access.ErrNotFound
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM access_user_roles WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete user roles: %w", err)
	}
	for _, grant := range grants {
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_user_roles (user_id, role_id, granted_at, granted_by, expires_at)
			VALUES ($1, $2, $3, $4, $5)`,
			userID, grant.RoleID, now.UTC(), grantedBy, grant.ExpiresAt,
		); err != nil {
			if isForeignKeyViolation(err) {
				return access.ErrNotFound
			}
			return fmt.Errorf("insert user role: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit user role replacement: %w", err)
	}
	return nil
}

func (r *AccessRepository) ListUserRoles(ctx context.Context, userID, clientID string, includeExpired bool, now time.Time) ([]access.UserRole, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ur.user_id::text,
		       r.id::text, r.client_id, r.code, r.name, r.description, r.created_at, r.updated_at,
		       ur.granted_at, ur.granted_by, ur.expires_at
		FROM access_user_roles ur
		JOIN access_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		  AND ($2 = '' OR r.client_id = $2)
		  AND ($3 OR ur.expires_at IS NULL OR ur.expires_at > $4)
		ORDER BY r.client_id, r.code`,
		userID, clientID, includeExpired, now,
	)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer rows.Close()
	result := make([]access.UserRole, 0)
	for rows.Next() {
		var value access.UserRole
		var expiresAt pgtype.Timestamptz
		if err := rows.Scan(
			&value.UserID,
			&value.Role.ID, &value.Role.ClientID, &value.Role.Code, &value.Role.Name,
			&value.Role.Description, &value.Role.CreatedAt, &value.Role.UpdatedAt,
			&value.GrantedAt, &value.GrantedBy, &expiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		if expiresAt.Valid {
			value.ExpiresAt = &expiresAt.Time
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user roles: %w", err)
	}
	return result, nil
}

func (r *AccessRepository) Effective(ctx context.Context, userID, clientID string, now time.Time) (access.Entitlements, error) {
	result := access.Entitlements{
		UserID:      userID,
		ClientID:    clientID,
		Roles:       make([]string, 0),
		Permissions: make([]string, 0),
	}
	roleRows, err := r.pool.Query(ctx, `
		SELECT r.code
		FROM access_user_roles ur
		JOIN access_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		  AND r.client_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > $3)
		ORDER BY r.code`,
		userID, clientID, now,
	)
	if err != nil {
		return access.Entitlements{}, fmt.Errorf("list effective roles: %w", err)
	}
	for roleRows.Next() {
		var code string
		if err := roleRows.Scan(&code); err != nil {
			roleRows.Close()
			return access.Entitlements{}, err
		}
		result.Roles = append(result.Roles, code)
	}
	if err := roleRows.Err(); err != nil {
		roleRows.Close()
		return access.Entitlements{}, err
	}
	roleRows.Close()

	permissionRows, err := r.pool.Query(ctx, `
		SELECT DISTINCT p.code
		FROM access_user_roles ur
		JOIN access_roles r ON r.id = ur.role_id
		JOIN access_role_permissions rp ON rp.role_id = r.id
		JOIN access_permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1
		  AND r.client_id = $2
		  AND p.client_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > $3)
		ORDER BY p.code`,
		userID, clientID, now,
	)
	if err != nil {
		return access.Entitlements{}, fmt.Errorf("list effective permissions: %w", err)
	}
	defer permissionRows.Close()
	for permissionRows.Next() {
		var code string
		if err := permissionRows.Scan(&code); err != nil {
			return access.Entitlements{}, err
		}
		result.Permissions = append(result.Permissions, code)
	}
	if err := permissionRows.Err(); err != nil {
		return access.Entitlements{}, err
	}
	return result, nil
}

type accessScanner interface {
	Scan(...any) error
}

func scanRole(scanner accessScanner) (access.Role, error) {
	var value access.Role
	if err := scanner.Scan(
		&value.ID, &value.ClientID, &value.Code, &value.Name, &value.Description,
		&value.CreatedAt, &value.UpdatedAt,
	); err != nil {
		return access.Role{}, err
	}
	return value, nil
}

func scanPermission(scanner accessScanner) (access.Permission, error) {
	var value access.Permission
	if err := scanner.Scan(
		&value.ID, &value.ClientID, &value.Code, &value.Name, &value.Description,
		&value.CreatedAt, &value.UpdatedAt,
	); err != nil {
		return access.Permission{}, err
	}
	return value, nil
}

func isForeignKeyViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23503"
}
