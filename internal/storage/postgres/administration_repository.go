package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"certus/internal/administration"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AdministrationRepository struct {
	pool *pgxpool.Pool
}

func NewAdministrationRepository(pool *pgxpool.Pool) *AdministrationRepository {
	return &AdministrationRepository{pool: pool}
}

func (r *AdministrationRepository) ListUserRoles(
	ctx context.Context,
	userID string,
) ([]administration.Grant, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT user_id::text, role_code, granted_at, granted_by
		FROM admin_role_grants
		WHERE user_id = $1
		ORDER BY role_code`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list administrator roles: %w", err)
	}
	defer rows.Close()
	result := make([]administration.Grant, 0)
	for rows.Next() {
		var value administration.Grant
		if err := rows.Scan(&value.UserID, &value.Role, &value.GrantedAt, &value.GrantedBy); err != nil {
			return nil, fmt.Errorf("scan administrator role: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate administrator roles: %w", err)
	}
	return result, nil
}

func (r *AdministrationRepository) ListRoleUsers(
	ctx context.Context,
	role administration.Role,
) ([]string, error) {
	if !administration.ValidRole(role) {
		return nil, administration.ErrInvalid
	}
	rows, err := r.pool.Query(ctx, `
		SELECT user_id::text
		FROM admin_role_grants
		WHERE role_code = $1
		ORDER BY user_id`,
		role,
	)
	if err != nil {
		return nil, fmt.Errorf("list users for administrator role: %w", err)
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("scan user for administrator role: %w", err)
		}
		result = append(result, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users for administrator role: %w", err)
	}
	return result, nil
}

func (r *AdministrationRepository) ReplaceUserRoles(
	ctx context.Context,
	userID string,
	roles []administration.Role,
	grantedBy string,
	now time.Time,
) error {
	if err := administration.ValidateRoles(roles); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(grantedBy) == "" {
		return administration.ErrInvalid
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin administrator role replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('certus:administrator-roles'))`); err != nil {
		return fmt.Errorf("lock administrator role replacement: %w", err)
	}
	var userExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&userExists); err != nil {
		return fmt.Errorf("find administrator user: %w", err)
	}
	if !userExists {
		return administration.ErrNotFound
	}
	var currentlySuper bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM admin_role_grants
			WHERE user_id = $1 AND role_code = $2
		)`,
		userID, administration.RoleSuperAdmin,
	).Scan(&currentlySuper); err != nil {
		return fmt.Errorf("find current super administrator role: %w", err)
	}
	if currentlySuper && !administration.HasRole(roles, administration.RoleSuperAdmin) {
		var otherSuperAdmins int64
		if err := tx.QueryRow(ctx, `
			SELECT count(DISTINCT user_id)
			FROM admin_role_grants
			WHERE role_code = $1 AND user_id <> $2`,
			administration.RoleSuperAdmin, userID,
		).Scan(&otherSuperAdmins); err != nil {
			return fmt.Errorf("count replacement super administrators: %w", err)
		}
		if otherSuperAdmins == 0 {
			return administration.ErrLastSuperAdmin
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_role_grants WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete administrator roles: %w", err)
	}
	for _, role := range roles {
		if _, err := tx.Exec(ctx, `
			INSERT INTO admin_role_grants (user_id, role_code, granted_at, granted_by)
			VALUES ($1, $2, $3, $4)`,
			userID, role, now.UTC(), grantedBy,
		); err != nil {
			if isForeignKeyViolation(err) {
				return administration.ErrNotFound
			}
			return fmt.Errorf("insert administrator role: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit administrator role replacement: %w", err)
	}
	return nil
}

func (r *AdministrationRepository) Effective(
	ctx context.Context,
	userID string,
) (administration.Access, error) {
	grants, err := r.ListUserRoles(ctx, userID)
	if err != nil {
		return administration.Access{}, err
	}
	roles := make([]administration.Role, 0, len(grants))
	for _, grant := range grants {
		roles = append(roles, grant.Role)
	}
	return administration.AccessFor(userID, roles), nil
}

var _ administration.Repository = (*AdministrationRepository)(nil)
