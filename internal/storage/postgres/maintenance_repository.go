package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type MaintenanceRepository struct {
	pool *pgxpool.Pool
}

func NewMaintenanceRepository(pool *pgxpool.Pool) *MaintenanceRepository {
	return &MaintenanceRepository{pool: pool}
}

func (r *MaintenanceRepository) Cleanup(
	ctx context.Context,
	now time.Time,
	auditBefore time.Time,
	signingKeyBefore time.Time,
) (map[string]int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin maintenance cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	cutoff := now.Add(-time.Hour)
	statements := []struct {
		name string
		sql  string
		args []any
	}{
		{"oauth_authorization_codes", `DELETE FROM oauth_authorization_codes WHERE expires_at < $1 OR consumed_at < $2`, []any{now, cutoff}},
		{"oauth_device_authorizations", `DELETE FROM oauth_device_authorizations WHERE expires_at < $1 OR consumed_at < $2 OR decided_at < $2 AND status = 'denied'`, []any{now, cutoff}},
		{"oauth_access_tokens", `DELETE FROM oauth_access_tokens WHERE expires_at < $1 OR revoked_at < $2`, []any{now, cutoff}},
		{"oauth_refresh_tokens", `DELETE FROM oauth_refresh_tokens WHERE expires_at < $1 OR revoked_at < $2 OR consumed_at < $2`, []any{now, cutoff}},
		{"cas_service_tickets", `DELETE FROM cas_service_tickets WHERE expires_at < $1 OR consumed_at < $2`, []any{now, cutoff}},
		{"cas_proxy_tickets", `DELETE FROM cas_proxy_tickets WHERE expires_at < $1 OR consumed_at < $2`, []any{now, cutoff}},
		{"cas_proxy_granting_tickets", `DELETE FROM cas_proxy_granting_tickets WHERE expires_at < $1`, []any{now}},
		{"password_reset_tokens", `DELETE FROM password_reset_tokens WHERE expires_at < $1 OR consumed_at < $2`, []any{now, cutoff}},
		{"sessions", `DELETE FROM sessions WHERE expires_at < $1 OR revoked_at < $2`, []any{now, cutoff}},
		{"audit_events", `DELETE FROM audit_events WHERE occurred_at < $1`, []any{auditBefore}},
		{"oidc_signing_keys", `DELETE FROM oidc_signing_keys WHERE active = false AND retired_at < $1`, []any{signingKeyBefore}},
	}
	result := make(map[string]int64, len(statements))
	for _, statement := range statements {
		command, err := tx.Exec(ctx, statement.sql, statement.args...)
		if err != nil {
			return nil, fmt.Errorf("clean %s: %w", statement.name, err)
		}
		result[statement.name] = command.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit maintenance cleanup: %w", err)
	}
	return result, nil
}
