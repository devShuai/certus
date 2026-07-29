package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/oidc"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OIDCKeyRepository struct {
	pool *pgxpool.Pool
}

func NewOIDCKeyRepository(pool *pgxpool.Pool) *OIDCKeyRepository {
	return &OIDCKeyRepository{pool: pool}
}

func (r *OIDCKeyRepository) LoadActiveSigningKey(ctx context.Context) ([]byte, error) {
	var value []byte
	err := r.pool.QueryRow(ctx, `
		SELECT private_key_pem
		FROM oidc_signing_keys
		WHERE active = true
		ORDER BY created_at DESC
		LIMIT 1`,
	).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oidc.ErrSigningKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load OIDC signing key: %w", err)
	}
	return value, nil
}

func (r *OIDCKeyRepository) SaveActiveSigningKey(ctx context.Context, kid string, value []byte, createdAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oidc_signing_keys (kid, private_key_pem, algorithm, active, created_at)
		VALUES ($1, $2, 'RS256', true, $3)`,
		kid, value, createdAt,
	)
	if err != nil {
		return fmt.Errorf("save OIDC signing key: %w", err)
	}
	return nil
}

func (r *OIDCKeyRepository) RotateSigningKey(ctx context.Context, kid string, value []byte, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OIDC signing key rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(741924574)`); err != nil {
		return fmt.Errorf("lock OIDC signing key rotation: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oidc_signing_keys
		SET active = false, retired_at = coalesce(retired_at, $1)
		WHERE active = true`,
		now,
	); err != nil {
		return fmt.Errorf("retire OIDC signing key: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_signing_keys (kid, private_key_pem, algorithm, active, created_at)
		VALUES ($1, $2, 'RS256', true, $3)`,
		kid, value, now,
	); err != nil {
		return fmt.Errorf("insert rotated OIDC signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit OIDC signing key rotation: %w", err)
	}
	return nil
}

func (r *OIDCKeyRepository) ListSigningKeys(ctx context.Context) ([]oidc.SigningKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT kid, private_key_pem, active, created_at, retired_at
		FROM oidc_signing_keys
		ORDER BY active DESC, created_at DESC, kid`)
	if err != nil {
		return nil, fmt.Errorf("list OIDC signing keys: %w", err)
	}
	defer rows.Close()
	result := make([]oidc.SigningKey, 0)
	for rows.Next() {
		var value oidc.SigningKey
		var retiredAt pgtype.Timestamptz
		if err := rows.Scan(&value.KID, &value.PEM, &value.Active, &value.CreatedAt, &retiredAt); err != nil {
			return nil, fmt.Errorf("scan OIDC signing key: %w", err)
		}
		if retiredAt.Valid {
			retired := retiredAt.Time
			value.RetiredAt = &retired
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate OIDC signing keys: %w", err)
	}
	return result, nil
}

func (r *OIDCKeyRepository) DeleteRetiredSigningKeys(ctx context.Context, before time.Time) (int64, error) {
	command, err := r.pool.Exec(ctx, `
		DELETE FROM oidc_signing_keys
		WHERE active = false AND retired_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete retired OIDC signing keys: %w", err)
	}
	return command.RowsAffected(), nil
}
