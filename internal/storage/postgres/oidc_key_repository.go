package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/oidc"

	"github.com/jackc/pgx/v5"
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
