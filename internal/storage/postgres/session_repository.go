package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"certus/internal/session"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Create(ctx context.Context, value session.Session, hash []byte, ipAddress, userAgent string) (session.Session, error) {
	var ip any
	if parsed := net.ParseIP(strings.TrimSpace(ipAddress)); parsed != nil {
		ip = parsed.String()
	}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, token_hash, authenticated_at, expires_at, last_seen_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $3, $5, $6)
		RETURNING id::text`,
		value.UserID, hash, value.AuthenticatedAt, value.ExpiresAt, ip, userAgent,
	).Scan(&value.ID)
	if err != nil {
		return session.Session{}, fmt.Errorf("insert session: %w", err)
	}
	return value, nil
}

func (r *SessionRepository) Find(ctx context.Context, hash []byte, now time.Time) (session.Session, error) {
	var value session.Session
	err := r.pool.QueryRow(ctx, `
		UPDATE sessions
		SET last_seen_at = $2
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > $2
		RETURNING id::text, user_id::text, authenticated_at, expires_at`,
		hash, now,
	).Scan(&value.ID, &value.UserID, &value.AuthenticatedAt, &value.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return session.Session{}, session.ErrNotFound
	}
	if err != nil {
		return session.Session{}, fmt.Errorf("find session: %w", err)
	}
	return value, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id string, now time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = coalesce(revoked_at, $2)
		WHERE id = $1`,
		id, now,
	)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if command.RowsAffected() == 0 {
		return session.ErrNotFound
	}
	return nil
}
