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
		RETURNING id::text, last_seen_at`,
		value.UserID, hash, value.AuthenticatedAt, value.ExpiresAt, ip, userAgent,
	).Scan(&value.ID, &value.LastSeenAt)
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
		RETURNING id::text, user_id::text, authenticated_at, expires_at, last_seen_at,
		          coalesce(host(ip_address), ''), user_agent, revoked_at`,
		hash, now,
	).Scan(
		&value.ID, &value.UserID, &value.AuthenticatedAt, &value.ExpiresAt,
		&value.LastSeenAt, &value.IPAddress, &value.UserAgent, &value.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return session.Session{}, session.ErrNotFound
	}
	if err != nil {
		return session.Session{}, fmt.Errorf("find session: %w", err)
	}
	return value, nil
}

func (r *SessionRepository) ListByUser(ctx context.Context, userID string, now time.Time) ([]session.Session, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, user_id::text, authenticated_at, expires_at, last_seen_at,
		       coalesce(host(ip_address), ''), user_agent, revoked_at
		FROM sessions
		WHERE user_id = $1
		  AND revoked_at IS NULL
		  AND expires_at > $2
		ORDER BY last_seen_at DESC, id DESC`,
		userID, now,
	)
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}
	defer rows.Close()
	result := make([]session.Session, 0)
	for rows.Next() {
		var value session.Session
		if err := rows.Scan(
			&value.ID, &value.UserID, &value.AuthenticatedAt, &value.ExpiresAt,
			&value.LastSeenAt, &value.IPAddress, &value.UserAgent, &value.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user session: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user sessions: %w", err)
	}
	return result, nil
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

func (r *SessionRepository) RevokeForUser(ctx context.Context, userID, id string, now time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE id = $1 AND user_id = $2`,
		id, userID, now,
	)
	if err != nil {
		return fmt.Errorf("revoke user session: %w", err)
	}
	if command.RowsAffected() == 0 {
		return session.ErrNotFound
	}
	return nil
}

func (r *SessionRepository) RevokeAll(ctx context.Context, userID, exceptID string, now time.Time) (int64, error) {
	command, err := r.pool.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = $3
		WHERE user_id = $1
		  AND ($2 = '' OR id <> nullif($2, '')::uuid)
		  AND revoked_at IS NULL
		  AND expires_at > $3`,
		userID, exceptID, now,
	)
	if err != nil {
		return 0, fmt.Errorf("revoke all user sessions: %w", err)
	}
	return command.RowsAffected(), nil
}
