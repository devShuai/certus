package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/cas"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CASRepository struct {
	pool *pgxpool.Pool
}

func NewCASRepository(pool *pgxpool.Pool) *CASRepository {
	return &CASRepository{pool: pool}
}

func (r *CASRepository) SaveServiceTicket(ctx context.Context, value cas.ServiceTicket) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin service ticket: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO cas_service_tickets (
			ticket_hash, client_id, service_url, user_id, session_id, primary_credentials, issued_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		value.Hash, value.ClientID, value.Service, value.UserID, value.SessionID,
		value.PrimaryCredentials, value.IssuedAt, value.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert service ticket: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO cas_service_sessions (session_id, client_id, service_url, ticket, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (session_id, service_url) DO UPDATE
		SET ticket = EXCLUDED.ticket, client_id = EXCLUDED.client_id`,
		value.SessionID, value.ClientID, value.Service, value.Ticket, value.IssuedAt,
	)
	if err != nil {
		return fmt.Errorf("insert CAS service session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit service ticket: %w", err)
	}
	return nil
}

func (r *CASRepository) ConsumeServiceTicket(ctx context.Context, hash []byte, service string, requirePrimary bool, now time.Time) (cas.ServiceTicket, error) {
	var value cas.ServiceTicket
	err := r.pool.QueryRow(ctx, `
		UPDATE cas_service_tickets
		SET consumed_at = $3
		WHERE ticket_hash = $1
		  AND service_url = $2
		  AND (NOT $4 OR primary_credentials = true)
		  AND consumed_at IS NULL
		  AND expires_at > $3
		RETURNING ticket_hash, client_id, service_url, user_id::text, session_id::text, primary_credentials, issued_at, expires_at`,
		hash, service, now, requirePrimary,
	).Scan(
		&value.Hash, &value.ClientID, &value.Service, &value.UserID, &value.SessionID,
		&value.PrimaryCredentials, &value.IssuedAt, &value.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return cas.ServiceTicket{}, cas.ErrTicketNotFound
	}
	if err != nil {
		return cas.ServiceTicket{}, fmt.Errorf("consume service ticket: %w", err)
	}
	return value, nil
}

func (r *CASRepository) ListServiceSessions(ctx context.Context, sessionID string) ([]cas.ServiceSession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT session_id::text, client_id, service_url, ticket
		FROM cas_service_sessions
		WHERE session_id = $1`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("list CAS service sessions: %w", err)
	}
	defer rows.Close()
	result := make([]cas.ServiceSession, 0)
	for rows.Next() {
		var value cas.ServiceSession
		if err := rows.Scan(&value.SessionID, &value.ClientID, &value.Service, &value.Ticket); err != nil {
			return nil, fmt.Errorf("scan CAS service session: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate CAS service sessions: %w", err)
	}
	return result, nil
}

func (r *CASRepository) DeleteServiceSessions(ctx context.Context, sessionID string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM cas_service_sessions WHERE session_id = $1`, sessionID); err != nil {
		return fmt.Errorf("delete CAS service sessions: %w", err)
	}
	return nil
}
