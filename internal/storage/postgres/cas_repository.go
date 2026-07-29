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

func (r *CASRepository) SaveProxyGrantingTicket(ctx context.Context, value cas.ProxyGrantingTicket) error {
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO cas_proxy_granting_tickets (
			pgt_hash, client_id, user_id, session_id, callback_url, proxy_chain,
			primary_credentials, issued_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		value.Hash, value.ClientID, value.UserID, value.SessionID, value.CallbackURL,
		value.Proxies, value.PrimaryCredentials, value.IssuedAt, value.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert proxy granting ticket: %w", err)
	}
	return nil
}

func (r *CASRepository) FindProxyGrantingTicket(ctx context.Context, hash []byte, now time.Time) (cas.ProxyGrantingTicket, error) {
	var value cas.ProxyGrantingTicket
	err := r.pool.QueryRow(ctx, `
		SELECT p.pgt_hash, p.client_id, p.user_id::text, p.session_id::text, p.callback_url,
		       p.proxy_chain, p.primary_credentials, p.issued_at, p.expires_at
		FROM cas_proxy_granting_tickets p
		JOIN sessions s ON s.id = p.session_id
		WHERE p.pgt_hash = $1
		  AND p.expires_at > $2
		  AND s.revoked_at IS NULL
		  AND s.expires_at > $2`,
		hash, now,
	).Scan(
		&value.Hash, &value.ClientID, &value.UserID, &value.SessionID, &value.CallbackURL,
		&value.Proxies, &value.PrimaryCredentials, &value.IssuedAt, &value.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return cas.ProxyGrantingTicket{}, cas.ErrTicketNotFound
	}
	if err != nil {
		return cas.ProxyGrantingTicket{}, fmt.Errorf("find proxy granting ticket: %w", err)
	}
	return value, nil
}

func (r *CASRepository) SaveProxyTicket(ctx context.Context, value cas.ProxyTicket, pgtHash []byte) error {
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO cas_proxy_tickets (
			ticket_hash, pgt_hash, client_id, target_service, user_id, session_id,
			proxy_chain, primary_credentials, issued_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		value.Hash, pgtHash, value.ClientID, value.TargetService, value.UserID, value.SessionID,
		value.Proxies, value.PrimaryCredentials, value.IssuedAt, value.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert proxy ticket: %w", err)
	}
	return nil
}

func (r *CASRepository) ConsumeProxyTicket(ctx context.Context, hash []byte, targetService string, requirePrimary bool, now time.Time) (cas.ProxyTicket, error) {
	var value cas.ProxyTicket
	err := r.pool.QueryRow(ctx, `
		UPDATE cas_proxy_tickets
		SET consumed_at = $3
		WHERE ticket_hash = $1
		  AND target_service = $2
		  AND (NOT $4 OR primary_credentials = true)
		  AND consumed_at IS NULL
		  AND expires_at > $3
		  AND EXISTS (
		      SELECT 1
		      FROM sessions s
		      WHERE s.id = cas_proxy_tickets.session_id
		        AND s.revoked_at IS NULL
		        AND s.expires_at > $3
		  )
		RETURNING ticket_hash, client_id, target_service, user_id::text, session_id::text,
		          proxy_chain, primary_credentials, issued_at, expires_at`,
		hash, targetService, now, requirePrimary,
	).Scan(
		&value.Hash, &value.ClientID, &value.TargetService, &value.UserID, &value.SessionID,
		&value.Proxies, &value.PrimaryCredentials, &value.IssuedAt, &value.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return cas.ProxyTicket{}, cas.ErrTicketNotFound
	}
	if err != nil {
		return cas.ProxyTicket{}, fmt.Errorf("consume proxy ticket: %w", err)
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
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete CAS session artifacts: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM cas_service_sessions WHERE session_id = $1`, sessionID); err != nil {
		return fmt.Errorf("delete CAS service sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cas_proxy_granting_tickets WHERE session_id = $1`, sessionID); err != nil {
		return fmt.Errorf("delete CAS proxy granting tickets: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete CAS session artifacts: %w", err)
	}
	return nil
}
