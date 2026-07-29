package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"certus/internal/audit"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditRepository struct {
	pool *pgxpool.Pool
}

func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{pool: pool}
}

func (r *AuditRepository) Append(ctx context.Context, event audit.Event) (audit.Event, error) {
	details, err := json.Marshal(event.Details)
	if err != nil {
		return audit.Event{}, fmt.Errorf("encode audit details: %w", err)
	}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO audit_events (
			occurred_at, actor_user_id, event_type, client_id, ip_address, request_id, outcome, details
		)
		VALUES ($1, $2, $3, $4, nullif($5, '')::inet, $6, $7, $8)
		RETURNING id::text`,
		event.OccurredAt, event.ActorUserID, event.EventType, event.ClientID,
		event.IPAddress, event.RequestID, event.Outcome, details,
	).Scan(&event.ID)
	if err != nil {
		return audit.Event{}, fmt.Errorf("append audit event: %w", err)
	}
	return event, nil
}

func (r *AuditRepository) List(ctx context.Context, filter audit.Filter) (audit.Page, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit_events
		WHERE ($1 = '' OR actor_user_id = nullif($1, '')::uuid)
		  AND ($2 = '' OR event_type = $2)
		  AND ($3 = '' OR client_id = $3)
		  AND ($4 = '' OR outcome = $4)
		  AND ($5::timestamptz IS NULL OR occurred_at >= $5)
		  AND ($6::timestamptz IS NULL OR occurred_at < $6)`,
		filter.ActorUserID, filter.EventType, filter.ClientID, filter.Outcome, filter.From, filter.To,
	).Scan(&total); err != nil {
		return audit.Page{}, fmt.Errorf("count audit events: %w", err)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, occurred_at, actor_user_id::text, event_type, client_id,
		       coalesce(host(ip_address), ''), request_id, outcome, details
		FROM audit_events
		WHERE ($1 = '' OR actor_user_id = nullif($1, '')::uuid)
		  AND ($2 = '' OR event_type = $2)
		  AND ($3 = '' OR client_id = $3)
		  AND ($4 = '' OR outcome = $4)
		  AND ($5::timestamptz IS NULL OR occurred_at >= $5)
		  AND ($6::timestamptz IS NULL OR occurred_at < $6)
		ORDER BY occurred_at DESC, id DESC
		LIMIT $7 OFFSET $8`,
		filter.ActorUserID, filter.EventType, filter.ClientID, filter.Outcome, filter.From, filter.To,
		filter.Limit, filter.Offset,
	)
	if err != nil {
		return audit.Page{}, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	items := make([]audit.Event, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return audit.Page{}, err
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return audit.Page{}, fmt.Errorf("iterate audit events: %w", err)
	}
	return audit.Page{Items: items, Total: total, Limit: filter.Limit, Offset: filter.Offset}, nil
}

func scanAuditEvent(row pgx.Row) (audit.Event, error) {
	var event audit.Event
	var actorUserID pgtype.Text
	var clientID pgtype.Text
	var details []byte
	if err := row.Scan(
		&event.ID, &event.OccurredAt, &actorUserID, &event.EventType, &clientID,
		&event.IPAddress, &event.RequestID, &event.Outcome, &details,
	); err != nil {
		return audit.Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	if actorUserID.Valid {
		event.ActorUserID = &actorUserID.String
	}
	if clientID.Valid {
		event.ClientID = &clientID.String
	}
	if err := json.Unmarshal(details, &event.Details); err != nil {
		return audit.Event{}, fmt.Errorf("decode audit details: %w", err)
	}
	return event, nil
}
