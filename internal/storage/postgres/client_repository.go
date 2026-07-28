package postgres

import (
	"context"
	"errors"
	"fmt"

	"certus/internal/client"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ClientRepository struct {
	pool *pgxpool.Pool
}

func NewClientRepository(pool *pgxpool.Pool) *ClientRepository {
	return &ClientRepository{pool: pool}
}

func (r *ClientRepository) List(ctx context.Context) ([]client.Client, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, description, enabled
		FROM oauth_clients
		ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	result := make([]client.Client, 0)
	for rows.Next() {
		var item client.Client
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Enabled); err != nil {
			return nil, fmt.Errorf("scan client: %w", err)
		}
		if err := r.loadRelations(ctx, &item); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate clients: %w", err)
	}
	return result, nil
}

func (r *ClientRepository) Find(ctx context.Context, id string) (client.Client, error) {
	var item client.Client
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, description, enabled
		FROM oauth_clients
		WHERE id = $1`, id,
	).Scan(&item.ID, &item.Name, &item.Description, &item.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return client.Client{}, client.ErrNotFound
	}
	if err != nil {
		return client.Client{}, fmt.Errorf("find client: %w", err)
	}
	if err := r.loadRelations(ctx, &item); err != nil {
		return client.Client{}, err
	}
	return item, nil
}

func (r *ClientRepository) loadRelations(ctx context.Context, item *client.Client) error {
	redirectRows, err := r.pool.Query(ctx, `
		SELECT redirect_uri
		FROM oauth_client_redirect_uris
		WHERE client_id = $1
		ORDER BY redirect_uri`, item.ID)
	if err != nil {
		return fmt.Errorf("list redirect URIs: %w", err)
	}
	for redirectRows.Next() {
		var redirectURI string
		if err := redirectRows.Scan(&redirectURI); err != nil {
			redirectRows.Close()
			return fmt.Errorf("scan redirect URI: %w", err)
		}
		item.RedirectURIs = append(item.RedirectURIs, redirectURI)
	}
	err = redirectRows.Err()
	redirectRows.Close()
	if err != nil {
		return fmt.Errorf("iterate redirect URIs: %w", err)
	}

	methodRows, err := r.pool.Query(ctx, `
		SELECT method
		FROM oauth_client_login_methods
		WHERE client_id = $1
		ORDER BY position, method`, item.ID)
	if err != nil {
		return fmt.Errorf("list login methods: %w", err)
	}
	defer methodRows.Close()
	for methodRows.Next() {
		var method string
		if err := methodRows.Scan(&method); err != nil {
			return fmt.Errorf("scan login method: %w", err)
		}
		item.LoginMethods = append(item.LoginMethods, client.LoginMethod(method))
	}
	if err := methodRows.Err(); err != nil {
		return fmt.Errorf("iterate login methods: %w", err)
	}
	return nil
}
