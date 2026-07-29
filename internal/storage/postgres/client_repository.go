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
		SELECT id, name, description, application_type, protocols, grant_types,
		       allowed_scopes, enabled, client_secret_hash, cas_version,
		       cas_service_urls, cas_proxy, cas_gateway, cas_renew, cas_single_logout
		FROM oauth_clients
		ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	result := make([]client.Client, 0)
	for rows.Next() {
		item, err := scanClient(rows)
		if err != nil {
			return nil, err
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
	item, err := scanClient(r.pool.QueryRow(ctx, `
		SELECT id, name, description, application_type, protocols, grant_types,
		       allowed_scopes, enabled, client_secret_hash, cas_version,
		       cas_service_urls, cas_proxy, cas_gateway, cas_renew, cas_single_logout
		FROM oauth_clients
		WHERE id = $1`, id))
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

func (r *ClientRepository) Create(ctx context.Context, item client.Client) (client.Client, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return client.Client{}, fmt.Errorf("begin client creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO oauth_clients (
			id, name, description, application_type, protocols, grant_types,
			allowed_scopes, enabled, client_secret_hash, cas_version,
			cas_service_urls, cas_proxy, cas_gateway, cas_renew, cas_single_logout
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		item.ID,
		item.Name,
		item.Description,
		item.ApplicationType,
		stringProtocols(item.Protocols),
		stringGrantTypes(item.GrantTypes),
		item.AllowedScopes,
		item.Enabled,
		nullableBytes(item.SecretHash),
		item.CASVersion,
		item.CASServiceURLs,
		item.CASProxy,
		item.CASGateway,
		item.CASRenew,
		item.CASSingleLogout,
	)
	if isUniqueViolation(err) {
		return client.Client{}, client.ErrConflict
	}
	if err != nil {
		return client.Client{}, fmt.Errorf("insert client: %w", err)
	}
	for _, redirectURI := range item.RedirectURIs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)`, item.ID, redirectURI); err != nil {
			return client.Client{}, fmt.Errorf("insert redirect URI: %w", err)
		}
	}
	for position, method := range item.LoginMethods {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_login_methods (client_id, method, position)
			VALUES ($1, $2, $3)`, item.ID, method, position); err != nil {
			return client.Client{}, fmt.Errorf("insert login method: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return client.Client{}, fmt.Errorf("commit client creation: %w", err)
	}
	return item, nil
}

func scanClient(scanner interface{ Scan(...any) error }) (client.Client, error) {
	var item client.Client
	var protocols []string
	var grants []string
	err := scanner.Scan(
		&item.ID,
		&item.Name,
		&item.Description,
		&item.ApplicationType,
		&protocols,
		&grants,
		&item.AllowedScopes,
		&item.Enabled,
		&item.SecretHash,
		&item.CASVersion,
		&item.CASServiceURLs,
		&item.CASProxy,
		&item.CASGateway,
		&item.CASRenew,
		&item.CASSingleLogout,
	)
	if err != nil {
		return client.Client{}, fmt.Errorf("scan client: %w", err)
	}
	for _, protocol := range protocols {
		item.Protocols = append(item.Protocols, client.Protocol(protocol))
	}
	for _, grant := range grants {
		item.GrantTypes = append(item.GrantTypes, client.GrantType(grant))
	}
	return item, nil
}

func stringProtocols(values []client.Protocol) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func stringGrantTypes(values []client.GrantType) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
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

func nullableBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}
