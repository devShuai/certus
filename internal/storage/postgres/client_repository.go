package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/client"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ClientRepository struct {
	pool *pgxpool.Pool
}

func NewClientRepository(pool *pgxpool.Pool) *ClientRepository {
	return &ClientRepository{pool: pool}
}

func (r *ClientRepository) ListSystems(ctx context.Context) ([]client.System, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, description, favicon_url, launch_uri, portal_visible
		FROM access_systems
		ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list access systems: %w", err)
	}
	defer rows.Close()
	result := make([]client.System, 0)
	for rows.Next() {
		item, scanErr := scanSystem(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access systems: %w", err)
	}
	return result, nil
}

func (r *ClientRepository) FindSystem(ctx context.Context, id string) (client.System, error) {
	item, err := scanSystem(r.pool.QueryRow(ctx, `
		SELECT id, name, description, favicon_url, launch_uri, portal_visible
		FROM access_systems
		WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return client.System{}, client.ErrSystemNotFound
	}
	if err != nil {
		return client.System{}, fmt.Errorf("find access system: %w", err)
	}
	return item, nil
}

func (r *ClientRepository) CreateSystem(ctx context.Context, item client.System) (client.System, error) {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO access_systems (id, name, description, favicon_url, launch_uri, portal_visible)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		item.ID, item.Name, item.Description, item.FaviconURL, item.LaunchURI, item.PortalVisible,
	)
	if isUniqueViolation(err) {
		return client.System{}, client.ErrSystemConflict
	}
	if err != nil {
		return client.System{}, fmt.Errorf("create access system: %w", err)
	}
	return item, nil
}

func (r *ClientRepository) ReplaceSystem(ctx context.Context, item client.System) (client.System, error) {
	command, err := r.pool.Exec(ctx, `
		UPDATE access_systems
		SET name = $2,
		    description = $3,
		    favicon_url = $4,
		    launch_uri = $5,
		    portal_visible = $6,
		    updated_at = now()
		WHERE id = $1`,
		item.ID, item.Name, item.Description, item.FaviconURL, item.LaunchURI, item.PortalVisible,
	)
	if err != nil {
		return client.System{}, fmt.Errorf("replace access system: %w", err)
	}
	if command.RowsAffected() == 0 {
		return client.System{}, client.ErrSystemNotFound
	}
	return item, nil
}

func (r *ClientRepository) DeleteSystem(ctx context.Context, id string) error {
	command, err := r.pool.Exec(ctx, `DELETE FROM access_systems WHERE id = $1`, id)
	if isForeignKeyViolation(err) {
		return client.ErrSystemInUse
	}
	if err != nil {
		return fmt.Errorf("delete access system: %w", err)
	}
	if command.RowsAffected() == 0 {
		return client.ErrSystemNotFound
	}
	return nil
}

func scanSystem(scanner interface{ Scan(...any) error }) (client.System, error) {
	var item client.System
	if err := scanner.Scan(
		&item.ID,
		&item.Name,
		&item.Description,
		&item.FaviconURL,
		&item.LaunchURI,
		&item.PortalVisible,
	); err != nil {
		return client.System{}, err
	}
	return item, nil
}

func (r *ClientRepository) List(ctx context.Context) ([]client.Client, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, system_id, name, description, favicon_url, launch_uri, application_type, protocols, grant_types,
		       allowed_scopes, enabled, client_secret_hash, cas_version,
		       cas_service_urls, cas_proxy, cas_gateway, cas_renew, cas_single_logout,
		       backchannel_logout_uri, backchannel_logout_session_required,
		       token_endpoint_auth_method,
		       access_token_lifetime_seconds, refresh_token_lifetime_seconds,
		       archived_at
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
		SELECT id, system_id, name, description, favicon_url, launch_uri, application_type, protocols, grant_types,
		       allowed_scopes, enabled, client_secret_hash, cas_version,
		       cas_service_urls, cas_proxy, cas_gateway, cas_renew, cas_single_logout,
		       backchannel_logout_uri, backchannel_logout_session_required,
		       token_endpoint_auth_method,
		       access_token_lifetime_seconds, refresh_token_lifetime_seconds,
		       archived_at
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

func (r *ClientRepository) Replace(ctx context.Context, item client.Client) (client.Client, error) {
	if item.SystemID == "" {
		item.SystemID = item.ID
	}
	item.AccessTokenLifetimeSeconds = int64(item.AccessTokenLifetime() / time.Second)
	item.RefreshTokenLifetimeSeconds = int64(item.RefreshTokenLifetime() / time.Second)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return client.Client{}, fmt.Errorf("begin client replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	command, err := tx.Exec(ctx, `
		UPDATE oauth_clients
		SET name = $2,
		    description = $3,
		    protocols = $4,
		    grant_types = $5,
		    allowed_scopes = $6,
		    enabled = $7,
		    cas_version = $8,
		    cas_service_urls = $9,
		    cas_proxy = $10,
		    cas_gateway = $11,
		    cas_renew = $12,
		    cas_single_logout = $13,
		    backchannel_logout_uri = $14,
		    backchannel_logout_session_required = $15,
		    token_endpoint_auth_method = $16,
		    favicon_url = $17,
		    launch_uri = $18,
		    access_token_lifetime_seconds = $19,
		    refresh_token_lifetime_seconds = $20,
		    system_id = $21,
		    updated_at = now()
		WHERE id = $1 AND archived_at IS NULL`,
		item.ID,
		item.Name,
		item.Description,
		stringProtocols(item.Protocols),
		stringGrantTypes(item.GrantTypes),
		item.AllowedScopes,
		item.Enabled,
		item.CASVersion,
		item.CASServiceURLs,
		item.CASProxy,
		item.CASGateway,
		item.CASRenew,
		item.CASSingleLogout,
		item.BackchannelLogoutURI,
		item.BackchannelLogoutSessionRequired,
		item.EffectiveTokenEndpointAuthMethod(),
		item.FaviconURL,
		item.LaunchURI,
		item.AccessTokenLifetimeSeconds,
		item.RefreshTokenLifetimeSeconds,
		item.SystemID,
	)
	if err != nil {
		return client.Client{}, fmt.Errorf("replace client: %w", err)
	}
	if command.RowsAffected() == 0 {
		return client.Client{}, client.ErrArchived
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_redirect_uris WHERE client_id = $1`, item.ID); err != nil {
		return client.Client{}, fmt.Errorf("replace client redirect URIs: %w", err)
	}
	for _, redirectURI := range item.RedirectURIs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)`, item.ID, redirectURI); err != nil {
			return client.Client{}, fmt.Errorf("insert replacement redirect URI: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_post_logout_redirect_uris WHERE client_id = $1`, item.ID); err != nil {
		return client.Client{}, fmt.Errorf("replace client post-logout redirect URIs: %w", err)
	}
	for _, redirectURI := range item.PostLogoutRedirectURIs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_post_logout_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)`, item.ID, redirectURI); err != nil {
			return client.Client{}, fmt.Errorf("insert replacement post-logout redirect URI: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_login_methods WHERE client_id = $1`, item.ID); err != nil {
		return client.Client{}, fmt.Errorf("replace client login methods: %w", err)
	}
	for position, method := range item.LoginMethods {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_login_methods (client_id, method, position)
			VALUES ($1, $2, $3)`, item.ID, method, position); err != nil {
			return client.Client{}, fmt.Errorf("insert replacement login method: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_identity_sources WHERE client_id = $1`, item.ID); err != nil {
		return client.Client{}, fmt.Errorf("replace client identity sources: %w", err)
	}
	for position, sourceID := range item.IdentitySourceIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_identity_sources (client_id, source_id, position)
			VALUES ($1, $2, $3)`, item.ID, sourceID, position); err != nil {
			return client.Client{}, fmt.Errorf("insert replacement identity source: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_introspection_permissions WHERE token_client_id = $1`, item.ID); err != nil {
		return client.Client{}, fmt.Errorf("replace client introspection permissions: %w", err)
	}
	for position, introspectorID := range item.IntrospectableBy {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_introspection_permissions (
				token_client_id, introspector_client_id, position
			)
			VALUES ($1, $2, $3)`, item.ID, introspectorID, position); err != nil {
			return client.Client{}, fmt.Errorf("insert replacement client introspection permission: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return client.Client{}, fmt.Errorf("commit client replacement: %w", err)
	}
	return item, nil
}

func (r *ClientRepository) RotateSecret(ctx context.Context, id string, hash []byte) (client.Client, error) {
	command, err := r.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET client_secret_hash = $2, updated_at = now()
		WHERE id = $1
		  AND application_type = 'confidential'
		  AND archived_at IS NULL`,
		id, hash,
	)
	if err != nil {
		return client.Client{}, fmt.Errorf("rotate client secret: %w", err)
	}
	if command.RowsAffected() == 0 {
		return client.Client{}, client.ErrNotFound
	}
	return r.Find(ctx, id)
}

func (r *ClientRepository) Archive(ctx context.Context, id string, now time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET enabled = false,
		    archived_at = coalesce(archived_at, $2),
		    updated_at = $2
		WHERE id = $1`,
		id, now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("archive client: %w", err)
	}
	if command.RowsAffected() == 0 {
		return client.ErrNotFound
	}
	return nil
}

func (r *ClientRepository) DeleteArchived(ctx context.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin archived client deletion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var archived bool
	err = tx.QueryRow(ctx, `
		SELECT archived_at IS NOT NULL
		FROM oauth_clients
		WHERE id = $1
		FOR UPDATE`, id).Scan(&archived)
	if errors.Is(err, pgx.ErrNoRows) {
		return client.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find client for deletion: %w", err)
	}
	if !archived {
		return client.ErrNotArchived
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM oauth_client_introspection_permissions
		WHERE introspector_client_id = $1`, id); err != nil {
		return fmt.Errorf("delete client introspection references: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete archived client: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit archived client deletion: %w", err)
	}
	return nil
}

func (r *ClientRepository) Create(ctx context.Context, item client.Client) (client.Client, error) {
	if item.SystemID == "" {
		item.SystemID = item.ID
	}
	item.AccessTokenLifetimeSeconds = int64(item.AccessTokenLifetime() / time.Second)
	item.RefreshTokenLifetimeSeconds = int64(item.RefreshTokenLifetime() / time.Second)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return client.Client{}, fmt.Errorf("begin client creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO access_systems (id, name, description, favicon_url, launch_uri, portal_visible)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO NOTHING`,
		item.SystemID,
		item.Name,
		item.Description,
		item.FaviconURL,
		item.LaunchURI,
		item.LaunchURI != "",
	)
	if err != nil {
		return client.Client{}, fmt.Errorf("ensure client access system: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO oauth_clients (
			id, system_id, name, description, application_type, protocols, grant_types,
			allowed_scopes, enabled, client_secret_hash, cas_version,
			cas_service_urls, cas_proxy, cas_gateway, cas_renew, cas_single_logout,
			backchannel_logout_uri, backchannel_logout_session_required,
			token_endpoint_auth_method, favicon_url, launch_uri,
			access_token_lifetime_seconds, refresh_token_lifetime_seconds
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
		item.ID,
		item.SystemID,
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
		item.BackchannelLogoutURI,
		item.BackchannelLogoutSessionRequired,
		item.EffectiveTokenEndpointAuthMethod(),
		item.FaviconURL,
		item.LaunchURI,
		item.AccessTokenLifetimeSeconds,
		item.RefreshTokenLifetimeSeconds,
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
	for _, redirectURI := range item.PostLogoutRedirectURIs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_post_logout_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)`, item.ID, redirectURI); err != nil {
			return client.Client{}, fmt.Errorf("insert post-logout redirect URI: %w", err)
		}
	}
	for position, method := range item.LoginMethods {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_login_methods (client_id, method, position)
			VALUES ($1, $2, $3)`, item.ID, method, position); err != nil {
			return client.Client{}, fmt.Errorf("insert login method: %w", err)
		}
	}
	for position, sourceID := range item.IdentitySourceIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_identity_sources (client_id, source_id, position)
			VALUES ($1, $2, $3)`, item.ID, sourceID, position); err != nil {
			return client.Client{}, fmt.Errorf("insert client identity source: %w", err)
		}
	}
	for position, introspectorID := range item.IntrospectableBy {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_introspection_permissions (
				token_client_id, introspector_client_id, position
			)
			VALUES ($1, $2, $3)`, item.ID, introspectorID, position); err != nil {
			return client.Client{}, fmt.Errorf("insert client introspection permission: %w", err)
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
	var archivedAt pgtype.Timestamptz
	err := scanner.Scan(
		&item.ID,
		&item.SystemID,
		&item.Name,
		&item.Description,
		&item.FaviconURL,
		&item.LaunchURI,
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
		&item.BackchannelLogoutURI,
		&item.BackchannelLogoutSessionRequired,
		&item.TokenEndpointAuthMethod,
		&item.AccessTokenLifetimeSeconds,
		&item.RefreshTokenLifetimeSeconds,
		&archivedAt,
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
	if archivedAt.Valid {
		item.ArchivedAt = &archivedAt.Time
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

	postLogoutRows, err := r.pool.Query(ctx, `
		SELECT redirect_uri
		FROM oauth_client_post_logout_redirect_uris
		WHERE client_id = $1
		ORDER BY redirect_uri`, item.ID)
	if err != nil {
		return fmt.Errorf("list post-logout redirect URIs: %w", err)
	}
	for postLogoutRows.Next() {
		var redirectURI string
		if err := postLogoutRows.Scan(&redirectURI); err != nil {
			postLogoutRows.Close()
			return fmt.Errorf("scan post-logout redirect URI: %w", err)
		}
		item.PostLogoutRedirectURIs = append(item.PostLogoutRedirectURIs, redirectURI)
	}
	err = postLogoutRows.Err()
	postLogoutRows.Close()
	if err != nil {
		return fmt.Errorf("iterate post-logout redirect URIs: %w", err)
	}

	methodRows, err := r.pool.Query(ctx, `
		SELECT method
		FROM oauth_client_login_methods
		WHERE client_id = $1
		ORDER BY position, method`, item.ID)
	if err != nil {
		return fmt.Errorf("list login methods: %w", err)
	}
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
	methodRows.Close()

	sourceRows, err := r.pool.Query(ctx, `
		SELECT source_id
		FROM oauth_client_identity_sources
		WHERE client_id = $1
		ORDER BY position, source_id`, item.ID)
	if err != nil {
		return fmt.Errorf("list client identity sources: %w", err)
	}
	for sourceRows.Next() {
		var sourceID string
		if err := sourceRows.Scan(&sourceID); err != nil {
			sourceRows.Close()
			return fmt.Errorf("scan client identity source: %w", err)
		}
		item.IdentitySourceIDs = append(item.IdentitySourceIDs, sourceID)
	}
	err = sourceRows.Err()
	sourceRows.Close()
	if err != nil {
		return fmt.Errorf("iterate client identity sources: %w", err)
	}

	introspectionRows, err := r.pool.Query(ctx, `
		SELECT introspector_client_id
		FROM oauth_client_introspection_permissions
		WHERE token_client_id = $1
		ORDER BY position, introspector_client_id`, item.ID)
	if err != nil {
		return fmt.Errorf("list client introspection permissions: %w", err)
	}
	for introspectionRows.Next() {
		var introspectorID string
		if err := introspectionRows.Scan(&introspectorID); err != nil {
			introspectionRows.Close()
			return fmt.Errorf("scan client introspection permission: %w", err)
		}
		item.IntrospectableBy = append(item.IntrospectableBy, introspectorID)
	}
	err = introspectionRows.Err()
	introspectionRows.Close()
	if err != nil {
		return fmt.Errorf("iterate client introspection permissions: %w", err)
	}
	system, err := r.FindSystem(ctx, item.SystemID)
	if err != nil {
		return fmt.Errorf("load client access system: %w", err)
	}
	item.System = &system
	return nil
}

func nullableBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}
