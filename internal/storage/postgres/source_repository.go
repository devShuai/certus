package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/federation"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SourceRepository struct {
	pool *pgxpool.Pool
}

var _ federation.SourceRepository = (*SourceRepository)(nil)
var _ federation.SourceSecretRepository = (*SourceRepository)(nil)

func NewSourceRepository(pool *pgxpool.Pool) *SourceRepository {
	return &SourceRepository{pool: pool}
}

func (r *SourceRepository) List(ctx context.Context) ([]federation.Source, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, source_type, enabled,
		       ldap_url, ldap_start_tls, ldap_base_dn, ldap_bind_dn,
		       ldap_user_filter, ldap_username_attribute,
		       ldap_display_name_attribute, ldap_email_attribute,
		       oidc_issuer, oidc_client_id, oidc_scopes,
		       secret_ciphertext, secret_key_id,
		       created_at, updated_at, archived_at
		FROM identity_sources
		ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list identity sources: %w", err)
	}
	defer rows.Close()
	result := make([]federation.Source, 0)
	for rows.Next() {
		source, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity sources: %w", err)
	}
	return result, nil
}

func (r *SourceRepository) Find(ctx context.Context, id string) (federation.Source, error) {
	source, err := scanSource(r.pool.QueryRow(ctx, `
		SELECT id, name, source_type, enabled,
		       ldap_url, ldap_start_tls, ldap_base_dn, ldap_bind_dn,
		       ldap_user_filter, ldap_username_attribute,
		       ldap_display_name_attribute, ldap_email_attribute,
		       oidc_issuer, oidc_client_id, oidc_scopes,
		       secret_ciphertext, secret_key_id,
		       created_at, updated_at, archived_at
		FROM identity_sources
		WHERE id = $1`,
		id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return federation.Source{}, federation.ErrSourceNotFound
	}
	if err != nil {
		return federation.Source{}, fmt.Errorf("find identity source: %w", err)
	}
	return source, nil
}

func (r *SourceRepository) Create(
	ctx context.Context,
	source federation.Source,
) (federation.Source, error) {
	ldap := source.LDAP
	oidc := source.OIDC
	_, err := r.pool.Exec(ctx, `
		INSERT INTO identity_sources (
			id, name, source_type, enabled,
			ldap_url, ldap_start_tls, ldap_base_dn, ldap_bind_dn,
			ldap_user_filter, ldap_username_attribute,
			ldap_display_name_attribute, ldap_email_attribute,
			oidc_issuer, oidc_client_id, oidc_scopes,
			secret_ciphertext, secret_key_id,
			created_at, updated_at, archived_at
		)
		VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19, $20
		)`,
		source.ID,
		source.Name,
		source.Type,
		source.Enabled,
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.URL }),
		ldapBool(ldap, func(value *federation.LDAPSource) bool { return value.StartTLS }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.BaseDN }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.BindDN }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.UserFilter }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.UsernameAttribute }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.DisplayNameAttribute }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.EmailAttribute }),
		oidcString(oidc, func(value *federation.OIDCSource) string { return value.Issuer }),
		oidcString(oidc, func(value *federation.OIDCSource) string { return value.ClientID }),
		oidcScopes(oidc),
		nullableBytes(source.SecretCiphertext),
		nullableSourceString(source.SecretKeyID),
		source.CreatedAt,
		source.UpdatedAt,
		source.ArchivedAt,
	)
	if isUniqueViolation(err) {
		return federation.Source{}, federation.ErrSourceConflict
	}
	if err != nil {
		return federation.Source{}, fmt.Errorf("create identity source: %w", err)
	}
	return source, nil
}

func (r *SourceRepository) Replace(
	ctx context.Context,
	source federation.Source,
) (federation.Source, error) {
	ldap := source.LDAP
	oidc := source.OIDC
	command, err := r.pool.Exec(ctx, `
		UPDATE identity_sources
		SET name = $2,
		    enabled = $3,
		    ldap_url = $4,
		    ldap_start_tls = $5,
		    ldap_base_dn = $6,
		    ldap_bind_dn = $7,
		    ldap_user_filter = $8,
		    ldap_username_attribute = $9,
		    ldap_display_name_attribute = $10,
		    ldap_email_attribute = $11,
		    oidc_issuer = $12,
		    oidc_client_id = $13,
		    oidc_scopes = $14,
		    secret_ciphertext = $15,
		    secret_key_id = $16,
		    updated_at = $17
		WHERE id = $1 AND source_type = $18 AND archived_at IS NULL`,
		source.ID,
		source.Name,
		source.Enabled,
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.URL }),
		ldapBool(ldap, func(value *federation.LDAPSource) bool { return value.StartTLS }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.BaseDN }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.BindDN }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.UserFilter }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.UsernameAttribute }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.DisplayNameAttribute }),
		ldapString(ldap, func(value *federation.LDAPSource) string { return value.EmailAttribute }),
		oidcString(oidc, func(value *federation.OIDCSource) string { return value.Issuer }),
		oidcString(oidc, func(value *federation.OIDCSource) string { return value.ClientID }),
		oidcScopes(oidc),
		nullableBytes(source.SecretCiphertext),
		nullableSourceString(source.SecretKeyID),
		source.UpdatedAt,
		source.Type,
	)
	if err != nil {
		return federation.Source{}, fmt.Errorf("replace identity source: %w", err)
	}
	if command.RowsAffected() == 0 {
		current, findErr := r.Find(ctx, source.ID)
		switch {
		case errors.Is(findErr, federation.ErrSourceNotFound):
			return federation.Source{}, federation.ErrSourceNotFound
		case findErr != nil:
			return federation.Source{}, findErr
		case current.ArchivedAt != nil:
			return federation.Source{}, federation.ErrSourceArchived
		default:
			return federation.Source{}, federation.ErrInvalidSource
		}
	}
	return source, nil
}

func (r *SourceRepository) Archive(ctx context.Context, id string, now time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE identity_sources
		SET enabled = false,
		    archived_at = coalesce(archived_at, $2),
		    updated_at = $2
		WHERE id = $1`,
		id,
		now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("archive identity source: %w", err)
	}
	if command.RowsAffected() == 0 {
		return federation.ErrSourceNotFound
	}
	return nil
}

func (r *SourceRepository) ListSourceSecretCiphertexts(
	ctx context.Context,
) ([]federation.SourceSecretRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, secret_ciphertext, secret_key_id
		FROM identity_sources
		WHERE secret_ciphertext IS NOT NULL
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list identity source secrets: %w", err)
	}
	defer rows.Close()
	result := make([]federation.SourceSecretRecord, 0)
	for rows.Next() {
		var record federation.SourceSecretRecord
		if err := rows.Scan(&record.ID, &record.Ciphertext, &record.KeyID); err != nil {
			return nil, fmt.Errorf("scan identity source secret: %w", err)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity source secrets: %w", err)
	}
	return result, nil
}

func (r *SourceRepository) ReplaceSourceSecretCiphertext(
	ctx context.Context,
	id string,
	current, replacement []byte,
	keyID string,
) (bool, error) {
	command, err := r.pool.Exec(ctx, `
		UPDATE identity_sources
		SET secret_ciphertext = $3,
		    secret_key_id = $4,
		    updated_at = now()
		WHERE id = $1 AND secret_ciphertext = $2`,
		id,
		current,
		replacement,
		keyID,
	)
	if err != nil {
		return false, fmt.Errorf("replace identity source secret: %w", err)
	}
	return command.RowsAffected() == 1, nil
}

func scanSource(scanner interface{ Scan(...any) error }) (federation.Source, error) {
	var source federation.Source
	var ldapURL, ldapBaseDN, ldapBindDN, ldapUserFilter pgtype.Text
	var ldapUsernameAttribute, ldapDisplayNameAttribute, ldapEmailAttribute pgtype.Text
	var ldapStartTLS pgtype.Bool
	var oidcIssuer, oidcClientID pgtype.Text
	var oidcScopes []string
	var secretCiphertext []byte
	var secretKeyID pgtype.Text
	var archivedAt pgtype.Timestamptz
	err := scanner.Scan(
		&source.ID,
		&source.Name,
		&source.Type,
		&source.Enabled,
		&ldapURL,
		&ldapStartTLS,
		&ldapBaseDN,
		&ldapBindDN,
		&ldapUserFilter,
		&ldapUsernameAttribute,
		&ldapDisplayNameAttribute,
		&ldapEmailAttribute,
		&oidcIssuer,
		&oidcClientID,
		&oidcScopes,
		&secretCiphertext,
		&secretKeyID,
		&source.CreatedAt,
		&source.UpdatedAt,
		&archivedAt,
	)
	if err != nil {
		return federation.Source{}, err
	}
	switch source.Type {
	case federation.SourceLDAP:
		source.LDAP = &federation.LDAPSource{
			URL:                  ldapURL.String,
			StartTLS:             ldapStartTLS.Bool,
			BaseDN:               ldapBaseDN.String,
			BindDN:               ldapBindDN.String,
			UserFilter:           ldapUserFilter.String,
			UsernameAttribute:    ldapUsernameAttribute.String,
			DisplayNameAttribute: ldapDisplayNameAttribute.String,
			EmailAttribute:       ldapEmailAttribute.String,
		}
	case federation.SourceOIDC:
		source.OIDC = &federation.OIDCSource{
			Issuer:   oidcIssuer.String,
			ClientID: oidcClientID.String,
			Scopes:   oidcScopes,
		}
	}
	source.SecretCiphertext = secretCiphertext
	source.SecretConfigured = len(secretCiphertext) > 0
	if secretKeyID.Valid {
		source.SecretKeyID = secretKeyID.String
	}
	if archivedAt.Valid {
		value := archivedAt.Time
		source.ArchivedAt = &value
	}
	return source, nil
}

func ldapString(
	source *federation.LDAPSource,
	get func(*federation.LDAPSource) string,
) any {
	if source == nil {
		return nil
	}
	return get(source)
}

func ldapBool(
	source *federation.LDAPSource,
	get func(*federation.LDAPSource) bool,
) any {
	if source == nil {
		return nil
	}
	return get(source)
}

func oidcString(
	source *federation.OIDCSource,
	get func(*federation.OIDCSource) string,
) any {
	if source == nil {
		return nil
	}
	return get(source)
}

func oidcScopes(source *federation.OIDCSource) any {
	if source == nil {
		return nil
	}
	return source.Scopes
}

func nullableSourceString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
