package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/oauth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OAuthRepository struct {
	pool *pgxpool.Pool
}

func NewOAuthRepository(pool *pgxpool.Pool) *OAuthRepository {
	return &OAuthRepository{pool: pool}
}

func (r *OAuthRepository) SaveAuthorizationCode(ctx context.Context, value oauth.AuthorizationCode) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_authorization_codes (
			code_hash, client_id, user_id, session_id, redirect_uri, scope, nonce,
			code_challenge, code_challenge_method, authenticated_at,
			authentication_methods, assurance_level, created_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'S256', $9, $10, $11, $12, $13)`,
		value.Hash, value.ClientID, value.UserID, value.SessionID, value.RedirectURI, value.Scope,
		value.Nonce, value.CodeChallenge, value.AuthenticatedAt, value.AuthMethods,
		value.AssuranceLevel, value.CreatedAt, value.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert authorization code: %w", err)
	}
	return nil
}

func (r *OAuthRepository) ConsumeAuthorizationCode(ctx context.Context, hash []byte, clientID, redirectURI, codeChallenge string, now time.Time) (oauth.AuthorizationCode, error) {
	var value oauth.AuthorizationCode
	err := r.pool.QueryRow(ctx, `
		UPDATE oauth_authorization_codes
		SET consumed_at = $2
		WHERE code_hash = $1
		  AND client_id = $3
		  AND redirect_uri = $4
		  AND code_challenge = $5
		  AND consumed_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > $2
		RETURNING code_hash, client_id, user_id::text, session_id::text, redirect_uri, scope, nonce,
		          code_challenge, authenticated_at, authentication_methods, assurance_level,
		          created_at, expires_at`,
		hash, now, clientID, redirectURI, codeChallenge,
	).Scan(
		&value.Hash, &value.ClientID, &value.UserID, &value.SessionID, &value.RedirectURI,
		&value.Scope, &value.Nonce, &value.CodeChallenge, &value.AuthenticatedAt,
		&value.AuthMethods, &value.AssuranceLevel, &value.CreatedAt, &value.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.AuthorizationCode{}, oauth.ErrGrantNotFound
	}
	if err != nil {
		return oauth.AuthorizationCode{}, fmt.Errorf("consume authorization code: %w", err)
	}
	return value, nil
}

func (r *OAuthRepository) SaveAccessToken(ctx context.Context, value oauth.AccessToken) error {
	var userID any
	if value.UserID != "" {
		userID = value.UserID
	}
	var familyID any
	if value.FamilyID != "" {
		familyID = value.FamilyID
	}
	var sessionID any
	if value.SessionID != "" {
		sessionID = value.SessionID
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_access_tokens (
			token_hash, client_id, user_id, session_id, refresh_family_id, scope, issued_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		value.Hash, value.ClientID, userID, sessionID, familyID, value.Scope, value.IssuedAt, value.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert access token: %w", err)
	}
	return nil
}

func (r *OAuthRepository) FindAccessToken(ctx context.Context, hash []byte, now time.Time) (oauth.AccessToken, error) {
	var value oauth.AccessToken
	var userID pgtype.Text
	var sessionID pgtype.Text
	var familyID pgtype.Text
	err := r.pool.QueryRow(ctx, `
		SELECT token_hash, client_id, user_id::text, session_id::text,
		       refresh_family_id::text, scope, issued_at, expires_at
		FROM oauth_access_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > $2`,
		hash, now,
	).Scan(
		&value.Hash, &value.ClientID, &userID, &sessionID, &familyID,
		&value.Scope, &value.IssuedAt, &value.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.AccessToken{}, oauth.ErrGrantNotFound
	}
	if err != nil {
		return oauth.AccessToken{}, fmt.Errorf("find access token: %w", err)
	}
	if userID.Valid {
		value.UserID = userID.String
	}
	if sessionID.Valid {
		value.SessionID = sessionID.String
	}
	if familyID.Valid {
		value.FamilyID = familyID.String
	}
	return value, nil
}

func (r *OAuthRepository) RevokeAccessToken(ctx context.Context, hash []byte, clientID string, now time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE oauth_access_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE token_hash = $1 AND client_id = $2`,
		hash, clientID, now,
	)
	if err != nil {
		return fmt.Errorf("revoke access token: %w", err)
	}
	if command.RowsAffected() == 0 {
		return oauth.ErrGrantNotFound
	}
	return nil
}

func (r *OAuthRepository) SaveRefreshToken(ctx context.Context, value oauth.RefreshToken) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (
			token_hash, family_id, client_id, user_id, session_id, scope, issued_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		value.Hash, value.FamilyID, value.ClientID, value.UserID, nullableText(value.SessionID),
		value.Scope, value.IssuedAt, value.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (r *OAuthRepository) FindRefreshToken(ctx context.Context, hash []byte, now time.Time) (oauth.RefreshToken, error) {
	var value oauth.RefreshToken
	var sessionID pgtype.Text
	err := r.pool.QueryRow(ctx, `
		SELECT token_hash, family_id::text, client_id, user_id::text, session_id::text,
		       scope, issued_at, expires_at
		FROM oauth_refresh_tokens
		WHERE token_hash = $1
		  AND consumed_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > $2`,
		hash, now,
	).Scan(
		&value.Hash, &value.FamilyID, &value.ClientID, &value.UserID, &sessionID, &value.Scope,
		&value.IssuedAt, &value.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	if err != nil {
		return oauth.RefreshToken{}, fmt.Errorf("find refresh token: %w", err)
	}
	if sessionID.Valid {
		value.SessionID = sessionID.String
	}
	return value, nil
}

func (r *OAuthRepository) RotateRefreshToken(ctx context.Context, hash []byte, replacement oauth.RefreshToken, now time.Time) (oauth.RefreshToken, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return oauth.RefreshToken{}, fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current oauth.RefreshToken
	var sessionID pgtype.Text
	var consumedAt pgtype.Timestamptz
	var revokedAt pgtype.Timestamptz
	err = tx.QueryRow(ctx, `
		SELECT token_hash, family_id::text, client_id, user_id::text, session_id::text,
		       scope, issued_at, expires_at, consumed_at, revoked_at
		FROM oauth_refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE`,
		hash,
	).Scan(
		&current.Hash, &current.FamilyID, &current.ClientID, &current.UserID, &sessionID, &current.Scope,
		&current.IssuedAt, &current.ExpiresAt, &consumedAt, &revokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	if err != nil {
		return oauth.RefreshToken{}, fmt.Errorf("lock refresh token: %w", err)
	}
	if current.ClientID != replacement.ClientID {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	if sessionID.Valid {
		current.SessionID = sessionID.String
	}
	if consumedAt.Valid || revokedAt.Valid {
		if _, err := tx.Exec(ctx, `
			UPDATE oauth_refresh_tokens
			SET revoked_at = coalesce(revoked_at, $2)
			WHERE family_id = $1`,
			current.FamilyID, now,
		); err != nil {
			return oauth.RefreshToken{}, fmt.Errorf("revoke refresh family: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE oauth_access_tokens
			SET revoked_at = coalesce(revoked_at, $2)
			WHERE refresh_family_id = $1`,
			current.FamilyID, now,
		); err != nil {
			return oauth.RefreshToken{}, fmt.Errorf("revoke reused refresh family access tokens: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return oauth.RefreshToken{}, fmt.Errorf("commit refresh reuse handling: %w", err)
		}
		return oauth.RefreshToken{}, oauth.ErrRefreshReuse
	}
	if !current.ExpiresAt.After(now) {
		return oauth.RefreshToken{}, oauth.ErrGrantExpired
	}
	replacement.FamilyID = current.FamilyID
	replacement.UserID = current.UserID
	replacement.SessionID = current.SessionID
	if replacement.Scope == nil {
		replacement.Scope = append([]string(nil), current.Scope...)
	}
	if !oauth.ScopesCover(current.Scope, replacement.Scope) {
		return oauth.RefreshToken{}, oauth.ErrInvalidScope
	}
	command, err := tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET consumed_at = $2, replaced_by_hash = $3
		WHERE token_hash = $1`,
		hash, now, replacement.Hash,
	)
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return oauth.RefreshToken{}, fmt.Errorf("consume refresh token: %w", err)
		}
		return oauth.RefreshToken{}, errors.New("consume refresh token: no row updated")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (
			token_hash, family_id, client_id, user_id, session_id, scope, issued_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		replacement.Hash, replacement.FamilyID, replacement.ClientID, replacement.UserID,
		nullableText(replacement.SessionID), replacement.Scope, replacement.IssuedAt, replacement.ExpiresAt,
	)
	if err != nil {
		return oauth.RefreshToken{}, fmt.Errorf("insert replacement refresh token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return oauth.RefreshToken{}, fmt.Errorf("commit refresh rotation: %w", err)
	}
	return current, nil
}

func (r *OAuthRepository) RevokeRefreshToken(ctx context.Context, hash []byte, clientID string, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin refresh token revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var familyID string
	if err := tx.QueryRow(ctx, `
		SELECT family_id::text
		FROM oauth_refresh_tokens
		WHERE token_hash = $1 AND client_id = $2
		FOR UPDATE`,
		hash, clientID,
	).Scan(&familyID); errors.Is(err, pgx.ErrNoRows) {
		return oauth.ErrGrantNotFound
	} else if err != nil {
		return fmt.Errorf("find refresh token family: %w", err)
	}
	command, err := tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE family_id = $1 AND client_id = $2`,
		familyID, clientID, now,
	)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	if command.RowsAffected() == 0 {
		return errors.New("revoke refresh token family: no row updated")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_access_tokens
		SET revoked_at = coalesce(revoked_at, $2)
		WHERE refresh_family_id = $1`,
		familyID, now,
	); err != nil {
		return fmt.Errorf("revoke access tokens for refresh family: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit refresh token revocation: %w", err)
	}
	return nil
}

func (r *OAuthRepository) SaveDeviceAuthorization(ctx context.Context, value oauth.DeviceAuthorization) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_device_authorizations (
			device_code_hash, user_code_hash, client_id, scope, status,
			created_at, expires_at, interval_seconds
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		value.DeviceHash, value.UserHash, value.ClientID, value.Scope, value.Status,
		value.CreatedAt, value.ExpiresAt, int(value.Interval/time.Second),
	)
	if err != nil {
		return fmt.Errorf("insert device authorization: %w", err)
	}
	return nil
}

func (r *OAuthRepository) FindDeviceByUserCode(ctx context.Context, hash []byte, now time.Time) (oauth.DeviceAuthorization, error) {
	value, err := scanDevice(r.pool.QueryRow(ctx, `
		SELECT device_code_hash, user_code_hash, client_id, user_id::text, scope, status,
		       authenticated_at, authentication_methods, assurance_level,
		       created_at, expires_at, interval_seconds, last_poll_at
		FROM oauth_device_authorizations
		WHERE user_code_hash = $1
		  AND status = 'pending'
		  AND expires_at > $2`,
		hash, now,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.DeviceAuthorization{}, oauth.ErrGrantNotFound
	}
	if err != nil {
		return oauth.DeviceAuthorization{}, fmt.Errorf("find device by user code: %w", err)
	}
	return value, nil
}

func (r *OAuthRepository) DecideDeviceAuthorization(
	ctx context.Context,
	userHash []byte,
	userID string,
	authenticatedAt time.Time,
	authMethods []string,
	assuranceLevel string,
	approve bool,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device authorization decision: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	status := oauth.DeviceDenied
	if approve {
		status = oauth.DeviceApproved
	}
	var clientID string
	var scopes []string
	err = tx.QueryRow(ctx, `
		UPDATE oauth_device_authorizations
		SET user_id = $2, authenticated_at = $3, authentication_methods = $4,
		    assurance_level = $5, status = $6, decided_at = $7
		WHERE user_code_hash = $1
		  AND status = 'pending'
		  AND expires_at > $7
		RETURNING client_id, scope`,
		userHash, userID, authenticatedAt, authMethods, assuranceLevel, status, now,
	).Scan(&clientID, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.ErrGrantNotFound
	}
	if err != nil {
		return fmt.Errorf("decide device authorization: %w", err)
	}
	if approve {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_consents (user_id, client_id, scopes, granted_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (user_id, client_id)
			DO UPDATE SET
			    scopes = ARRAY(
			        SELECT DISTINCT scope
			        FROM unnest(oauth_consents.scopes || excluded.scopes) AS scope
			        ORDER BY scope
			    ),
			    updated_at = excluded.updated_at`,
			userID, clientID, scopes, now,
		); err != nil {
			return fmt.Errorf("grant device OAuth consent: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit device authorization decision: %w", err)
	}
	return nil
}

func (r *OAuthRepository) PollDeviceAuthorization(ctx context.Context, deviceHash []byte, clientID string, now time.Time) (oauth.DeviceAuthorization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return oauth.DeviceAuthorization{}, fmt.Errorf("begin device poll: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	value, err := scanDevice(tx.QueryRow(ctx, `
		SELECT device_code_hash, user_code_hash, client_id, user_id::text, scope, status,
		       authenticated_at, authentication_methods, assurance_level,
		       created_at, expires_at, interval_seconds, last_poll_at
		FROM oauth_device_authorizations
		WHERE device_code_hash = $1 AND client_id = $2
		FOR UPDATE`,
		deviceHash, clientID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.DeviceAuthorization{}, oauth.ErrGrantNotFound
	}
	if err != nil {
		return oauth.DeviceAuthorization{}, fmt.Errorf("lock device authorization: %w", err)
	}
	if !value.ExpiresAt.After(now) {
		return oauth.DeviceAuthorization{}, oauth.ErrGrantExpired
	}
	if value.LastPollAt != nil && now.Before(value.LastPollAt.Add(value.Interval)) {
		value.Interval += 5 * time.Second
		_, err := tx.Exec(ctx, `
			UPDATE oauth_device_authorizations
			SET interval_seconds = $2, last_poll_at = $3
			WHERE device_code_hash = $1`,
			deviceHash, int(value.Interval/time.Second), now,
		)
		if err != nil {
			return oauth.DeviceAuthorization{}, fmt.Errorf("slow device poll: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return oauth.DeviceAuthorization{}, err
		}
		return oauth.DeviceAuthorization{}, oauth.ErrSlowDown
	}
	_, err = tx.Exec(ctx, `
		UPDATE oauth_device_authorizations
		SET last_poll_at = $2
		WHERE device_code_hash = $1`,
		deviceHash, now,
	)
	if err != nil {
		return oauth.DeviceAuthorization{}, fmt.Errorf("record device poll: %w", err)
	}
	switch value.Status {
	case oauth.DevicePending:
		if err := tx.Commit(ctx); err != nil {
			return oauth.DeviceAuthorization{}, err
		}
		return oauth.DeviceAuthorization{}, oauth.ErrAuthorizationPending
	case oauth.DeviceDenied:
		if err := tx.Commit(ctx); err != nil {
			return oauth.DeviceAuthorization{}, err
		}
		return oauth.DeviceAuthorization{}, oauth.ErrAccessDenied
	case oauth.DeviceConsumed:
		return oauth.DeviceAuthorization{}, oauth.ErrGrantConsumed
	case oauth.DeviceApproved:
		_, err := tx.Exec(ctx, `
			UPDATE oauth_device_authorizations
			SET status = 'consumed', consumed_at = $2
			WHERE device_code_hash = $1`,
			deviceHash, now,
		)
		if err != nil {
			return oauth.DeviceAuthorization{}, fmt.Errorf("consume device authorization: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return oauth.DeviceAuthorization{}, err
		}
		return value, nil
	default:
		return oauth.DeviceAuthorization{}, oauth.ErrGrantNotFound
	}
}

type deviceScanner interface {
	Scan(...any) error
}

func scanDevice(scanner deviceScanner) (oauth.DeviceAuthorization, error) {
	var value oauth.DeviceAuthorization
	var userID pgtype.Text
	var intervalSeconds int
	var authenticatedAt pgtype.Timestamptz
	var lastPoll pgtype.Timestamptz
	err := scanner.Scan(
		&value.DeviceHash, &value.UserHash, &value.ClientID, &userID, &value.Scope,
		&value.Status, &authenticatedAt, &value.AuthMethods, &value.AssuranceLevel,
		&value.CreatedAt, &value.ExpiresAt, &intervalSeconds, &lastPoll,
	)
	if err != nil {
		return oauth.DeviceAuthorization{}, err
	}
	if userID.Valid {
		value.UserID = userID.String
	}
	if authenticatedAt.Valid {
		value.AuthenticatedAt = authenticatedAt.Time
	}
	value.Interval = time.Duration(intervalSeconds) * time.Second
	if lastPoll.Valid {
		value.LastPollAt = &lastPoll.Time
	}
	return value, nil
}

func (r *OAuthRepository) SaveOIDCClientSession(ctx context.Context, value oauth.OIDCClientSession) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oidc_client_sessions (session_id, client_id, user_id, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (session_id, client_id)
		DO UPDATE SET user_id = excluded.user_id, created_at = excluded.created_at`,
		value.SessionID, value.ClientID, value.UserID, value.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("save OIDC client session: %w", err)
	}
	return nil
}

func (r *OAuthRepository) ListOIDCClientSessions(ctx context.Context, sessionID string) ([]oauth.OIDCClientSession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT session_id::text, client_id, user_id::text, created_at
		FROM oidc_client_sessions
		WHERE session_id = $1
		ORDER BY client_id`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("list OIDC client sessions: %w", err)
	}
	defer rows.Close()
	result := make([]oauth.OIDCClientSession, 0)
	for rows.Next() {
		var value oauth.OIDCClientSession
		if err := rows.Scan(&value.SessionID, &value.ClientID, &value.UserID, &value.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan OIDC client session: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate OIDC client sessions: %w", err)
	}
	return result, nil
}

func (r *OAuthRepository) DeleteOIDCClientSessions(ctx context.Context, sessionID string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM oidc_client_sessions WHERE session_id = $1`, sessionID); err != nil {
		return fmt.Errorf("delete OIDC client sessions: %w", err)
	}
	return nil
}

func (r *OAuthRepository) RevokeSessionTokens(
	ctx context.Context,
	userID, sessionID string,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OAuth session revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_authorization_codes
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1 AND session_id = $2`,
		userID, sessionID, now,
	); err != nil {
		return fmt.Errorf("revoke session authorization codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_access_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1 AND session_id = $2`,
		userID, sessionID, now,
	); err != nil {
		return fmt.Errorf("revoke session access tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1 AND session_id = $2`,
		userID, sessionID, now,
	); err != nil {
		return fmt.Errorf("revoke session refresh tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit OAuth session revocation: %w", err)
	}
	return nil
}

func (r *OAuthRepository) RevokeUserTokens(
	ctx context.Context,
	userID, exceptSessionID string,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OAuth user revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_authorization_codes
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1
		  AND ($2 = '' OR session_id IS DISTINCT FROM nullif($2, '')::uuid)`,
		userID, exceptSessionID, now,
	); err != nil {
		return fmt.Errorf("revoke user authorization codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_access_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1
		  AND ($2 = '' OR session_id IS DISTINCT FROM nullif($2, '')::uuid)`,
		userID, exceptSessionID, now,
	); err != nil {
		return fmt.Errorf("revoke user access tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1
		  AND ($2 = '' OR session_id IS DISTINCT FROM nullif($2, '')::uuid)`,
		userID, exceptSessionID, now,
	); err != nil {
		return fmt.Errorf("revoke user refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_device_authorizations
		SET status = 'denied', decided_at = coalesce(decided_at, $2)
		WHERE user_id = $1 AND status = 'approved'`,
		userID, now,
	); err != nil {
		return fmt.Errorf("revoke user device authorizations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit OAuth user revocation: %w", err)
	}
	return nil
}

func (r *OAuthRepository) RevokeClientTokens(
	ctx context.Context,
	clientID string,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OAuth client revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_authorization_codes
		SET revoked_at = coalesce(revoked_at, $2)
		WHERE client_id = $1`,
		clientID, now,
	); err != nil {
		return fmt.Errorf("revoke client authorization codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_access_tokens
		SET revoked_at = coalesce(revoked_at, $2)
		WHERE client_id = $1`,
		clientID, now,
	); err != nil {
		return fmt.Errorf("revoke client access tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = coalesce(revoked_at, $2)
		WHERE client_id = $1`,
		clientID, now,
	); err != nil {
		return fmt.Errorf("revoke client refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_device_authorizations
		SET status = 'denied', decided_at = coalesce(decided_at, $2)
		WHERE client_id = $1 AND status IN ('pending', 'approved')`,
		clientID, now,
	); err != nil {
		return fmt.Errorf("revoke client device authorizations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit OAuth client revocation: %w", err)
	}
	return nil
}

func (r *OAuthRepository) FindConsent(ctx context.Context, userID, clientID string) (oauth.Consent, error) {
	var value oauth.Consent
	err := r.pool.QueryRow(ctx, `
		SELECT user_id::text, client_id, scopes, granted_at, updated_at
		FROM oauth_consents
		WHERE user_id = $1 AND client_id = $2`,
		userID, clientID,
	).Scan(&value.UserID, &value.ClientID, &value.Scopes, &value.GrantedAt, &value.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.Consent{}, oauth.ErrConsentNotFound
	}
	if err != nil {
		return oauth.Consent{}, fmt.Errorf("find OAuth consent: %w", err)
	}
	return value, nil
}

func (r *OAuthRepository) GrantConsent(
	ctx context.Context,
	userID, clientID string,
	scopes []string,
	now time.Time,
) (oauth.Consent, error) {
	var value oauth.Consent
	err := r.pool.QueryRow(ctx, `
		INSERT INTO oauth_consents (user_id, client_id, scopes, granted_at, updated_at)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (user_id, client_id)
		DO UPDATE SET
		    scopes = ARRAY(
		        SELECT DISTINCT scope
		        FROM unnest(oauth_consents.scopes || excluded.scopes) AS scope
		        ORDER BY scope
		    ),
		    updated_at = excluded.updated_at
		RETURNING user_id::text, client_id, scopes, granted_at, updated_at`,
		userID, clientID, scopes, now,
	).Scan(&value.UserID, &value.ClientID, &value.Scopes, &value.GrantedAt, &value.UpdatedAt)
	if err != nil {
		return oauth.Consent{}, fmt.Errorf("grant OAuth consent: %w", err)
	}
	return value, nil
}

func (r *OAuthRepository) ListConsentsByUser(ctx context.Context, userID string) ([]oauth.Consent, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT user_id::text, client_id, scopes, granted_at, updated_at
		FROM oauth_consents
		WHERE user_id = $1
		ORDER BY updated_at DESC, client_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list OAuth consents: %w", err)
	}
	defer rows.Close()
	result := make([]oauth.Consent, 0)
	for rows.Next() {
		var value oauth.Consent
		if err := rows.Scan(&value.UserID, &value.ClientID, &value.Scopes, &value.GrantedAt, &value.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan OAuth consent: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate OAuth consents: %w", err)
	}
	return result, nil
}

func (r *OAuthRepository) DeleteConsent(
	ctx context.Context,
	userID, clientID string,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OAuth consent revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `
		DELETE FROM oauth_consents
		WHERE user_id = $1 AND client_id = $2`, userID, clientID)
	if err != nil {
		return fmt.Errorf("delete OAuth consent: %w", err)
	}
	if command.RowsAffected() == 0 {
		return oauth.ErrConsentNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_authorization_codes
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1 AND client_id = $2`,
		userID, clientID, now,
	); err != nil {
		return fmt.Errorf("revoke consent authorization codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_access_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1 AND client_id = $2`,
		userID, clientID, now,
	); err != nil {
		return fmt.Errorf("revoke consent access tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = coalesce(revoked_at, $3)
		WHERE user_id = $1 AND client_id = $2`,
		userID, clientID, now,
	); err != nil {
		return fmt.Errorf("revoke consent refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_device_authorizations
		SET status = 'denied', decided_at = coalesce(decided_at, $3)
		WHERE user_id = $1 AND client_id = $2 AND status = 'approved'`,
		userID, clientID, now,
	); err != nil {
		return fmt.Errorf("revoke consent device authorizations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit OAuth consent revocation: %w", err)
	}
	return nil
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
