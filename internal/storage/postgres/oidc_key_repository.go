package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/oidc"
	"certus/internal/secrets"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OIDCKeyRepository struct {
	pool    *pgxpool.Pool
	keyRing secrets.KeyRing
}

var _ oidc.KeyRepository = (*OIDCKeyRepository)(nil)

func NewOIDCKeyRepository(pool *pgxpool.Pool) *OIDCKeyRepository {
	return &OIDCKeyRepository{pool: pool}
}

func NewEncryptedOIDCKeyRepository(
	pool *pgxpool.Pool,
	keyRing secrets.KeyRing,
) *OIDCKeyRepository {
	return &OIDCKeyRepository{pool: pool, keyRing: keyRing}
}

func (r *OIDCKeyRepository) LoadActiveSigningKey(ctx context.Context) ([]byte, error) {
	var kid string
	var value []byte
	var encryptionKeyID pgtype.Text
	err := r.pool.QueryRow(ctx, `
		SELECT kid, private_key_pem, encryption_key_id
		FROM oidc_signing_keys
		WHERE active = true
		ORDER BY created_at DESC
		LIMIT 1`,
	).Scan(&kid, &value, &encryptionKeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oidc.ErrSigningKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load OIDC signing key: %w", err)
	}
	plaintext, err := r.unprotectSigningKey(kid, value, encryptionKeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypt active OIDC signing key: %w", err)
	}
	return plaintext, nil
}

func (r *OIDCKeyRepository) SaveActiveSigningKey(ctx context.Context, kid string, value []byte, createdAt time.Time) error {
	material, encryptionKeyID, err := r.protectSigningKey(kid, value)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO oidc_signing_keys (
			kid, private_key_pem, encryption_key_id, algorithm, active, created_at
		)
		VALUES ($1, $2, $3, 'RS256', true, $4)`,
		kid, material, nullableEncryptionKeyID(encryptionKeyID), createdAt,
	)
	if err != nil {
		return fmt.Errorf("save OIDC signing key: %w", err)
	}
	return nil
}

func (r *OIDCKeyRepository) RotateSigningKey(ctx context.Context, kid string, value []byte, now time.Time) error {
	_, err := r.rotateSigningKey(ctx, kid, value, now, nil)
	return err
}

func (r *OIDCKeyRepository) RotateSigningKeyIfOlderThan(
	ctx context.Context,
	kid string,
	value []byte,
	now time.Time,
	createdBefore time.Time,
) (bool, error) {
	return r.rotateSigningKey(ctx, kid, value, now, &createdBefore)
}

func (r *OIDCKeyRepository) rotateSigningKey(
	ctx context.Context,
	kid string,
	value []byte,
	now time.Time,
	createdBefore *time.Time,
) (bool, error) {
	material, encryptionKeyID, err := r.protectSigningKey(kid, value)
	if err != nil {
		return false, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin OIDC signing key rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(741924574)`); err != nil {
		return false, fmt.Errorf("lock OIDC signing key rotation: %w", err)
	}
	if createdBefore != nil {
		var activeCreatedAt time.Time
		err := tx.QueryRow(ctx, `
			SELECT created_at
			FROM oidc_signing_keys
			WHERE active = true
			ORDER BY created_at DESC
			LIMIT 1
			FOR UPDATE`,
		).Scan(&activeCreatedAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("read active OIDC signing key age: %w", err)
		}
		if err == nil && !activeCreatedAt.Before(*createdBefore) {
			if err := tx.Commit(ctx); err != nil {
				return false, fmt.Errorf("commit skipped OIDC signing key rotation: %w", err)
			}
			return false, nil
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oidc_signing_keys
		SET active = false, retired_at = coalesce(retired_at, $1)
		WHERE active = true`,
		now,
	); err != nil {
		return false, fmt.Errorf("retire OIDC signing key: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_signing_keys (
			kid, private_key_pem, encryption_key_id, algorithm, active, created_at
		)
		VALUES ($1, $2, $3, 'RS256', true, $4)`,
		kid, material, nullableEncryptionKeyID(encryptionKeyID), now,
	); err != nil {
		return false, fmt.Errorf("insert rotated OIDC signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit OIDC signing key rotation: %w", err)
	}
	return true, nil
}

func (r *OIDCKeyRepository) ListSigningKeys(ctx context.Context) ([]oidc.SigningKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT kid, private_key_pem, encryption_key_id, active, created_at, retired_at
		FROM oidc_signing_keys
		ORDER BY active DESC, created_at DESC, kid`)
	if err != nil {
		return nil, fmt.Errorf("list OIDC signing keys: %w", err)
	}
	defer rows.Close()
	result := make([]oidc.SigningKey, 0)
	for rows.Next() {
		var value oidc.SigningKey
		var encryptionKeyID pgtype.Text
		var retiredAt pgtype.Timestamptz
		if err := rows.Scan(
			&value.KID, &value.PEM, &encryptionKeyID,
			&value.Active, &value.CreatedAt, &retiredAt,
		); err != nil {
			return nil, fmt.Errorf("scan OIDC signing key: %w", err)
		}
		plaintext, err := r.unprotectSigningKey(value.KID, value.PEM, encryptionKeyID)
		if err != nil {
			return nil, fmt.Errorf("decrypt OIDC signing key %s: %w", value.KID, err)
		}
		value.PEM = plaintext
		if retiredAt.Valid {
			retired := retiredAt.Time
			value.RetiredAt = &retired
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate OIDC signing keys: %w", err)
	}
	return result, nil
}

func (r *OIDCKeyRepository) RewrapSigningKeys(ctx context.Context) (int64, error) {
	if !r.keyRing.Available() {
		return 0, nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin OIDC signing key rewrap: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(741924574)`); err != nil {
		return 0, fmt.Errorf("lock OIDC signing key rewrap: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT kid, private_key_pem, encryption_key_id
		FROM oidc_signing_keys
		ORDER BY kid
		FOR UPDATE`)
	if err != nil {
		return 0, fmt.Errorf("list OIDC signing keys for rewrap: %w", err)
	}
	type storedKey struct {
		kid             string
		material        []byte
		encryptionKeyID pgtype.Text
	}
	values := make([]storedKey, 0)
	for rows.Next() {
		var value storedKey
		if err := rows.Scan(&value.kid, &value.material, &value.encryptionKeyID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan OIDC signing key for rewrap: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate OIDC signing keys for rewrap: %w", err)
	}
	rows.Close()
	var count int64
	for _, value := range values {
		plaintext, err := r.unprotectSigningKey(value.kid, value.material, value.encryptionKeyID)
		if err != nil {
			return 0, fmt.Errorf("decrypt OIDC signing key %s for rewrap: %w", value.kid, err)
		}
		currentKeyID := ""
		if value.encryptionKeyID.Valid {
			currentKeyID = value.encryptionKeyID.String
		}
		if currentKeyID == r.keyRing.PrimaryID() {
			continue
		}
		material, keyID, err := r.keyRing.Encrypt(signingKeyPurpose, value.kid, plaintext)
		if err != nil {
			return 0, fmt.Errorf("encrypt OIDC signing key %s for rewrap: %w", value.kid, err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE oidc_signing_keys
			SET private_key_pem = $2, encryption_key_id = $3
			WHERE kid = $1`,
			value.kid, material, keyID,
		); err != nil {
			return 0, fmt.Errorf("rewrap OIDC signing key %s: %w", value.kid, err)
		}
		count++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit OIDC signing key rewrap: %w", err)
	}
	return count, nil
}

func (r *OIDCKeyRepository) DeleteRetiredSigningKeys(ctx context.Context, before time.Time) (int64, error) {
	command, err := r.pool.Exec(ctx, `
		DELETE FROM oidc_signing_keys
		WHERE active = false AND retired_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete retired OIDC signing keys: %w", err)
	}
	return command.RowsAffected(), nil
}

const signingKeyPurpose = "oidc-signing-key"

func (r *OIDCKeyRepository) protectSigningKey(kid string, plaintext []byte) ([]byte, string, error) {
	if !r.keyRing.Available() {
		return append([]byte(nil), plaintext...), "", nil
	}
	material, keyID, err := r.keyRing.Encrypt(signingKeyPurpose, kid, plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt OIDC signing key: %w", err)
	}
	return material, keyID, nil
}

func (r *OIDCKeyRepository) unprotectSigningKey(
	kid string,
	material []byte,
	encryptionKeyID pgtype.Text,
) ([]byte, error) {
	if !encryptionKeyID.Valid {
		if _, encrypted := secrets.EnvelopeKeyID(material); encrypted {
			return nil, errors.New("encrypted OIDC signing key is missing key metadata")
		}
		return append([]byte(nil), material...), nil
	}
	if kid == "" {
		return nil, errors.New("OIDC signing key identifier is required for decryption")
	}
	plaintext, err := r.keyRing.Decrypt(signingKeyPurpose, kid, material, encryptionKeyID.String)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func nullableEncryptionKeyID(value string) any {
	if value == "" {
		return nil
	}
	return value
}
