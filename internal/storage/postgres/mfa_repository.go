package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/mfa"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MFARepository struct {
	pool *pgxpool.Pool
}

var _ mfa.SecretRepository = (*MFARepository)(nil)

func NewMFARepository(pool *pgxpool.Pool) *MFARepository {
	return &MFARepository{pool: pool}
}

func (r *MFARepository) Find(ctx context.Context, userID string) (mfa.Credential, error) {
	var credential mfa.Credential
	var verifiedAt pgtype.Timestamptz
	var lockedUntil pgtype.Timestamptz
	err := r.pool.QueryRow(ctx, `
		SELECT c.user_id::text, c.secret_ciphertext, c.enabled, c.created_at, c.verified_at,
		       c.last_used_step, c.failed_attempts, c.locked_until,
		       count(r.code_hash) FILTER (WHERE r.used_at IS NULL)
		FROM mfa_totp_credentials c
		LEFT JOIN mfa_recovery_codes r ON r.user_id = c.user_id
		WHERE c.user_id = $1
		GROUP BY c.user_id`,
		userID,
	).Scan(
		&credential.UserID, &credential.Secret, &credential.Enabled, &credential.CreatedAt,
		&verifiedAt, &credential.LastUsedStep, &credential.FailedAttempts, &lockedUntil,
		&credential.RecoveryCodes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return mfa.Credential{}, mfa.ErrNotFound
	}
	if err != nil {
		return mfa.Credential{}, fmt.Errorf("find MFA credential: %w", err)
	}
	if verifiedAt.Valid {
		value := verifiedAt.Time
		credential.VerifiedAt = &value
	}
	if lockedUntil.Valid {
		value := lockedUntil.Time
		credential.LockedUntil = &value
	}
	return credential, nil
}

func (r *MFARepository) ReplacePending(ctx context.Context, credential mfa.Credential, recoveryCodes [][]byte) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin MFA setup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO mfa_totp_credentials (
			user_id, secret_ciphertext, enabled, created_at, verified_at,
			last_used_step, failed_attempts, locked_until
		)
		VALUES ($1, $2, false, $3, NULL, -1, 0, NULL)
		ON CONFLICT (user_id) DO UPDATE
		SET secret_ciphertext = EXCLUDED.secret_ciphertext,
		    enabled = false,
		    created_at = EXCLUDED.created_at,
		    verified_at = NULL,
		    last_used_step = -1,
		    failed_attempts = 0,
		    locked_until = NULL`,
		credential.UserID, credential.Secret, credential.CreatedAt,
	); err != nil {
		return fmt.Errorf("replace pending MFA credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, credential.UserID); err != nil {
		return fmt.Errorf("replace MFA recovery codes: %w", err)
	}
	for _, hash := range recoveryCodes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at)
			VALUES ($1, $2, $3)`,
			credential.UserID, hash, credential.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert MFA recovery code: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit MFA setup: %w", err)
	}
	return nil
}

func (r *MFARepository) ListSecretCiphertexts(ctx context.Context) ([]mfa.SecretRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT user_id::text, secret_ciphertext
		FROM mfa_totp_credentials
		ORDER BY user_id`)
	if err != nil {
		return nil, fmt.Errorf("list MFA secret ciphertexts: %w", err)
	}
	defer rows.Close()
	result := make([]mfa.SecretRecord, 0)
	for rows.Next() {
		var value mfa.SecretRecord
		if err := rows.Scan(&value.UserID, &value.Ciphertext); err != nil {
			return nil, fmt.Errorf("scan MFA secret ciphertext: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate MFA secret ciphertexts: %w", err)
	}
	return result, nil
}

func (r *MFARepository) ReplaceSecretCiphertext(
	ctx context.Context,
	userID string,
	current, replacement []byte,
) (bool, error) {
	command, err := r.pool.Exec(ctx, `
		UPDATE mfa_totp_credentials
		SET secret_ciphertext = $3
		WHERE user_id = $1 AND secret_ciphertext = $2`,
		userID, current, replacement,
	)
	if err != nil {
		return false, fmt.Errorf("replace MFA secret ciphertext: %w", err)
	}
	return command.RowsAffected() == 1, nil
}

func (r *MFARepository) Enable(ctx context.Context, userID string, step int64, now time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE mfa_totp_credentials
		SET enabled = true, verified_at = $3, last_used_step = $2,
		    failed_attempts = 0, locked_until = NULL
		WHERE user_id = $1`,
		userID, step, now,
	)
	if err != nil {
		return fmt.Errorf("enable MFA credential: %w", err)
	}
	if command.RowsAffected() == 0 {
		return mfa.ErrNotFound
	}
	return nil
}

func (r *MFARepository) UseTOTP(ctx context.Context, userID string, step int64, _ time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE mfa_totp_credentials
		SET last_used_step = $2, failed_attempts = 0, locked_until = NULL
		WHERE user_id = $1 AND enabled = true AND last_used_step < $2`,
		userID, step,
	)
	if err != nil {
		return fmt.Errorf("consume TOTP code: %w", err)
	}
	if command.RowsAffected() == 0 {
		return mfa.ErrReplay
	}
	return nil
}

func (r *MFARepository) UseRecoveryCode(ctx context.Context, userID string, hash []byte, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin recovery code consumption: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `
		UPDATE mfa_recovery_codes
		SET used_at = $3
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, hash, now,
	)
	if err != nil {
		return fmt.Errorf("consume MFA recovery code: %w", err)
	}
	if command.RowsAffected() == 0 {
		return mfa.ErrInvalidCode
	}
	if _, err := tx.Exec(ctx, `
		UPDATE mfa_totp_credentials
		SET failed_attempts = 0, locked_until = NULL
		WHERE user_id = $1 AND enabled = true`,
		userID,
	); err != nil {
		return fmt.Errorf("reset MFA failures: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit recovery code consumption: %w", err)
	}
	return nil
}

func (r *MFARepository) RecordFailure(ctx context.Context, userID string, attempts int, lockedUntil *time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE mfa_totp_credentials
		SET failed_attempts = $2, locked_until = $3
		WHERE user_id = $1`,
		userID, attempts, lockedUntil,
	)
	if err != nil {
		return fmt.Errorf("record MFA failure: %w", err)
	}
	if command.RowsAffected() == 0 {
		return mfa.ErrNotFound
	}
	return nil
}

func (r *MFARepository) Delete(ctx context.Context, userID string) error {
	command, err := r.pool.Exec(ctx, `DELETE FROM mfa_totp_credentials WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete MFA credential: %w", err)
	}
	if command.RowsAffected() == 0 {
		return mfa.ErrNotFound
	}
	return nil
}
