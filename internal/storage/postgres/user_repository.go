package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"certus/internal/identity"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) List(ctx context.Context, filter identity.UserFilter) (identity.UserPage, error) {
	query := strings.TrimSpace(filter.Query)
	var total int64
	if err := r.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM users
		WHERE ($1 = '' OR username ILIKE '%' || $1 || '%' OR display_name ILIKE '%' || $1 || '%' OR coalesce(email, '') ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR status = $2)`,
		query, string(filter.Status),
	).Scan(&total); err != nil {
		return identity.UserPage{}, fmt.Errorf("count users: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id::text, username, display_name, email, status, created_at, updated_at
		FROM users
		WHERE ($1 = '' OR username ILIKE '%' || $1 || '%' OR display_name ILIKE '%' || $1 || '%' OR coalesce(email, '') ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR status = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4`,
		query, string(filter.Status), filter.Limit, filter.Offset,
	)
	if err != nil {
		return identity.UserPage{}, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	items := make([]identity.User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return identity.UserPage{}, err
		}
		items = append(items, user)
	}
	if err := rows.Err(); err != nil {
		return identity.UserPage{}, fmt.Errorf("iterate users: %w", err)
	}
	return identity.UserPage{
		Items:  items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (r *UserRepository) Find(ctx context.Context, id string) (identity.User, error) {
	user, err := scanUser(r.pool.QueryRow(ctx, `
		SELECT id::text, username, display_name, email, status, created_at, updated_at
		FROM users
		WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, identity.ErrNotFound
	}
	return user, err
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (identity.User, error) {
	user, err := scanUser(r.pool.QueryRow(ctx, `
		SELECT id::text, username, display_name, email, status, created_at, updated_at
		FROM users
		WHERE lower(username) = lower($1)`, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, fmt.Errorf("find user by username: %w", err)
	}
	return user, nil
}

func (r *UserRepository) Create(ctx context.Context, user identity.User) (identity.User, error) {
	created, err := scanUser(r.pool.QueryRow(ctx, `
		INSERT INTO users (id, username, display_name, email, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		RETURNING id::text, username, display_name, email, status, created_at, updated_at`,
		user.ID, user.Username, user.DisplayName, user.Email, user.Status, user.CreatedAt,
	))
	if isUniqueViolation(err) {
		return identity.User{}, identity.ErrConflict
	}
	if err != nil {
		return identity.User{}, fmt.Errorf("create user: %w", err)
	}
	return created, nil
}

func (r *UserRepository) Replace(ctx context.Context, user identity.User) (identity.User, error) {
	updated, err := scanUser(r.pool.QueryRow(ctx, `
		UPDATE users
		SET display_name = $2, email = $3, status = $4, updated_at = $5
		WHERE id = $1
		RETURNING id::text, username, display_name, email, status, created_at, updated_at`,
		user.ID, user.DisplayName, user.Email, user.Status, user.UpdatedAt,
	))
	if isUniqueViolation(err) {
		return identity.User{}, identity.ErrConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, fmt.Errorf("replace user: %w", err)
	}
	return updated, nil
}

func (r *UserRepository) SetPassword(ctx context.Context, userID, hash string, changedAt time.Time) error {
	command, err := r.pool.Exec(ctx, `
		INSERT INTO user_password_credentials (user_id, password_hash, changed_at, failed_attempts, locked_until)
		VALUES ($1, $2, $3, 0, NULL)
		ON CONFLICT (user_id) DO UPDATE
		SET password_hash = EXCLUDED.password_hash,
		    changed_at = EXCLUDED.changed_at,
		    failed_attempts = 0,
		    locked_until = NULL`,
		userID, hash, changedAt,
	)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if command.RowsAffected() == 0 {
		return identity.ErrNotFound
	}
	return nil
}

func (r *UserRepository) FindPasswordByUsername(ctx context.Context, username string) (identity.User, identity.PasswordCredential, error) {
	var user identity.User
	var credential identity.PasswordCredential
	var email pgtype.Text
	var lockedUntil pgtype.Timestamptz
	err := r.pool.QueryRow(ctx, `
		SELECT u.id::text, u.username, u.display_name, u.email, u.status, u.created_at, u.updated_at,
		       c.user_id::text, c.password_hash, c.failed_attempts, c.locked_until
		FROM users u
		JOIN user_password_credentials c ON c.user_id = u.id
		WHERE lower(u.username) = lower($1)`,
		username,
	).Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&email,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&credential.UserID,
		&credential.Hash,
		&credential.FailedAttempts,
		&lockedUntil,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, identity.PasswordCredential{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, identity.PasswordCredential{}, fmt.Errorf("find password credential: %w", err)
	}
	if email.Valid {
		user.Email = &email.String
	}
	if lockedUntil.Valid {
		value := lockedUntil.Time
		credential.LockedUntil = &value
	}
	return user, credential, nil
}

func (r *UserRepository) RecordPasswordFailure(ctx context.Context, userID string, _ time.Time, attempts int, lockedUntil time.Time) error {
	var value any
	if !lockedUntil.IsZero() {
		value = lockedUntil
	}
	command, err := r.pool.Exec(ctx, `
		UPDATE user_password_credentials
		SET failed_attempts = $2, locked_until = $3
		WHERE user_id = $1`,
		userID, attempts, value,
	)
	if err != nil {
		return fmt.Errorf("record password failure: %w", err)
	}
	if command.RowsAffected() == 0 {
		return identity.ErrNotFound
	}
	return nil
}

func (r *UserRepository) RecordPasswordSuccess(ctx context.Context, userID string, _ time.Time) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE user_password_credentials
		SET failed_attempts = 0, locked_until = NULL
		WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("record password success: %w", err)
	}
	if command.RowsAffected() == 0 {
		return identity.ErrNotFound
	}
	return nil
}

type userScanner interface {
	Scan(...any) error
}

func scanUser(scanner userScanner) (identity.User, error) {
	var user identity.User
	var email pgtype.Text
	if err := scanner.Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&email,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return identity.User{}, err
	}
	if email.Valid {
		user.Email = &email.String
	}
	return user, nil
}

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
