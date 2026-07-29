package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
