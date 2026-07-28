package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS certus_schema_migrations (
			version text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	slices.Sort(entries)
	for _, name := range entries {
		content, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		sum := sha256.Sum256(content)
		checksum := hex.EncodeToString(sum[:])
		if err := applyMigration(ctx, pool, name, checksum, string(content)); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, pool *pgxpool.Pool, version, checksum, statement string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(741924573)"); err != nil {
		return fmt.Errorf("lock migration %s: %w", version, err)
	}
	var existing string
	err = tx.QueryRow(ctx, "SELECT checksum FROM certus_schema_migrations WHERE version = $1", version).Scan(&existing)
	switch {
	case err == nil && existing != checksum:
		return fmt.Errorf("migration %s checksum changed", version)
	case err == nil:
		return tx.Commit(ctx)
	case err != pgx.ErrNoRows:
		return fmt.Errorf("check migration %s: %w", version, err)
	}

	if _, err := tx.Exec(ctx, statement); err != nil {
		return fmt.Errorf("apply migration %s: %w", version, err)
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO certus_schema_migrations (version, checksum) VALUES ($1, $2)",
		version, checksum,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", version, err)
	}
	return nil
}
