package identity

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type PasswordMigrationAlgorithm string

const (
	PasswordMigrationSpecusSHA256 PasswordMigrationAlgorithm = "specus_sha256"

	defaultPasswordMigrationLifetime = 90 * 24 * time.Hour
	maxPasswordMigrationLifetime     = 365 * 24 * time.Hour
	maxPasswordMigrationUsers        = 1000
)

type PasswordMigrationUser struct {
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	Email        *string    `json:"email"`
	Status       UserStatus `json:"status"`
	PasswordHash string     `json:"password_hash"`
}

type ImportPasswordUsers struct {
	Algorithm PasswordMigrationAlgorithm `json:"password_algorithm"`
	ExpiresAt *time.Time                 `json:"expires_at,omitempty"`
	Users     []PasswordMigrationUser    `json:"users"`
}

type PasswordMigrationResult struct {
	Items     []User    `json:"items"`
	Count     int       `json:"count"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PasswordMigrationRecord struct {
	User         User
	PasswordHash string
}

type PasswordMigrationRepository interface {
	CreateWithMigratedPasswords(
		context.Context,
		[]PasswordMigrationRecord,
		time.Time,
	) ([]User, error)
}

type PasswordMigrationService struct {
	repository PasswordMigrationRepository
	now        func() time.Time
}

func NewPasswordMigrationService(repository PasswordMigrationRepository) *PasswordMigrationService {
	return &PasswordMigrationService{repository: repository, now: time.Now}
}

func (s *PasswordMigrationService) Import(
	ctx context.Context,
	input ImportPasswordUsers,
) (PasswordMigrationResult, error) {
	if input.Algorithm != PasswordMigrationSpecusSHA256 {
		return PasswordMigrationResult{}, fmt.Errorf(
			"%w: password_algorithm must be %q",
			ErrInvalid,
			PasswordMigrationSpecusSHA256,
		)
	}
	if len(input.Users) == 0 || len(input.Users) > maxPasswordMigrationUsers {
		return PasswordMigrationResult{}, fmt.Errorf(
			"%w: users must contain 1-%d entries",
			ErrInvalid,
			maxPasswordMigrationUsers,
		)
	}
	now := s.now().UTC()
	expiresAt := now.Add(defaultPasswordMigrationLifetime)
	if input.ExpiresAt != nil {
		expiresAt = input.ExpiresAt.UTC()
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(maxPasswordMigrationLifetime)) {
		return PasswordMigrationResult{}, fmt.Errorf(
			"%w: expires_at must be in the future and no more than 365 days away",
			ErrInvalid,
		)
	}

	records := make([]PasswordMigrationRecord, 0, len(input.Users))
	usernames := make(map[string]struct{}, len(input.Users))
	emails := make(map[string]struct{}, len(input.Users))
	for _, item := range input.Users {
		user, err := NewUser(CreateUser{
			Username:    item.Username,
			DisplayName: item.DisplayName,
			Email:       item.Email,
			Status:      item.Status,
		}, now)
		if err != nil {
			return PasswordMigrationResult{}, err
		}
		if _, duplicate := usernames[user.Username]; duplicate {
			return PasswordMigrationResult{}, fmt.Errorf(
				"%w: duplicate username in migration",
				ErrConflict,
			)
		}
		usernames[user.Username] = struct{}{}
		if user.Email != nil {
			if _, duplicate := emails[*user.Email]; duplicate {
				return PasswordMigrationResult{}, fmt.Errorf(
					"%w: duplicate email in migration",
					ErrConflict,
				)
			}
			emails[*user.Email] = struct{}{}
		}
		encoded, err := encodeMigratedPassword(input.Algorithm, item.PasswordHash, expiresAt)
		if err != nil {
			return PasswordMigrationResult{}, err
		}
		records = append(records, PasswordMigrationRecord{
			User:         user,
			PasswordHash: encoded,
		})
	}
	created, err := s.repository.CreateWithMigratedPasswords(ctx, records, now)
	if err != nil {
		return PasswordMigrationResult{}, err
	}
	return PasswordMigrationResult{
		Items:     created,
		Count:     len(created),
		ExpiresAt: expiresAt,
	}, nil
}

func encodeMigratedPassword(
	algorithm PasswordMigrationAlgorithm,
	hash string,
	expiresAt time.Time,
) (string, error) {
	if algorithm != PasswordMigrationSpecusSHA256 {
		return "", fmt.Errorf("%w: unsupported password migration algorithm", ErrInvalid)
	}
	hash = strings.ToLower(strings.TrimSpace(hash))
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != 32 || len(hash) != 64 {
		return "", fmt.Errorf("%w: password_hash must be a 64-character SHA-256 hex digest", ErrInvalid)
	}
	return fmt.Sprintf(
		"$legacy$%s$%s$%s",
		algorithm,
		strconv.FormatInt(expiresAt.UTC().Unix(), 10),
		hash,
	), nil
}
