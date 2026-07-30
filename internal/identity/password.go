package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"certus/internal/security"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrCredentialLocked   = errors.New("credential temporarily locked")
	ErrInvalidResetToken  = errors.New("invalid or expired password reset token")
)

const (
	passwordMemory  = 64 * 1024
	passwordTime    = 3
	passwordThreads = 4
	passwordKeyLen  = 32
	passwordSaltLen = 16
)

type PasswordCredential struct {
	UserID         string
	Hash           string
	FailedAttempts int
	LockedUntil    *time.Time
}

type PasswordRepository interface {
	SetPassword(context.Context, string, string, time.Time) error
	FindPasswordByUsername(context.Context, string) (User, PasswordCredential, error)
	RecordPasswordFailure(context.Context, string, time.Time, int, time.Time) error
	RecordPasswordSuccess(context.Context, string, time.Time) error
}

type PasswordResetToken struct {
	UserID    string
	Hash      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

type PasswordResetRepository interface {
	SavePasswordReset(context.Context, PasswordResetToken) error
	ConsumePasswordReset(context.Context, []byte, time.Time) (string, error)
}

type PasswordService struct {
	repository PasswordRepository
	resets     PasswordResetRepository
	now        func() time.Time
}

func NewPasswordService(repository PasswordRepository) *PasswordService {
	resets, _ := repository.(PasswordResetRepository)
	return &PasswordService{repository: repository, resets: resets, now: time.Now}
}

func (s *PasswordService) Set(ctx context.Context, userID, password string) error {
	hash, err := validateAndHashPassword(password)
	if err != nil {
		return err
	}
	return s.repository.SetPassword(ctx, userID, hash, s.now().UTC())
}

func (s *PasswordService) Change(ctx context.Context, userID, username, currentPassword, newPassword string) error {
	user, err := s.Authenticate(ctx, username, currentPassword)
	if err != nil || user.ID != userID {
		return ErrInvalidCredentials
	}
	return s.Set(ctx, userID, newPassword)
}

func (s *PasswordService) IssueReset(ctx context.Context, userID string, lifetime time.Duration) (string, error) {
	if s.resets == nil {
		return "", errors.New("password reset repository is unavailable")
	}
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	if err := s.resets.SavePasswordReset(ctx, PasswordResetToken{
		UserID:    userID,
		Hash:      security.HashToken(raw),
		CreatedAt: now,
		ExpiresAt: now.Add(lifetime),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *PasswordService) Reset(ctx context.Context, token, newPassword string) (string, error) {
	if s.resets == nil || strings.TrimSpace(token) == "" {
		return "", ErrInvalidResetToken
	}
	hash, err := validateAndHashPassword(newPassword)
	if err != nil {
		return "", err
	}
	userID, err := s.resets.ConsumePasswordReset(ctx, security.HashToken(token), s.now().UTC())
	if err != nil {
		return "", ErrInvalidResetToken
	}
	if err := s.repository.SetPassword(ctx, userID, hash, s.now().UTC()); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *PasswordService) Authenticate(ctx context.Context, username, password string) (User, error) {
	now := s.now().UTC()
	user, credential, err := s.repository.FindPasswordByUsername(ctx, strings.ToLower(strings.TrimSpace(username)))
	if err != nil {
		// Run the KDF even for unknown users to reduce username timing leakage.
		_, _ = verifyPassword(
			"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$UiS2jdoWvtJdnDWubZvht9mXZ3ImaK0dx94kBqj3NXk",
			password,
		)
		return User{}, ErrInvalidCredentials
	}
	if user.Status != UserActive {
		return User{}, ErrInvalidCredentials
	}
	if credential.LockedUntil != nil && credential.LockedUntil.After(now) {
		return User{}, ErrCredentialLocked
	}
	ok, upgrade, err := verifyStoredPassword(credential.Hash, password, now)
	if err != nil {
		return User{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		attempts := credential.FailedAttempts + 1
		lockedUntil := time.Time{}
		if attempts >= 5 {
			lockedUntil = now.Add(15 * time.Minute)
		}
		_ = s.repository.RecordPasswordFailure(ctx, credential.UserID, now, attempts, lockedUntil)
		if !lockedUntil.IsZero() {
			return User{}, ErrCredentialLocked
		}
		return User{}, ErrInvalidCredentials
	}
	if upgrade {
		hash, err := hashPassword(password)
		if err != nil {
			return User{}, fmt.Errorf("upgrade migrated password: %w", err)
		}
		if err := s.repository.SetPassword(ctx, credential.UserID, hash, now); err != nil {
			return User{}, fmt.Errorf("persist migrated password upgrade: %w", err)
		}
		return user, nil
	}
	if err := s.repository.RecordPasswordSuccess(ctx, credential.UserID, now); err != nil {
		return User{}, fmt.Errorf("record password success: %w", err)
	}
	return user, nil
}

func verifyStoredPassword(encoded, password string, now time.Time) (bool, bool, error) {
	if strings.HasPrefix(encoded, "$legacy$") {
		ok, err := verifyMigratedPassword(encoded, password, now)
		return ok, ok, err
	}
	ok, err := verifyPassword(encoded, password)
	return ok, false, err
}

func verifyMigratedPassword(encoded, password string, now time.Time) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 ||
		parts[0] != "" ||
		parts[1] != "legacy" ||
		parts[2] != string(PasswordMigrationSpecusSHA256) {
		return false, errors.New("invalid migrated password hash")
	}
	expiresAt, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || expiresAt <= 0 {
		return false, errors.New("invalid migrated password expiry")
	}
	if !now.UTC().Before(time.Unix(expiresAt, 0).UTC()) {
		return false, nil
	}
	expected, err := hex.DecodeString(parts[4])
	if err != nil || len(expected) != sha256.Size || len(parts[4]) != sha256.Size*2 {
		return false, errors.New("invalid migrated password digest")
	}
	actual := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(actual[:], expected) == 1, nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, passwordThreads, passwordKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		passwordMemory,
		passwordTime,
		passwordThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func validateAndHashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("password must contain 12-1024 characters")
	}
	return hashPassword(password)
}

func verifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return false, errors.New("invalid argon2 parameters")
	}
	memory, err := parseArgon2Parameter(parameters[0], "m")
	if err != nil {
		return false, err
	}
	iterations, err := parseArgon2Parameter(parameters[1], "t")
	if err != nil {
		return false, err
	}
	threads, err := parseArgon2Parameter(parameters[2], "p")
	if err != nil || threads > 255 {
		return false, errors.New("invalid argon2 threads")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, errors.New("invalid argon2 salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 {
		return false, errors.New("invalid argon2 key")
	}
	if memory > 256*1024 || iterations > 10 || threads == 0 {
		return false, errors.New("unsafe argon2 parameters")
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parseArgon2Parameter(value, name string) (uint64, error) {
	prefix := name + "="
	if !strings.HasPrefix(value, prefix) {
		return 0, errors.New("invalid argon2 parameters")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	if err != nil || parsed == 0 {
		return 0, errors.New("invalid argon2 parameters")
	}
	return parsed, nil
}
