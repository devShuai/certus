package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrCredentialLocked   = errors.New("credential temporarily locked")
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

type PasswordService struct {
	repository PasswordRepository
	now        func() time.Time
}

func NewPasswordService(repository PasswordRepository) *PasswordService {
	return &PasswordService{repository: repository, now: time.Now}
}

func (s *PasswordService) Set(ctx context.Context, userID, password string) error {
	if len(password) < 12 || len(password) > 1024 {
		return errors.New("password must contain 12-1024 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return s.repository.SetPassword(ctx, userID, hash, s.now().UTC())
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
	ok, err := verifyPassword(credential.Hash, password)
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
	if err := s.repository.RecordPasswordSuccess(ctx, credential.UserID, now); err != nil {
		return User{}, fmt.Errorf("record password success: %w", err)
	}
	return user, nil
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
