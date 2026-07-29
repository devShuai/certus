package mfa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotFound       = errors.New("MFA credential not found")
	ErrUnavailable    = errors.New("MFA encryption key is unavailable")
	ErrInvalidCode    = errors.New("invalid MFA code")
	ErrLocked         = errors.New("MFA verification is temporarily locked")
	ErrReplay         = errors.New("MFA code has already been used")
	ErrAlreadyEnabled = errors.New("MFA is already enabled")
)

const (
	totpPeriod        = int64(30)
	totpDigits        = 6
	recoveryCodeCount = 10
)

var totpCodePattern = regexp.MustCompile(`^[0-9]{6}$`)

type Credential struct {
	UserID         string
	Secret         []byte
	Enabled        bool
	CreatedAt      time.Time
	VerifiedAt     *time.Time
	LastUsedStep   int64
	FailedAttempts int
	LockedUntil    *time.Time
	RecoveryCodes  int
}

type Status struct {
	Available     bool       `json:"available"`
	Enabled       bool       `json:"enabled"`
	Pending       bool       `json:"pending"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	RecoveryCodes int        `json:"recovery_codes"`
}

type Setup struct {
	Secret        string   `json:"secret"`
	OTPAuthURI    string   `json:"otpauth_uri"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type Repository interface {
	Find(context.Context, string) (Credential, error)
	ReplacePending(context.Context, Credential, [][]byte) error
	Enable(context.Context, string, int64, time.Time) error
	UseTOTP(context.Context, string, int64, time.Time) error
	UseRecoveryCode(context.Context, string, []byte, time.Time) error
	RecordFailure(context.Context, string, int, *time.Time) error
	Delete(context.Context, string) error
}

type Service struct {
	repository Repository
	key        []byte
	issuer     string
	now        func() time.Time
}

func NewService(repository Repository, encryptionKey []byte, issuer string) *Service {
	return &Service{
		repository: repository,
		key:        append([]byte(nil), encryptionKey...),
		issuer:     strings.TrimSpace(issuer),
		now:        time.Now,
	}
}

func (s *Service) Status(ctx context.Context, userID string) (Status, error) {
	credential, err := s.repository.Find(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return Status{Available: s.available()}, nil
	}
	if err != nil {
		return Status{}, err
	}
	return Status{
		Available:     s.available(),
		Enabled:       credential.Enabled,
		Pending:       !credential.Enabled,
		VerifiedAt:    credential.VerifiedAt,
		RecoveryCodes: credential.RecoveryCodes,
	}, nil
}

func (s *Service) RequiresChallenge(ctx context.Context, userID string) (bool, error) {
	credential, err := s.repository.Find(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !credential.Enabled {
		return false, nil
	}
	if !s.available() {
		return false, ErrUnavailable
	}
	return true, nil
}

func (s *Service) Setup(ctx context.Context, userID, username string) (Setup, error) {
	if !s.available() {
		return Setup{}, ErrUnavailable
	}
	if credential, err := s.repository.Find(ctx, userID); err == nil && credential.Enabled {
		return Setup{}, ErrAlreadyEnabled
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return Setup{}, err
	}
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return Setup{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	encrypted, err := s.encrypt(userID, secret)
	if err != nil {
		return Setup{}, err
	}
	recoveryCodes := make([]string, 0, recoveryCodeCount)
	recoveryHashes := make([][]byte, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		code, err := newRecoveryCode()
		if err != nil {
			return Setup{}, err
		}
		recoveryCodes = append(recoveryCodes, code)
		recoveryHashes = append(recoveryHashes, hashRecoveryCode(code))
	}
	now := s.now().UTC()
	if err := s.repository.ReplacePending(ctx, Credential{
		UserID:    userID,
		Secret:    encrypted,
		CreatedAt: now,
	}, recoveryHashes); err != nil {
		return Setup{}, err
	}
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	label := s.issuer + ":" + username
	query := url.Values{
		"secret":    {encodedSecret},
		"issuer":    {s.issuer},
		"algorithm": {"SHA1"},
		"digits":    {"6"},
		"period":    {"30"},
	}
	return Setup{
		Secret:        encodedSecret,
		OTPAuthURI:    "otpauth://totp/" + url.PathEscape(label) + "?" + query.Encode(),
		RecoveryCodes: recoveryCodes,
	}, nil
}

func (s *Service) Enable(ctx context.Context, userID, code string) error {
	credential, err := s.repository.Find(ctx, userID)
	if err != nil {
		return err
	}
	if credential.Enabled {
		return nil
	}
	step, err := s.matchTOTP(credential, code)
	if err != nil {
		return err
	}
	return s.repository.Enable(ctx, userID, step, s.now().UTC())
}

func (s *Service) Verify(ctx context.Context, userID, code string) error {
	credential, err := s.repository.Find(ctx, userID)
	if err != nil {
		return ErrInvalidCode
	}
	if !credential.Enabled {
		return ErrInvalidCode
	}
	now := s.now().UTC()
	if credential.LockedUntil != nil && credential.LockedUntil.After(now) {
		return ErrLocked
	}
	normalized := normalizeCode(code)
	if totpCodePattern.MatchString(normalized) {
		step, matchErr := s.matchTOTP(credential, normalized)
		if matchErr == nil {
			if err := s.repository.UseTOTP(ctx, userID, step, now); err == nil {
				return nil
			} else if errors.Is(err, ErrReplay) {
				return ErrReplay
			} else {
				return err
			}
		}
		if errors.Is(matchErr, ErrReplay) {
			return ErrReplay
		}
	} else if len(normalized) >= 20 {
		if err := s.repository.UseRecoveryCode(ctx, userID, hashRecoveryCode(normalized), now); err == nil {
			return nil
		} else if !errors.Is(err, ErrInvalidCode) {
			return err
		}
	}
	attempts := credential.FailedAttempts + 1
	var lockedUntil *time.Time
	if attempts >= 5 {
		delay := time.Duration(min(attempts-4, 12)) * 5 * time.Minute
		value := now.Add(delay)
		lockedUntil = &value
	}
	if err := s.repository.RecordFailure(ctx, userID, attempts, lockedUntil); err != nil {
		return err
	}
	if lockedUntil != nil {
		return ErrLocked
	}
	return ErrInvalidCode
}

func (s *Service) Disable(ctx context.Context, userID string) error {
	return s.repository.Delete(ctx, userID)
}

func (s *Service) matchTOTP(credential Credential, code string) (int64, error) {
	if !s.available() {
		return 0, ErrUnavailable
	}
	secret, err := s.decrypt(credential.UserID, credential.Secret)
	if err != nil {
		return 0, err
	}
	nowStep := s.now().UTC().Unix() / totpPeriod
	for _, step := range []int64{nowStep, nowStep - 1, nowStep + 1} {
		expected := generateTOTP(secret, step)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(normalizeCode(code))) == 1 {
			if step <= credential.LastUsedStep {
				return 0, ErrReplay
			}
			return step, nil
		}
	}
	return 0, ErrInvalidCode
}

func (s *Service) available() bool {
	return len(s.key) == 32
}

func (s *Service) encrypt(userID string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(userID)), nil
}

func (s *Service) decrypt(userID string, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrUnavailable
	}
	nonce := ciphertext[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], []byte(userID))
	if err != nil {
		return nil, ErrUnavailable
	}
	return plaintext, nil
}

func generateTOTP(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, value%1_000_000)
}

func newRecoveryCode() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate recovery code: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value)
	groups := make([]string, 0, (len(encoded)+4)/5)
	for len(encoded) > 0 {
		size := min(5, len(encoded))
		groups = append(groups, encoded[:size])
		encoded = encoded[size:]
	}
	return strings.Join(groups, "-"), nil
}

func hashRecoveryCode(code string) []byte {
	sum := sha256.Sum256([]byte("certus:mfa:recovery:" + normalizeCode(code)))
	return sum[:]
}

func normalizeCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.NewReplacer("-", "", " ", "").Replace(code)
	return code
}

func DecodeEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		value, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil || len(value) != 32 {
		return nil, errors.New("MFA encryption key must be base64-encoded 32 bytes")
	}
	return value, nil
}
