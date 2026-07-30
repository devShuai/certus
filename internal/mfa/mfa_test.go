package mfa

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"certus/internal/secrets"
)

func TestRFC6238SHA1Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, vector := range vectors {
		if actual := generateTOTP(secret, vector.unix/30); actual != vector.code {
			t.Fatalf("TOTP at %d: got %s, want %s", vector.unix, actual, vector.code)
		}
	}
}

func TestSetupEnableVerifyReplayAndRecovery(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	repository := NewMemoryRepository()
	service := NewService(repository, key, "Certus")
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	setup, err := service.Setup(context.Background(), "user-1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32NoPaddingDecode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := generateTOTP(secret, now.Unix()/30)
	if err := service.Enable(context.Background(), "user-1", code); err != nil {
		t.Fatal(err)
	}
	if err := service.Verify(context.Background(), "user-1", code); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	now = now.Add(30 * time.Second)
	if err := service.Verify(context.Background(), "user-1", generateTOTP(secret, now.Unix()/30)); err != nil {
		t.Fatal(err)
	}
	if err := service.Verify(context.Background(), "user-1", setup.RecoveryCodes[0]); err != nil {
		t.Fatal(err)
	}
	if err := service.Verify(context.Background(), "user-1", setup.RecoveryCodes[0]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected consumed recovery code rejection, got %v", err)
	}
}

func TestRewrapLegacySecretAndRotateKeyRing(t *testing.T) {
	ctx := context.Background()
	legacyKey := []byte("legacy-mfa-key-material-32-bytes")
	repository := NewMemoryRepository()
	legacyService := NewService(repository, legacyKey, "Certus")
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	legacyService.now = func() time.Time { return now }
	setup, err := legacyService.Setup(ctx, "user-1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	before, err := repository.Find(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, versioned := secrets.EnvelopeKeyID(before.Secret); versioned {
		t.Fatal("legacy MFA secret unexpectedly used a versioned envelope")
	}

	primaryKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	keyRing, err := secrets.ParseKeyRing("primary=" + primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := RewrapSecrets(ctx, repository, keyRing, legacyKey); err != nil || count != 1 {
		t.Fatalf("rewrap legacy MFA secret: count=%d err=%v", count, err)
	}
	rewrapped, err := repository.Find(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if keyID, ok := secrets.EnvelopeKeyID(rewrapped.Secret); !ok || keyID != "primary" {
		t.Fatalf("unexpected rewrapped MFA envelope key: %q, %v", keyID, ok)
	}

	primaryService := NewServiceWithKeyRing(repository, keyRing, nil, "Certus")
	primaryService.now = func() time.Time { return now }
	secret, err := base32NoPaddingDecode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := primaryService.Enable(ctx, "user-1", generateTOTP(secret, now.Unix()/30)); err != nil {
		t.Fatalf("verify rewrapped MFA secret: %v", err)
	}

	nextKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	rotatedRing, err := secrets.ParseKeyRing("next=" + nextKey + ",primary=" + primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := RewrapSecrets(ctx, repository, rotatedRing, nil); err != nil || count != 1 {
		t.Fatalf("rotate MFA secret envelope: count=%d err=%v", count, err)
	}
	rotated, err := repository.Find(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if keyID, ok := secrets.EnvelopeKeyID(rotated.Secret); !ok || keyID != "next" {
		t.Fatalf("unexpected rotated MFA envelope key: %q, %v", keyID, ok)
	}
	now = now.Add(30 * time.Second)
	rotatedService := NewServiceWithKeyRing(repository, rotatedRing, nil, "Certus")
	rotatedService.now = func() time.Time { return now }
	if err := rotatedService.Verify(ctx, "user-1", generateTOTP(secret, now.Unix()/30)); err != nil {
		t.Fatalf("verify rotated MFA secret: %v", err)
	}
	if count, err := RewrapSecrets(ctx, repository, rotatedRing, nil); err != nil || count != 0 {
		t.Fatalf("idempotent MFA rewrap: count=%d err=%v", count, err)
	}
}

func TestRewrapLegacySecretRequiresLegacyKey(t *testing.T) {
	ctx := context.Background()
	legacyKey := []byte("legacy-mfa-key-material-32-bytes")
	repository := NewMemoryRepository()
	service := NewService(repository, legacyKey, "Certus")
	if _, err := service.Setup(ctx, "user-1", "alice"); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	keyRing, err := secrets.ParseKeyRing("primary=" + key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RewrapSecrets(ctx, repository, keyRing, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected missing legacy key error, got %v", err)
	}
}

func base32NoPaddingDecode(value string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(value)
}
