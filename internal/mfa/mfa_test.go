package mfa

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"testing"
	"time"
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

func base32NoPaddingDecode(value string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(value)
}
