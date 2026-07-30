package secrets

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestKeyRingEncryptDecryptAndRotatePrimary(t *testing.T) {
	oldKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	newKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	oldRing, err := ParseKeyRing("old=" + oldKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, keyID, err := oldRing.Encrypt("oidc-signing-key", "kid-1", []byte("private-key"))
	if err != nil || keyID != "old" || strings.Contains(string(envelope), "private-key") {
		t.Fatalf("secret was not encrypted: %q %s %v", envelope, keyID, err)
	}
	rotated, err := ParseKeyRing("new=" + newKey + ",old=" + oldKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rotated.Decrypt("oidc-signing-key", "kid-1", envelope, "old")
	if err != nil || string(plaintext) != "private-key" {
		t.Fatalf("old key could not decrypt after primary rotation: %q %v", plaintext, err)
	}
	nextEnvelope, nextKeyID, err := rotated.Encrypt("oidc-signing-key", "kid-1", plaintext)
	if err != nil || nextKeyID != "new" {
		t.Fatalf("new primary was not used: %s %v", nextKeyID, err)
	}
	if _, err := rotated.Decrypt("oidc-signing-key", "other-kid", nextEnvelope, "new"); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("record-bound envelope was accepted for another record: %v", err)
	}
}

func TestKeyRingRejectsMalformedConfigurationAndEnvelope(t *testing.T) {
	for _, value := range []string{
		"missing-separator",
		"bad id=" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"one=" + base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"one=" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + ",one=" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
	} {
		if _, err := ParseKeyRing(value); err == nil {
			t.Fatalf("invalid key ring was accepted: %q", value)
		}
	}
	ring, err := ParseKeyRing("one=" + base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Decrypt("purpose", "record", []byte("plaintext"), ""); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("plaintext was accepted as an envelope: %v", err)
	}
}
