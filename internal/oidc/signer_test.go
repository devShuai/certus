package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignerPersistsKeyAndProducesVerifiableJWT(t *testing.T) {
	repository := &MemoryKeyRepository{}
	signer, err := NewSigner(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(map[string]any{"iss": "https://auth.example.com", "sub": "user"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid compact JWT: %s", token)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&signer.key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("JWT signature is invalid: %v", err)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "RS256" || header["kid"] != signer.kid {
		t.Fatalf("unexpected JWT header: %#v", header)
	}
	reloaded, err := NewSigner(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.kid != signer.kid {
		t.Fatalf("signing key was not persisted: %s != %s", reloaded.kid, signer.kid)
	}
}

func TestSignerSupportsExplicitTokenTypes(t *testing.T) {
	signer, err := NewSigner(context.Background(), &MemoryKeyRepository{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.SignTyped(map[string]any{"events": map[string]any{}}, "logout+jwt")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["typ"] != "logout+jwt" {
		t.Fatalf("unexpected explicit token type: %#v", header)
	}
}

func TestSignerRotationKeepsRetiredVerificationKey(t *testing.T) {
	ctx := context.Background()
	repository := &MemoryKeyRepository{}
	signer, err := NewSigner(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := signer.Sign(map[string]any{"purpose": "rotation-test"})
	if err != nil {
		t.Fatal(err)
	}
	oldKID := signer.kid
	newKID, err := signer.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if newKID == oldKID {
		t.Fatal("rotation did not replace the active key")
	}
	if _, err := signer.Verify(oldToken); err != nil {
		t.Fatalf("retired key no longer verifies an unexpired token: %v", err)
	}
	keys, _ := signer.JWKS()["keys"].([]map[string]string)
	if len(keys) != 2 || keys[0]["kid"] != newKID {
		t.Fatalf("JWKS does not publish active and retired keys: %#v", keys)
	}
}

func TestSignerAutomaticallyRotatesOnlyStaleKey(t *testing.T) {
	ctx := context.Background()
	repository := &MemoryKeyRepository{}
	signer, err := NewSigner(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	repository.mu.Lock()
	repository.keys[0].CreatedAt = now.Add(-25 * time.Hour)
	oldKID := repository.keys[0].KID
	repository.mu.Unlock()
	newKID, rotated, err := signer.RotateIfOlderThan(ctx, 24*time.Hour, now)
	if err != nil || !rotated || newKID == oldKID {
		t.Fatalf("stale signing key was not rotated: %s %v %v", newKID, rotated, err)
	}
	again, rotated, err := signer.RotateIfOlderThan(ctx, 24*time.Hour, now.Add(time.Minute))
	if err != nil || rotated || again != newKID {
		t.Fatalf("fresh signing key rotated again: %s %v %v", again, rotated, err)
	}
}
