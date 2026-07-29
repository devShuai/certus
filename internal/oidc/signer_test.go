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
