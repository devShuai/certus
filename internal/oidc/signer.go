package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var ErrSigningKeyNotFound = errors.New("signing key not found")

type KeyRepository interface {
	LoadActiveSigningKey(context.Context) ([]byte, error)
	SaveActiveSigningKey(context.Context, string, []byte, time.Time) error
}

type MemoryKeyRepository struct {
	pem []byte
}

func (r *MemoryKeyRepository) LoadActiveSigningKey(context.Context) ([]byte, error) {
	if len(r.pem) == 0 {
		return nil, ErrSigningKeyNotFound
	}
	return append([]byte(nil), r.pem...), nil
}

func (r *MemoryKeyRepository) SaveActiveSigningKey(_ context.Context, _ string, value []byte, _ time.Time) error {
	r.pem = append([]byte(nil), value...)
	return nil
}

type Signer struct {
	key *rsa.PrivateKey
	kid string
}

func NewSigner(ctx context.Context, repository KeyRepository) (*Signer, error) {
	encoded, err := repository.LoadActiveSigningKey(ctx)
	if errors.Is(err, ErrSigningKeyNotFound) {
		key, generateErr := rsa.GenerateKey(rand.Reader, 2048)
		if generateErr != nil {
			return nil, fmt.Errorf("generate OIDC signing key: %w", generateErr)
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal OIDC signing key: %w", marshalErr)
		}
		encoded = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		kid := keyID(&key.PublicKey)
		if saveErr := repository.SaveActiveSigningKey(ctx, kid, encoded, time.Now().UTC()); saveErr != nil {
			// Another instance may have created the first active key while this
			// process was generating one. In that case, converge on the key that
			// won the database uniqueness race.
			persisted, loadErr := repository.LoadActiveSigningKey(ctx)
			if loadErr != nil {
				return nil, fmt.Errorf("save OIDC signing key: %w", saveErr)
			}
			return signerFromPEM(persisted)
		}
		return &Signer{key: key, kid: kid}, nil
	}
	if err != nil {
		return nil, err
	}
	return signerFromPEM(encoded)
}

func signerFromPEM(encoded []byte) (*Signer, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("invalid OIDC signing key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, errors.New("OIDC signing key must be RSA with at least 2048 bits")
	}
	return &Signer{key: key, kid: keyID(&key.PublicKey)}, nil
}

func (s *Signer) Sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": s.kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Signer) Verify(compact string) (map[string]any, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid signed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid signed token header")
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil || header["alg"] != "RS256" || header["kid"] != s.kid {
		return nil, errors.New("unsupported signed token header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signed token signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("invalid signed token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid signed token payload")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("invalid signed token claims")
	}
	return claims, nil
}

func (s *Signer) JWKS() map[string]any {
	publicKey := &s.key.PublicKey
	return map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": s.kid,
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}}}
}

func keyID(key *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(key)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
