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
	"slices"
	"strings"
	"sync"
	"time"
)

var ErrSigningKeyNotFound = errors.New("signing key not found")

type KeyRepository interface {
	LoadActiveSigningKey(context.Context) ([]byte, error)
	SaveActiveSigningKey(context.Context, string, []byte, time.Time) error
	RotateSigningKey(context.Context, string, []byte, time.Time) error
	ListSigningKeys(context.Context) ([]SigningKey, error)
	DeleteRetiredSigningKeys(context.Context, time.Time) (int64, error)
}

type SigningKey struct {
	KID       string     `json:"kid"`
	PEM       []byte     `json:"-"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

type MemoryKeyRepository struct {
	mu   sync.RWMutex
	keys []SigningKey
}

func (r *MemoryKeyRepository) LoadActiveSigningKey(context.Context) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for index := len(r.keys) - 1; index >= 0; index-- {
		if r.keys[index].Active {
			return append([]byte(nil), r.keys[index].PEM...), nil
		}
	}
	return nil, ErrSigningKeyNotFound
}

func (r *MemoryKeyRepository) SaveActiveSigningKey(_ context.Context, kid string, value []byte, createdAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, current := range r.keys {
		if current.Active {
			return errors.New("active signing key already exists")
		}
	}
	r.keys = append(r.keys, SigningKey{
		KID: kid, PEM: append([]byte(nil), value...), Active: true, CreatedAt: createdAt,
	})
	return nil
}

func (r *MemoryKeyRepository) RotateSigningKey(_ context.Context, kid string, value []byte, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.keys {
		if r.keys[index].Active {
			r.keys[index].Active = false
			retiredAt := now
			r.keys[index].RetiredAt = &retiredAt
		}
	}
	r.keys = append(r.keys, SigningKey{
		KID: kid, PEM: append([]byte(nil), value...), Active: true, CreatedAt: now,
	})
	return nil
}

func (r *MemoryKeyRepository) ListSigningKeys(context.Context) ([]SigningKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]SigningKey, 0, len(r.keys))
	for _, value := range r.keys {
		result = append(result, cloneSigningKey(value))
	}
	return result, nil
}

func (r *MemoryKeyRepository) DeleteRetiredSigningKeys(_ context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.keys[:0]
	var count int64
	for _, value := range r.keys {
		if !value.Active && value.RetiredAt != nil && value.RetiredAt.Before(before) {
			count++
			continue
		}
		result = append(result, value)
	}
	r.keys = result
	return count, nil
}

type Signer struct {
	mu           sync.RWMutex
	key          *rsa.PrivateKey
	kid          string
	verification map[string]*rsa.PublicKey
	repository   KeyRepository
	lastRefresh  time.Time
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
			signer, parseErr := signerFromPEM(persisted)
			if parseErr != nil {
				return nil, parseErr
			}
			signer.repository = repository
			if reloadErr := signer.reloadVerificationKeys(ctx); reloadErr != nil {
				return nil, reloadErr
			}
			return signer, nil
		}
		signer := &Signer{key: key, kid: kid, repository: repository}
		if err := signer.reloadVerificationKeys(ctx); err != nil {
			return nil, err
		}
		return signer, nil
	}
	if err != nil {
		return nil, err
	}
	signer, err := signerFromPEM(encoded)
	if err != nil {
		return nil, err
	}
	signer.repository = repository
	if err := signer.reloadVerificationKeys(ctx); err != nil {
		return nil, err
	}
	return signer, nil
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
	return &Signer{
		key:          key,
		kid:          keyID(&key.PublicKey),
		verification: map[string]*rsa.PublicKey{keyID(&key.PublicKey): &key.PublicKey},
	}, nil
}

func (s *Signer) Sign(claims map[string]any) (string, error) {
	return s.SignTyped(claims, "JWT")
}

func (s *Signer) SignTyped(claims map[string]any, tokenType string) (string, error) {
	if tokenType == "" {
		return "", errors.New("signed token type is required")
	}
	s.refreshIfStale()
	s.mu.RLock()
	key := s.key
	kid := s.kid
	s.mu.RUnlock()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": tokenType})
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
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Signer) Verify(compact string) (map[string]any, error) {
	s.refreshIfStale()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid signed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid signed token header")
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil || header["alg"] != "RS256" {
		return nil, errors.New("unsupported signed token header")
	}
	s.mu.RLock()
	publicKey := s.verification[header["kid"]]
	s.mu.RUnlock()
	if publicKey == nil {
		if err := s.Refresh(context.Background()); err != nil {
			return nil, errors.New("unsupported signed token header")
		}
		s.mu.RLock()
		publicKey = s.verification[header["kid"]]
		s.mu.RUnlock()
		if publicKey == nil {
			return nil, errors.New("unsupported signed token header")
		}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signed token signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]map[string]string, 0, len(s.verification))
	for kid, publicKey := range s.verification {
		keys = append(keys, publicJWK(kid, publicKey))
	}
	slices.SortFunc(keys, func(a, b map[string]string) int {
		if a["kid"] == s.kid {
			return -1
		}
		if b["kid"] == s.kid {
			return 1
		}
		return strings.Compare(a["kid"], b["kid"])
	})
	return map[string]any{"keys": keys}
}

func (s *Signer) Refresh(ctx context.Context) error {
	encoded, err := s.repository.LoadActiveSigningKey(ctx)
	if err != nil {
		return err
	}
	active, err := signerFromPEM(encoded)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if active.kid != s.kid {
		s.key = active.key
		s.kid = active.kid
	}
	s.mu.Unlock()
	return s.reloadVerificationKeys(ctx)
}

func (s *Signer) Rotate(ctx context.Context) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate OIDC signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal OIDC signing key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	kid := keyID(&key.PublicKey)
	if err := s.repository.RotateSigningKey(ctx, kid, encoded, time.Now().UTC()); err != nil {
		return "", fmt.Errorf("rotate OIDC signing key: %w", err)
	}
	if err := s.Refresh(ctx); err != nil {
		return "", err
	}
	s.mu.RLock()
	activeKID := s.kid
	s.mu.RUnlock()
	return activeKID, nil
}

func (s *Signer) ListKeys(ctx context.Context) ([]SigningKey, error) {
	keys, err := s.repository.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	for index := range keys {
		keys[index].PEM = nil
	}
	return keys, nil
}

func (s *Signer) reloadVerificationKeys(ctx context.Context) error {
	keys, err := s.repository.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("list OIDC signing keys: %w", err)
	}
	verification := make(map[string]*rsa.PublicKey, len(keys))
	for _, value := range keys {
		parsed, err := signerFromPEM(value.PEM)
		if err != nil {
			return fmt.Errorf("parse OIDC signing key %s: %w", value.KID, err)
		}
		verification[value.KID] = &parsed.key.PublicKey
	}
	s.mu.Lock()
	s.verification = verification
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *Signer) refreshIfStale() {
	s.mu.RLock()
	stale := time.Since(s.lastRefresh) >= 30*time.Second
	s.mu.RUnlock()
	if stale {
		_ = s.Refresh(context.Background())
	}
}

func publicJWK(kid string, publicKey *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}

func cloneSigningKey(value SigningKey) SigningKey {
	value.PEM = append([]byte(nil), value.PEM...)
	if value.RetiredAt != nil {
		retiredAt := *value.RetiredAt
		value.RetiredAt = &retiredAt
	}
	return value
}

func keyID(key *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(key)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
