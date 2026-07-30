package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrUnavailable     = errors.New("secret encryption key ring is unavailable")
	ErrInvalidEnvelope = errors.New("invalid encrypted secret envelope")
)

const envelopePrefix = "certus-secret-v1."

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

type KeyRing struct {
	primaryID string
	keys      map[string][]byte
}

func ParseKeyRing(specification string) (KeyRing, error) {
	specification = strings.TrimSpace(specification)
	if specification == "" {
		return KeyRing{}, nil
	}
	result := KeyRing{keys: make(map[string][]byte)}
	for index, entry := range strings.Split(specification, ",") {
		keyID, encoded, ok := strings.Cut(strings.TrimSpace(entry), "=")
		keyID = strings.TrimSpace(keyID)
		encoded = strings.TrimSpace(encoded)
		if !ok || !keyIDPattern.MatchString(keyID) || encoded == "" {
			return KeyRing{}, fmt.Errorf("invalid key ring entry %q", entry)
		}
		if _, duplicate := result.keys[keyID]; duplicate {
			return KeyRing{}, fmt.Errorf("duplicate key ring identifier %q", keyID)
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return KeyRing{}, fmt.Errorf("key ring entry %q must contain a Base64-encoded 32-byte key", keyID)
		}
		result.keys[keyID] = append([]byte(nil), key...)
		if index == 0 {
			result.primaryID = keyID
		}
	}
	return result, nil
}

func (k KeyRing) Available() bool {
	return k.primaryID != "" && len(k.keys[k.primaryID]) == 32
}

func (k KeyRing) PrimaryID() string {
	return k.primaryID
}

func (k KeyRing) Encrypt(purpose, recordID string, plaintext []byte) ([]byte, string, error) {
	if !k.Available() {
		return nil, "", ErrUnavailable
	}
	block, err := aes.NewCipher(k.keys[k.primaryID])
	if err != nil {
		return nil, "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("generate secret encryption nonce: %w", err)
	}
	payload := aead.Seal(nonce, nonce, plaintext, envelopeAAD(purpose, recordID, k.primaryID))
	envelope := envelopePrefix + k.primaryID + "." + base64.RawURLEncoding.EncodeToString(payload)
	return []byte(envelope), k.primaryID, nil
}

func (k KeyRing) Decrypt(
	purpose, recordID string,
	envelope []byte,
	expectedKeyID string,
) ([]byte, error) {
	keyID, payload, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if expectedKeyID != "" && expectedKeyID != keyID {
		return nil, ErrInvalidEnvelope
	}
	key := k.keys[keyID]
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key %q is not configured", ErrUnavailable, keyID)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(
		nil,
		payload[:aead.NonceSize()],
		payload[aead.NonceSize():],
		envelopeAAD(purpose, recordID, keyID),
	)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

func EnvelopeKeyID(envelope []byte) (string, bool) {
	keyID, _, err := parseEnvelope(envelope)
	return keyID, err == nil
}

func parseEnvelope(envelope []byte) (string, []byte, error) {
	value := string(envelope)
	if !strings.HasPrefix(value, envelopePrefix) {
		return "", nil, ErrInvalidEnvelope
	}
	keyID, encoded, ok := strings.Cut(strings.TrimPrefix(value, envelopePrefix), ".")
	if !ok || !keyIDPattern.MatchString(keyID) || encoded == "" {
		return "", nil, ErrInvalidEnvelope
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, ErrInvalidEnvelope
	}
	return keyID, payload, nil
}

func envelopeAAD(purpose, recordID, keyID string) []byte {
	return []byte(purpose + "\x00" + recordID + "\x00" + keyID)
}
