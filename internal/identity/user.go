package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotFound                = errors.New("user not found")
	ErrConflict                = errors.New("user already exists")
	ErrInvalid                 = errors.New("invalid user")
	ErrExternalIdentityMissing = errors.New("external identity not found")
	ErrLastAuthentication      = errors.New("cannot remove the last authentication method")
)

type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserLocked   UserStatus = "locked"
	UserDisabled UserStatus = "disabled"
)

type User struct {
	ID            string     `json:"id"`
	Username      string     `json:"username"`
	DisplayName   string     `json:"display_name"`
	Email         *string    `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Status        UserStatus `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type CreateUser struct {
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Email       *string    `json:"email"`
	Status      UserStatus `json:"status"`
}

type ReplaceUser struct {
	DisplayName string     `json:"display_name"`
	Email       *string    `json:"email"`
	Status      UserStatus `json:"status"`
}

type UserFilter struct {
	Query  string
	Status UserStatus
	Limit  int
	Offset int
}

type UserPage struct {
	Items  []User `json:"items"`
	Total  int64  `json:"total"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

type UserRepository interface {
	List(context.Context, UserFilter) (UserPage, error)
	Find(context.Context, string) (User, error)
	FindByUsername(context.Context, string) (User, error)
	Create(context.Context, User) (User, error)
	Replace(context.Context, User) (User, error)
}

type ExternalProfile struct {
	ProviderID    string         `json:"provider_id"`
	Subject       string         `json:"subject"`
	Username      string         `json:"username"`
	DisplayName   string         `json:"display_name"`
	Email         *string        `json:"email,omitempty"`
	EmailTrusted  bool           `json:"email_trusted"`
	EmailVerified bool           `json:"email_verified"`
	Claims        map[string]any `json:"claims,omitempty"`
}

type ExternalIdentityRepository interface {
	ResolveExternalIdentity(context.Context, ExternalProfile, time.Time) (User, error)
	ListExternalIdentities(context.Context, string) ([]ExternalIdentity, error)
	DeleteExternalIdentity(context.Context, string, string) error
}

type ExternalIdentity struct {
	ID                  string    `json:"id"`
	UserID              string    `json:"user_id"`
	ProviderID          string    `json:"provider_id"`
	Subject             string    `json:"subject"`
	Username            string    `json:"username"`
	DisplayName         string    `json:"display_name"`
	Email               *string   `json:"email,omitempty"`
	EmailTrusted        bool      `json:"email_trusted"`
	EmailVerified       bool      `json:"email_verified"`
	CreatedAt           time.Time `json:"created_at"`
	LastAuthenticatedAt time.Time `json:"last_authenticated_at"`
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
var userIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var unsupportedUsernameCharacters = regexp.MustCompile(`[^a-z0-9._-]+`)

func NewUser(input CreateUser, now time.Time) (User, error) {
	username := strings.ToLower(strings.TrimSpace(input.Username))
	displayName := strings.TrimSpace(input.DisplayName)
	email, err := normalizeEmail(input.Email)
	if err != nil {
		return User{}, err
	}
	status := input.Status
	if status == "" {
		status = UserActive
	}
	if !usernamePattern.MatchString(username) {
		return User{}, fmt.Errorf("%w: username must be 3-64 lowercase letters, digits, dots, underscores or hyphens", ErrInvalid)
	}
	if displayName == "" || len([]rune(displayName)) > 128 {
		return User{}, fmt.Errorf("%w: display_name must be 1-128 characters", ErrInvalid)
	}
	if !status.Valid() {
		return User{}, fmt.Errorf("%w: unsupported status", ErrInvalid)
	}
	id, err := newUUID()
	if err != nil {
		return User{}, fmt.Errorf("generate user ID: %w", err)
	}
	now = now.UTC()
	return User{
		ID:          id,
		Username:    username,
		DisplayName: displayName,
		Email:       email,
		Status:      status,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func Replace(current User, input ReplaceUser, now time.Time) (User, error) {
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" || len([]rune(displayName)) > 128 {
		return User{}, fmt.Errorf("%w: display_name must be 1-128 characters", ErrInvalid)
	}
	email, err := normalizeEmail(input.Email)
	if err != nil {
		return User{}, err
	}
	if email == nil || current.Email == nil || !strings.EqualFold(*current.Email, *email) {
		current.EmailVerified = false
	}
	if !input.Status.Valid() {
		return User{}, fmt.Errorf("%w: unsupported status", ErrInvalid)
	}
	current.DisplayName = displayName
	current.Email = email
	current.Status = input.Status
	current.UpdatedAt = now.UTC()
	return current, nil
}

func (s UserStatus) Valid() bool {
	return s == UserActive || s == UserLocked || s == UserDisabled
}

func ValidUserID(id string) bool {
	return userIDPattern.MatchString(id)
}

func NewExternalUser(profile ExternalProfile, disambiguate bool, now time.Time) (User, error) {
	if strings.TrimSpace(profile.ProviderID) == "" || strings.TrimSpace(profile.Subject) == "" {
		return User{}, fmt.Errorf("%w: external provider and subject are required", ErrInvalid)
	}
	username := strings.ToLower(strings.TrimSpace(profile.Username))
	username = unsupportedUsernameCharacters.ReplaceAllString(username, "-")
	username = strings.Trim(username, "._-")
	if username == "" {
		username = "user"
	}
	if len(username) > 54 {
		username = username[:54]
	}
	if disambiguate {
		sum := sha256.Sum256([]byte(profile.ProviderID + "\x00" + profile.Subject))
		username = fmt.Sprintf("%s-%x", username, sum[:4])
	}
	for len(username) < 3 {
		username += "0"
	}
	displayName := strings.TrimSpace(profile.DisplayName)
	if displayName == "" {
		displayName = profile.Username
	}
	if displayName == "" {
		displayName = username
	}
	user, err := NewUser(CreateUser{
		Username:    username,
		DisplayName: displayName,
		Email:       profile.Email,
		Status:      UserActive,
	}, now)
	if err != nil {
		return User{}, err
	}
	user.EmailVerified = profile.EmailVerified && user.Email != nil
	return user, nil
}

func normalizeEmail(value *string) (*string, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, nil
	}
	normalized := strings.ToLower(strings.TrimSpace(*value))
	if len(normalized) > 320 {
		return nil, fmt.Errorf("%w: invalid email", ErrInvalid)
	}
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return nil, fmt.Errorf("%w: invalid email", ErrInvalid)
	}
	return &normalized, nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
