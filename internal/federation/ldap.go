package federation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"certus/internal/identity"

	ldap "github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidCredentials = errors.New("external credentials are invalid")
	ErrUnavailable        = errors.New("external identity provider is unavailable")
)

type LDAPAuthenticator struct {
	config  LDAPConfig
	timeout time.Duration
}

func NewLDAPAuthenticator(cfg LDAPConfig) *LDAPAuthenticator {
	return &LDAPAuthenticator{config: cfg, timeout: 5 * time.Second}
}

func (a *LDAPAuthenticator) Enabled() bool {
	return a != nil && a.config.Enabled()
}

func (a *LDAPAuthenticator) Label() string {
	if a == nil {
		return ""
	}
	return a.config.Label
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (identity.ExternalProfile, error) {
	username = strings.TrimSpace(username)
	if !a.Enabled() {
		return identity.ExternalProfile{}, ErrUnavailable
	}
	if username == "" || password == "" {
		return identity.ExternalProfile{}, ErrInvalidCredentials
	}
	select {
	case <-ctx.Done():
		return identity.ExternalProfile{}, ctx.Err()
	default:
	}

	connection, err := a.connect(ctx)
	if err != nil {
		return identity.ExternalProfile{}, err
	}
	defer connection.Close()

	filter := strings.ReplaceAll(a.config.UserFilter, "{username}", ldap.EscapeFilter(username))
	attributes := uniqueAttributes(
		a.config.UsernameAttribute,
		a.config.DisplayNameAttribute,
		a.config.EmailAttribute,
	)
	result, err := connection.Search(ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		int(a.timeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	))
	if err != nil {
		return identity.ExternalProfile{}, fmt.Errorf("%w: search LDAP: %v", ErrUnavailable, err)
	}
	if len(result.Entries) != 1 {
		return identity.ExternalProfile{}, ErrInvalidCredentials
	}
	entry := result.Entries[0]
	if err := connection.Bind(entry.DN, password); err != nil {
		return identity.ExternalProfile{}, ErrInvalidCredentials
	}

	resolvedUsername := strings.TrimSpace(entry.GetAttributeValue(a.config.UsernameAttribute))
	if resolvedUsername == "" {
		resolvedUsername = username
	}
	displayName := strings.TrimSpace(entry.GetAttributeValue(a.config.DisplayNameAttribute))
	emailValue := strings.TrimSpace(entry.GetAttributeValue(a.config.EmailAttribute))
	var email *string
	if emailValue != "" {
		email = &emailValue
	}
	providerID := strings.TrimSpace(a.config.ProviderID)
	if providerID == "" {
		providerID = "ldap"
	}
	return identity.ExternalProfile{
		ProviderID:   providerID,
		Subject:      entry.DN,
		Username:     resolvedUsername,
		DisplayName:  displayName,
		Email:        email,
		EmailTrusted: true,
		Claims: map[string]any{
			"dn": entry.DN,
		},
	}, nil
}

func (a *LDAPAuthenticator) Probe(ctx context.Context) error {
	if !a.Enabled() {
		return ErrUnavailable
	}
	connection, err := a.connect(ctx)
	if err != nil {
		return err
	}
	return connection.Close()
}

func (a *LDAPAuthenticator) connect(ctx context.Context) (*ldap.Conn, error) {
	if !a.Enabled() {
		return nil, ErrUnavailable
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	endpoint, _ := url.Parse(a.config.URL)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: endpoint.Hostname(),
	}
	connection, err := ldap.DialURL(
		a.config.URL,
		ldap.DialWithDialer(&net.Dialer{Timeout: a.timeout}),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: connect LDAP: %v", ErrUnavailable, err)
	}
	connection.SetTimeout(a.timeout)
	if a.config.StartTLS {
		if err := connection.StartTLS(tlsConfig); err != nil {
			connection.Close()
			return nil, fmt.Errorf("%w: start LDAP TLS: %v", ErrUnavailable, err)
		}
	}
	if a.config.BindDN != "" {
		if err := connection.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			connection.Close()
			return nil, fmt.Errorf("%w: LDAP search bind failed", ErrUnavailable)
		}
	}
	return connection, nil
}

func uniqueAttributes(values ...string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
