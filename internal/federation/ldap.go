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

	"certus/internal/config"
	"certus/internal/identity"

	ldap "github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidCredentials = errors.New("external credentials are invalid")
	ErrUnavailable        = errors.New("external identity provider is unavailable")
)

type LDAPAuthenticator struct {
	config  config.LDAPConfig
	timeout time.Duration
}

func NewLDAPAuthenticator(cfg config.LDAPConfig) *LDAPAuthenticator {
	return &LDAPAuthenticator{config: cfg, timeout: 5 * time.Second}
}

func (a *LDAPAuthenticator) Enabled() bool {
	return a != nil && a.config.Enabled()
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
		return identity.ExternalProfile{}, fmt.Errorf("%w: connect LDAP: %v", ErrUnavailable, err)
	}
	defer connection.Close()
	connection.SetTimeout(a.timeout)
	if a.config.StartTLS {
		if err := connection.StartTLS(tlsConfig); err != nil {
			return identity.ExternalProfile{}, fmt.Errorf("%w: start LDAP TLS: %v", ErrUnavailable, err)
		}
	}
	if a.config.BindDN != "" {
		if err := connection.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return identity.ExternalProfile{}, fmt.Errorf("%w: LDAP search bind failed", ErrUnavailable)
		}
	}

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
	return identity.ExternalProfile{
		ProviderID:   "ldap",
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
