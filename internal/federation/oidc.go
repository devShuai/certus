package federation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"certus/internal/config"
	"certus/internal/identity"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCAuthenticator struct {
	config       config.ExternalOIDCConfig
	redirectURL  string
	httpClient   *http.Client
	mu           sync.Mutex
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewOIDCAuthenticator(cfg config.ExternalOIDCConfig, redirectURL string, client *http.Client) *OIDCAuthenticator {
	return &OIDCAuthenticator{config: cfg, redirectURL: redirectURL, httpClient: client}
}

func (a *OIDCAuthenticator) Enabled() bool {
	return a != nil && a.config.Enabled()
}

func (a *OIDCAuthenticator) Label() string {
	if a == nil {
		return ""
	}
	return a.config.Label
}

func (a *OIDCAuthenticator) AuthorizationURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	_, oauthConfig, err := a.configuration(ctx)
	if err != nil {
		return "", err
	}
	return oauthConfig.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

func (a *OIDCAuthenticator) Exchange(ctx context.Context, code, nonce, verifier string) (identity.ExternalProfile, error) {
	provider, oauthConfig, err := a.configuration(ctx)
	if err != nil {
		return identity.ExternalProfile{}, err
	}
	ctx = a.clientContext(ctx)
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return identity.ExternalProfile{}, fmt.Errorf("%w: exchange OIDC code: %v", ErrInvalidCredentials, err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return identity.ExternalProfile{}, fmt.Errorf("%w: OIDC response has no ID Token", ErrInvalidCredentials)
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: a.config.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return identity.ExternalProfile{}, fmt.Errorf("%w: verify OIDC ID Token: %v", ErrInvalidCredentials, err)
	}
	if idToken.Nonce == "" || idToken.Nonce != nonce {
		return identity.ExternalProfile{}, fmt.Errorf("%w: OIDC nonce mismatch", ErrInvalidCredentials)
	}
	var claims struct {
		Subject           string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity.ExternalProfile{}, fmt.Errorf("%w: decode OIDC claims: %v", ErrInvalidCredentials, err)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return identity.ExternalProfile{}, fmt.Errorf("%w: OIDC subject is missing", ErrInvalidCredentials)
	}
	username := strings.TrimSpace(claims.PreferredUsername)
	if username == "" && claims.EmailVerified {
		username = strings.SplitN(claims.Email, "@", 2)[0]
	}
	if username == "" {
		username = "oidc-user"
	}
	var email *string
	if claims.EmailVerified && strings.TrimSpace(claims.Email) != "" {
		value := strings.TrimSpace(claims.Email)
		email = &value
	}
	return identity.ExternalProfile{
		ProviderID:   "oidc:" + a.config.Issuer,
		Subject:      claims.Subject,
		Username:     username,
		DisplayName:  claims.Name,
		Email:        email,
		EmailTrusted: claims.EmailVerified,
		Claims: map[string]any{
			"issuer": a.config.Issuer,
		},
	}, nil
}

func (a *OIDCAuthenticator) configuration(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	if !a.Enabled() {
		return nil, nil, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, a.oauth2Config, nil
	}
	provider, err := oidc.NewProvider(a.clientContext(ctx), a.config.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: discover OIDC provider: %v", ErrUnavailable, err)
	}
	a.provider = provider
	a.oauth2Config = &oauth2.Config{
		ClientID:     a.config.ClientID,
		ClientSecret: a.config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  a.redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
	}
	return a.provider, a.oauth2Config, nil
}

func (a *OIDCAuthenticator) clientContext(ctx context.Context) context.Context {
	if a.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, a.httpClient)
}
