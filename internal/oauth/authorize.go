package oauth

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"certus/internal/client"
)

var (
	codeChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
	codeVerifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func ParseAuthorizationRequest(values url.Values, registered client.Client) (AuthorizationRequest, error) {
	if !registered.Enabled {
		return AuthorizationRequest{}, errors.New("client is disabled")
	}
	if !registered.SupportsOAuth() || !registered.SupportsGrant(client.GrantAuthorizationCode) {
		return AuthorizationRequest{}, errors.New("authorization_code is not enabled for this client")
	}
	if values.Get("client_id") != registered.ID {
		return AuthorizationRequest{}, errors.New("invalid client_id")
	}
	if values.Get("response_type") != "code" {
		return AuthorizationRequest{}, errors.New("response_type must be code")
	}
	redirectURI := values.Get("redirect_uri")
	if !registered.AllowsRedirectURI(redirectURI) {
		return AuthorizationRequest{}, errors.New("invalid redirect_uri")
	}
	if values.Get("code_challenge_method") != "S256" {
		return AuthorizationRequest{}, errors.New("code_challenge_method must be S256")
	}
	challenge := values.Get("code_challenge")
	if !codeChallengePattern.MatchString(challenge) {
		return AuthorizationRequest{}, errors.New("invalid code_challenge")
	}
	state := values.Get("state")
	if state == "" {
		return AuthorizationRequest{}, errors.New("state is required")
	}
	scopes := strings.Fields(values.Get("scope"))
	for _, scope := range scopes {
		if !contains(registered.AllowedScopes, scope) {
			return AuthorizationRequest{}, errors.New("requested scope is not allowed")
		}
	}
	return AuthorizationRequest{
		ClientID:            registered.ID,
		RedirectURI:         redirectURI,
		Scope:               scopes,
		State:               state,
		Nonce:               values.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}, nil
}

func ValidCodeVerifier(value string) bool {
	return codeVerifierPattern.MatchString(value)
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
