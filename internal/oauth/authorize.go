package oauth

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"certus/internal/client"
)

var (
	codeChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
	codeVerifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	maxAgePattern        = regexp.MustCompile(`^[0-9]+$`)
)

type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string
	MaxAge              *int64
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
	prompt, err := parsePrompt(values)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	maxAge, err := parseMaxAge(values)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	return AuthorizationRequest{
		ClientID:            registered.ID,
		RedirectURI:         redirectURI,
		Scope:               scopes,
		State:               state,
		Nonce:               values.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Prompt:              prompt,
		MaxAge:              maxAge,
	}, nil
}

func (r AuthorizationRequest) HasPrompt(expected string) bool {
	return contains(r.Prompt, expected)
}

func ValidCodeVerifier(value string) bool {
	return codeVerifierPattern.MatchString(value)
}

func parsePrompt(values url.Values) ([]string, error) {
	raw, exists := values["prompt"]
	if !exists {
		return nil, nil
	}
	if len(raw) != 1 {
		return nil, errors.New("prompt must not be repeated")
	}
	prompt := strings.Fields(raw[0])
	if len(prompt) == 0 {
		return nil, errors.New("prompt must not be empty")
	}
	seen := make(map[string]struct{}, len(prompt))
	for _, value := range prompt {
		if value != "none" && value != "login" {
			return nil, errors.New("unsupported prompt value")
		}
		if _, ok := seen[value]; ok {
			return nil, errors.New("prompt values must not be repeated")
		}
		seen[value] = struct{}{}
	}
	if _, none := seen["none"]; none && len(seen) != 1 {
		return nil, errors.New("prompt none cannot be combined with other values")
	}
	return prompt, nil
}

func parseMaxAge(values url.Values) (*int64, error) {
	raw, exists := values["max_age"]
	if !exists {
		return nil, nil
	}
	if len(raw) != 1 || !maxAgePattern.MatchString(raw[0]) {
		return nil, errors.New("max_age must be a non-negative integer")
	}
	value, err := strconv.ParseInt(raw[0], 10, 64)
	if err != nil || value < 0 {
		return nil, errors.New("max_age must be a non-negative integer")
	}
	return &value, nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
