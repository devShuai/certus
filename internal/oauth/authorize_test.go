package oauth

import (
	"net/url"
	"testing"

	"certus/internal/client"
)

func TestParseAuthorizationRequest(t *testing.T) {
	registered := client.Client{
		ID:            "specus",
		Protocols:     []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:    []client.GrantType{client.GrantAuthorizationCode},
		RedirectURIs:  []string{"https://specus.example.com/callback"},
		AllowedScopes: []string{"openid", "profile"},
		Enabled:       true,
	}
	values := url.Values{
		"client_id":             {"specus"},
		"redirect_uri":          {"https://specus.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"opaque-state"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"},
		"code_challenge_method": {"S256"},
		"prompt":                {"login consent"},
		"max_age":               {"300"},
	}

	request, err := ParseAuthorizationRequest(values, registered)
	if err != nil {
		t.Fatal(err)
	}
	if request.ClientID != "specus" || request.CodeChallengeMethod != "S256" ||
		!request.HasPrompt("login") || !request.HasPrompt("consent") ||
		request.MaxAge == nil || *request.MaxAge != 300 {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestParseAuthorizationRequestRejectsUnregisteredRedirect(t *testing.T) {
	registered := client.Client{
		ID:            "specus",
		Protocols:     []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:    []client.GrantType{client.GrantAuthorizationCode},
		RedirectURIs:  []string{"https://specus.example.com/callback"},
		AllowedScopes: []string{"openid"},
		Enabled:       true,
	}
	values := url.Values{
		"client_id":             {"specus"},
		"redirect_uri":          {"https://attacker.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"state"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"},
		"code_challenge_method": {"S256"},
	}

	if _, err := ParseAuthorizationRequest(values, registered); err == nil {
		t.Fatal("expected redirect URI validation error")
	}
}

func TestParseAuthorizationRequestRejectsInvalidAuthenticationParameters(t *testing.T) {
	registered := client.Client{
		ID:            "specus",
		Protocols:     []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:    []client.GrantType{client.GrantAuthorizationCode},
		RedirectURIs:  []string{"https://specus.example.com/callback"},
		AllowedScopes: []string{"openid"},
		Enabled:       true,
	}
	base := url.Values{
		"client_id":             {"specus"},
		"redirect_uri":          {"https://specus.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"state"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"},
		"code_challenge_method": {"S256"},
	}
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "conflicting prompt", key: "prompt", value: "none login"},
		{name: "unsupported prompt", key: "prompt", value: "select_account"},
		{name: "empty prompt", key: "prompt", value: ""},
		{name: "negative max age", key: "max_age", value: "-1"},
		{name: "signed max age", key: "max_age", value: "+1"},
		{name: "invalid max age", key: "max_age", value: "soon"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := make(url.Values, len(base))
			for key, current := range base {
				values[key] = append([]string(nil), current...)
			}
			values.Set(test.key, test.value)
			if _, err := ParseAuthorizationRequest(values, registered); err == nil {
				t.Fatal("expected authentication parameter validation error")
			}
		})
	}
}
