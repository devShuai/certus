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
	}

	request, err := ParseAuthorizationRequest(values, registered)
	if err != nil {
		t.Fatal(err)
	}
	if request.ClientID != "specus" || request.CodeChallengeMethod != "S256" {
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
