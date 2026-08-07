package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMemoryRepositoryReturnsCopies(t *testing.T) {
	repository := NewMemoryRepository(Client{
		ID:                     "specus",
		RedirectURIs:           []string{"https://specus.example.com/callback"},
		PostLogoutRedirectURIs: []string{"https://specus.example.com/logout"},
		LoginMethods:           []LoginMethod{LoginPassword},
		IdentitySourceIDs:      []string{"workforce"},
		IntrospectableBy:       []string{"resource-api"},
		Enabled:                true,
	})

	first, err := repository.Find(context.Background(), "specus")
	if err != nil {
		t.Fatal(err)
	}
	first.RedirectURIs[0] = "https://attacker.example.com"
	first.PostLogoutRedirectURIs[0] = "https://attacker.example.com/logout"
	first.LoginMethods[0] = LoginOIDC
	first.IdentitySourceIDs[0] = "attacker"
	first.IntrospectableBy[0] = "attacker"

	second, err := repository.Find(context.Background(), "specus")
	if err != nil {
		t.Fatal(err)
	}
	if second.RedirectURIs[0] != "https://specus.example.com/callback" ||
		second.PostLogoutRedirectURIs[0] != "https://specus.example.com/logout" ||
		second.LoginMethods[0] != LoginPassword ||
		second.IdentitySourceIDs[0] != "workforce" ||
		second.IntrospectableBy[0] != "resource-api" {
		t.Fatal("repository state was mutated through returned client")
	}
}

func TestNewConfidentialClientReturnsSecretOnce(t *testing.T) {
	item, secret, err := New(CreateClient{
		ID:                               "finance",
		Name:                             "Finance",
		FaviconURL:                       "https://finance.example.com/favicon.svg",
		LaunchURI:                        "https://finance.example.com/?login=oidc",
		ApplicationType:                  ApplicationConfidential,
		RedirectURIs:                     []string{"https://finance.example.com/oidc/callback"},
		PostLogoutRedirectURIs:           []string{"https://finance.example.com/logout/callback"},
		BackchannelLogoutURI:             "https://finance.example.com/oidc/backchannel-logout",
		BackchannelLogoutSessionRequired: true,
		LoginMethods:                     []LoginMethod{LoginPassword},
		AllowedScopes:                    []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 40 || len(item.SecretHash) != 32 {
		t.Fatalf("secret was not generated securely: secret=%d hash=%d", len(secret), len(item.SecretHash))
	}
	if item.TokenEndpointAuthMethod != TokenEndpointAuthSecretBasic {
		t.Fatalf("unexpected default client authentication method: %s", item.TokenEndpointAuthMethod)
	}
	if item.BackchannelLogoutURI == "" || !item.BackchannelLogoutSessionRequired {
		t.Fatalf("back-channel logout metadata was not retained: %#v", item)
	}
	if item.FaviconURL != "https://finance.example.com/favicon.svg" {
		t.Fatalf("favicon URL was not retained: %#v", item)
	}
	if item.LaunchURI != "https://finance.example.com/?login=oidc" {
		t.Fatalf("launch URI was not retained: %#v", item)
	}
	if strings.Contains(string(item.SecretHash), secret) {
		t.Fatal("raw secret was retained in client")
	}
}

func TestClientAuthenticationMethodMatchesApplicationType(t *testing.T) {
	confidential, _, err := New(CreateClient{
		ID:                      "finance-api",
		Name:                    "Finance API",
		ApplicationType:         ApplicationConfidential,
		TokenEndpointAuthMethod: TokenEndpointAuthSecretPost,
		Protocols:               []Protocol{ProtocolOAuth21},
		GrantTypes:              []GrantType{GrantClientCredentials},
	})
	if err != nil {
		t.Fatal(err)
	}
	if confidential.TokenEndpointAuthMethod != TokenEndpointAuthSecretPost {
		t.Fatalf("client_secret_post was not retained: %#v", confidential)
	}
	for _, input := range []CreateClient{
		{
			ID:                      "invalid-public",
			Name:                    "Invalid Public",
			ApplicationType:         ApplicationPublic,
			TokenEndpointAuthMethod: TokenEndpointAuthSecretPost,
			RedirectURIs:            []string{"https://app.example.com/callback"},
			LoginMethods:            []LoginMethod{LoginPassword},
		},
		{
			ID:                      "invalid-confidential",
			Name:                    "Invalid Confidential",
			ApplicationType:         ApplicationConfidential,
			TokenEndpointAuthMethod: TokenEndpointAuthNone,
			Protocols:               []Protocol{ProtocolOAuth21},
			GrantTypes:              []GrantType{GrantClientCredentials},
		},
	} {
		if _, _, err := New(input); err == nil {
			t.Fatalf("invalid client authentication method was accepted: %#v", input)
		}
	}
}

func TestNewClientRejectsInsecureRemoteRedirect(t *testing.T) {
	_, _, err := New(CreateClient{
		ID:           "finance",
		Name:         "Finance",
		RedirectURIs: []string{"http://finance.example.com/callback"},
		LoginMethods: []LoginMethod{LoginPassword},
	})
	if err == nil {
		t.Fatal("expected insecure redirect URI to be rejected")
	}
}

func TestNewClientRejectsInsecureRemoteFavicon(t *testing.T) {
	_, _, err := New(CreateClient{
		ID:           "finance-icon",
		Name:         "Finance",
		FaviconURL:   "http://finance.example.com/favicon.ico",
		RedirectURIs: []string{"https://finance.example.com/callback"},
		LoginMethods: []LoginMethod{LoginPassword},
	})
	if err == nil {
		t.Fatal("expected insecure favicon URL to be rejected")
	}
}

func TestNewClientRejectsInsecureRemoteLaunchURI(t *testing.T) {
	_, _, err := New(CreateClient{
		ID:           "finance-launch",
		Name:         "Finance",
		LaunchURI:    "http://finance.example.com/?login=oidc",
		RedirectURIs: []string{"https://finance.example.com/callback"},
		LoginMethods: []LoginMethod{LoginPassword},
	})
	if err == nil {
		t.Fatal("expected insecure launch URI to be rejected")
	}
}

func TestNewClientAllowsLoopbackHTTPForDevelopment(t *testing.T) {
	_, _, err := New(CreateClient{
		ID:           "local-app",
		Name:         "Local App",
		RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
		LoginMethods: []LoginMethod{LoginPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientNormalizesAndValidatesIdentitySourceBindings(t *testing.T) {
	item, _, err := New(CreateClient{
		ID:                "federated-app",
		Name:              "Federated App",
		RedirectURIs:      []string{"https://app.example.com/callback"},
		LoginMethods:      []LoginMethod{LoginOIDC},
		IdentitySourceIDs: []string{" Workforce ", "workforce", "partners"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(item.IdentitySourceIDs) != 2 ||
		item.IdentitySourceIDs[0] != "workforce" ||
		item.IdentitySourceIDs[1] != "partners" {
		t.Fatalf("identity source bindings were not normalized: %#v", item.IdentitySourceIDs)
	}
	for _, input := range []CreateClient{
		{
			ID:                "no-external-method",
			Name:              "No External Method",
			RedirectURIs:      []string{"https://app.example.com/callback"},
			LoginMethods:      []LoginMethod{LoginPassword},
			IdentitySourceIDs: []string{"workforce"},
		},
		{
			ID:                "invalid-source-id",
			Name:              "Invalid Source ID",
			RedirectURIs:      []string{"https://app.example.com/callback"},
			LoginMethods:      []LoginMethod{LoginOIDC},
			IdentitySourceIDs: []string{"invalid source"},
		},
	} {
		if _, _, err := New(input); err == nil {
			t.Fatalf("invalid identity source binding was accepted: %#v", input)
		}
	}
}

func TestClientNormalizesAndValidatesIntrospectionPermissions(t *testing.T) {
	item, _, err := New(CreateClient{
		ID:               "collector-cli",
		Name:             "Collector CLI",
		ApplicationType:  ApplicationPublic,
		Protocols:        []Protocol{ProtocolOAuth21},
		GrantTypes:       []GrantType{GrantDeviceCode},
		LoginMethods:     []LoginMethod{LoginPassword},
		IntrospectableBy: []string{" Resource-API ", "resource-api", "reporting-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(item.IntrospectableBy) != 2 ||
		item.IntrospectableBy[0] != "resource-api" ||
		item.IntrospectableBy[1] != "reporting-api" {
		t.Fatalf("introspection permissions were not normalized: %#v", item.IntrospectableBy)
	}
	if !item.AllowsIntrospectionBy("collector-cli") ||
		!item.AllowsIntrospectionBy("resource-api") ||
		item.AllowsIntrospectionBy("other-api") {
		t.Fatalf("unexpected introspection authorization: %#v", item.IntrospectableBy)
	}

	for _, input := range []CreateClient{
		{
			ID:               "invalid-target",
			Name:             "Invalid Target",
			Protocols:        []Protocol{ProtocolOAuth21},
			GrantTypes:       []GrantType{GrantDeviceCode},
			LoginMethods:     []LoginMethod{LoginPassword},
			IntrospectableBy: []string{"invalid target"},
		},
		{
			ID:               "self-target",
			Name:             "Self Target",
			Protocols:        []Protocol{ProtocolOAuth21},
			GrantTypes:       []GrantType{GrantDeviceCode},
			LoginMethods:     []LoginMethod{LoginPassword},
			IntrospectableBy: []string{"self-target"},
		},
		{
			ID:               "cas-only",
			Name:             "CAS Only",
			Protocols:        []Protocol{ProtocolCAS},
			LoginMethods:     []LoginMethod{LoginPassword},
			IntrospectableBy: []string{"resource-api"},
			CASVersion:       CASVersion3,
			CASServiceURLs:   []string{"https://legacy.example.com/login/cas"},
		},
	} {
		if _, _, err := New(input); err == nil {
			t.Fatalf("invalid introspection permission was accepted: %#v", input)
		}
	}
}

func TestNewClientRejectsInvalidBackchannelLogoutConfiguration(t *testing.T) {
	tests := []CreateClient{
		{
			ID:                               "missing-uri",
			Name:                             "Missing URI",
			BackchannelLogoutSessionRequired: true,
			RedirectURIs:                     []string{"https://app.example.com/callback"},
			LoginMethods:                     []LoginMethod{LoginPassword},
		},
		{
			ID:                   "insecure-uri",
			Name:                 "Insecure URI",
			BackchannelLogoutURI: "http://app.example.com/logout",
			RedirectURIs:         []string{"https://app.example.com/callback"},
			LoginMethods:         []LoginMethod{LoginPassword},
		},
		{
			ID:                   "cas-only",
			Name:                 "CAS Only",
			Protocols:            []Protocol{ProtocolCAS},
			BackchannelLogoutURI: "https://app.example.com/logout",
			LoginMethods:         []LoginMethod{LoginPassword},
			CASServiceURLs:       []string{"https://app.example.com/cas"},
		},
	}
	for _, input := range tests {
		if _, _, err := New(input); err == nil {
			t.Fatalf("invalid back-channel logout configuration was accepted: %#v", input)
		}
	}
}

func TestPublicClientCannotUseClientCredentials(t *testing.T) {
	_, _, err := New(CreateClient{
		ID:              "public-api",
		Name:            "Public API",
		ApplicationType: ApplicationPublic,
		Protocols:       []Protocol{ProtocolOAuth20},
		GrantTypes:      []GrantType{GrantClientCredentials},
	})
	if err == nil {
		t.Fatal("expected client_credentials validation error")
	}
}

func TestCASClientSupportsVersionedOptions(t *testing.T) {
	item, _, err := New(CreateClient{
		ID:              "legacy-cas",
		Name:            "Legacy CAS",
		ApplicationType: ApplicationPublic,
		Protocols:       []Protocol{ProtocolCAS},
		LoginMethods:    []LoginMethod{LoginLDAP},
		CASVersion:      CASVersion3,
		CASServiceURLs:  []string{"https://legacy.example.com/login/cas"},
		CASProxy:        true,
		CASGateway:      true,
		CASSingleLogout: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !item.SupportsProtocol(ProtocolCAS) || item.CASVersion != CASVersion3 || !item.CASProxy {
		t.Fatalf("unexpected CAS client: %#v", item)
	}
}

func TestAllowsRedirectURIRequiresExactAbsoluteURI(t *testing.T) {
	item := Client{RedirectURIs: []string{"https://specus.example.com/callback"}}
	cases := []struct {
		uri  string
		want bool
	}{
		{"https://specus.example.com/callback", true},
		{"https://specus.example.com/callback/", false},
		{"https://specus.example.com/callback?next=1", false},
		{"/callback", false},
		{"https://specus.example.com/callback#fragment", false},
	}
	for _, test := range cases {
		if got := item.AllowsRedirectURI(test.uri); got != test.want {
			t.Errorf("AllowsRedirectURI(%q) = %v, want %v", test.uri, got, test.want)
		}
	}
}

func TestAllowsPostLogoutRedirectURIRequiresExactRegistration(t *testing.T) {
	item := Client{PostLogoutRedirectURIs: []string{"https://specus.example.com/logout?source=certus"}}
	if !item.AllowsPostLogoutRedirectURI("https://specus.example.com/logout?source=certus") {
		t.Fatal("registered post-logout redirect URI was rejected")
	}
	for _, candidate := range []string{
		"https://specus.example.com/logout",
		"https://specus.example.com/logout?source=other",
		"https://attacker.example.com/logout",
	} {
		if item.AllowsPostLogoutRedirectURI(candidate) {
			t.Fatalf("unregistered post-logout redirect URI was accepted: %s", candidate)
		}
	}
}

func TestClientReplacementSecretRotationAndArchive(t *testing.T) {
	current, originalSecret, err := New(CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: ApplicationConfidential,
		Protocols:       []Protocol{ProtocolOAuth21},
		GrantTypes:      []GrantType{GrantAuthorizationCode, GrantRefreshToken},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
		LoginMethods:    []LoginMethod{LoginPassword},
		AllowedScopes:   []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	replaced, err := Replace(current, ReplaceClient{
		Name:          "Finance Portal",
		Protocols:     []Protocol{ProtocolOAuth21},
		GrantTypes:    []GrantType{GrantAuthorizationCode},
		RedirectURIs:  []string{"https://finance.example.com/oidc/callback"},
		LoginMethods:  []LoginMethod{LoginOIDC},
		AllowedScopes: []string{"openid"},
		Enabled:       &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID != current.ID ||
		replaced.ApplicationType != current.ApplicationType ||
		!bytesEqual(replaced.SecretHash, current.SecretHash) ||
		replaced.Enabled ||
		replaced.Name != "Finance Portal" {
		t.Fatalf("unexpected replacement: %#v", replaced)
	}

	rotated, secret, err := RotateSecret(replaced)
	if err != nil {
		t.Fatal(err)
	}
	if secret == originalSecret || bytesEqual(rotated.SecretHash, current.SecretHash) {
		t.Fatal("secret rotation did not create a new credential")
	}

	repository := NewMemoryRepository(rotated)
	if err := repository.Archive(context.Background(), rotated.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	archived, err := repository.Find(context.Background(), rotated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archived.Enabled || archived.ArchivedAt == nil {
		t.Fatalf("client was not archived: %#v", archived)
	}
	if _, err := repository.Replace(context.Background(), rotated); !errors.Is(err, ErrArchived) {
		t.Fatalf("archived client was replaceable: %v", err)
	}
}

func bytesEqual(left, right []byte) bool {
	return string(left) == string(right)
}
