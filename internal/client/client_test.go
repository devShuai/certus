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
		ID:           "specus",
		RedirectURIs: []string{"https://specus.example.com/callback"},
		LoginMethods: []LoginMethod{LoginPassword},
		Enabled:      true,
	})

	first, err := repository.Find(context.Background(), "specus")
	if err != nil {
		t.Fatal(err)
	}
	first.RedirectURIs[0] = "https://attacker.example.com"
	first.LoginMethods[0] = LoginOIDC

	second, err := repository.Find(context.Background(), "specus")
	if err != nil {
		t.Fatal(err)
	}
	if second.RedirectURIs[0] != "https://specus.example.com/callback" || second.LoginMethods[0] != LoginPassword {
		t.Fatal("repository state was mutated through returned client")
	}
}

func TestNewConfidentialClientReturnsSecretOnce(t *testing.T) {
	item, secret, err := New(CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: ApplicationConfidential,
		RedirectURIs:    []string{"https://finance.example.com/oidc/callback"},
		LoginMethods:    []LoginMethod{LoginPassword},
		AllowedScopes:   []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 40 || len(item.SecretHash) != 32 {
		t.Fatalf("secret was not generated securely: secret=%d hash=%d", len(secret), len(item.SecretHash))
	}
	if strings.Contains(string(item.SecretHash), secret) {
		t.Fatal("raw secret was retained in client")
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
