package client

import (
	"context"
	"testing"
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
