package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"certus/internal/audit"
	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/ratelimit"
	"certus/internal/session"
)

func newCapabilitiesClient(t *testing.T, id string) (client.Client, string) {
	t.Helper()
	registered, secret, err := client.New(client.CreateClient{
		ID:              id,
		Name:            "Capabilities Client",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		RedirectURIs:    []string{"https://app.example.com/callback"},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		AllowedScopes:   []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registered, secret
}

func newIntrospectionSource(t *testing.T, id, introspectorID string) client.Client {
	t.Helper()
	registered, _, err := client.New(client.CreateClient{
		ID:               id,
		Name:             "Collector CLI",
		ApplicationType:  client.ApplicationPublic,
		Protocols:        []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:       []client.GrantType{client.GrantDeviceCode},
		LoginMethods:     []client.LoginMethod{client.LoginPassword},
		AllowedScopes:    []string{"openid", "usage:write"},
		IntrospectableBy: []string{introspectorID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registered
}

func newClientCapabilitiesHandler(
	t *testing.T,
	repository client.Repository,
	configure func(*config.Config),
) (http.Handler, *audit.MemoryRepository) {
	t.Helper()
	cfg := config.Config{Issuer: "https://auth.example.com"}
	if configure != nil {
		configure(&cfg)
	}
	users := identity.NewMemoryUserRepository()
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(
		context.Background(),
		cfg,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:   repository,
			Users:     users,
			Passwords: users,
			Sessions:  session.NewMemoryRepository(),
			OAuth:     oauth.NewMemoryRepository(),
			CAS:       cas.NewMemoryRepository(),
			Audit:     audits,
			Keys:      &oidc.MemoryKeyRepository{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler, audits
}

func capabilitiesRequest(handler http.Handler, clientID, secret string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/clients/me/capabilities", nil)
	if clientID != "" {
		request.SetBasicAuth(clientID, secret)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestClientCapabilitiesDescribeCurrentClientWithoutLeakingConfiguration(t *testing.T) {
	registered, secret := newCapabilitiesClient(t, "conspectus")
	second := newIntrospectionSource(t, "z-collector", registered.ID)
	first := newIntrospectionSource(t, "a-collector", registered.ID)
	unrelated := newIntrospectionSource(t, "private-collector", "other-api")
	disabled := newIntrospectionSource(t, "disabled-collector", registered.ID)
	disabled.Enabled = false
	archived := newIntrospectionSource(t, "archived-collector", registered.ID)
	now := time.Now().UTC()
	archived.ArchivedAt = &now
	archived.Enabled = false

	handler, audits := newClientCapabilitiesHandler(t, client.NewMemoryRepository(
		registered,
		second,
		unrelated,
		disabled,
		first,
		archived,
	), nil)
	response := capabilitiesRequest(handler, registered.ID, secret)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities query: %d %s", response.Code, response.Body.String())
	}
	var body clientCapabilitiesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SchemaVersion != clientCapabilitiesSchemaVersion ||
		!slices.Equal(body.Features, supportedClientCapabilities) ||
		!slices.Equal(body.IntrospectionSources, []string{"a-collector", "z-collector"}) ||
		!strings.HasPrefix(body.ConfigRevision, "v1.") {
		t.Fatalf("unexpected capabilities response: %#v", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("capabilities response is cacheable: %q", response.Header().Get("Cache-Control"))
	}
	for _, forbidden := range []string{
		secret,
		"private-collector",
		"disabled-collector",
		"archived-collector",
		"allowed_scopes",
		"secret_hash",
	} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("capabilities response leaked %q: %s", forbidden, response.Body.String())
		}
	}

	events, err := audits.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events.Items {
		if event.EventType == "client.capabilities_queried" &&
			event.Outcome == audit.OutcomeSuccess &&
			event.ClientID != nil && *event.ClientID == registered.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("missing successful client.capabilities_queried audit event")
	}
}

func TestClientCapabilitiesRequireConfidentialBasicAuthentication(t *testing.T) {
	registered, secret := newCapabilitiesClient(t, "conspectus")
	public := newIntrospectionSource(t, "collector-cli", registered.ID)
	handler, audits := newClientCapabilitiesHandler(
		t,
		client.NewMemoryRepository(registered, public),
		nil,
	)

	for name, credentials := range map[string][2]string{
		"missing":       {"", ""},
		"wrong secret":  {registered.ID, secret + "-wrong"},
		"public client": {public.ID, "not-a-client-secret"},
	} {
		t.Run(name, func(t *testing.T) {
			response := capabilitiesRequest(handler, credentials[0], credentials[1])
			if response.Code != http.StatusUnauthorized ||
				!strings.Contains(response.Header().Get("WWW-Authenticate"), "Basic") {
				t.Fatalf("unexpected authentication response: %d %s", response.Code, response.Body.String())
			}
		})
	}

	events, err := audits.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, event := range events.Items {
		if event.EventType == "client.authentication_failed" && event.Outcome == audit.OutcomeFailure {
			failed++
			if event.ClientID != nil {
				t.Fatalf("unverified client ID was attributed as an authenticated subject: %#v", event)
			}
		}
	}
	if failed != 3 {
		t.Fatalf("unexpected authentication failure audit count: %d", failed)
	}
}

func TestClientCapabilitiesRevisionIsStableAndTracksRelations(t *testing.T) {
	registered, secret := newCapabilitiesClient(t, "conspectus")
	first := newIntrospectionSource(t, "a-collector", registered.ID)
	second := newIntrospectionSource(t, "z-collector", registered.ID)

	firstHandler, _ := newClientCapabilitiesHandler(
		t,
		client.NewMemoryRepository(registered, second, first),
		nil,
	)
	secondHandler, _ := newClientCapabilitiesHandler(
		t,
		client.NewMemoryRepository(registered, first, second),
		nil,
	)
	withoutRelation := second
	withoutRelation.IntrospectableBy = nil
	changedHandler, _ := newClientCapabilitiesHandler(
		t,
		client.NewMemoryRepository(registered, first, withoutRelation),
		nil,
	)

	readRevision := func(handler http.Handler) clientCapabilitiesResponse {
		t.Helper()
		response := capabilitiesRequest(handler, registered.ID, secret)
		if response.Code != http.StatusOK {
			t.Fatalf("capabilities query: %d %s", response.Code, response.Body.String())
		}
		var body clientCapabilitiesResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	firstBody := readRevision(firstHandler)
	secondBody := readRevision(secondHandler)
	changedBody := readRevision(changedHandler)
	if firstBody.ConfigRevision != secondBody.ConfigRevision {
		t.Fatalf("repository order changed the revision: %q != %q", firstBody.ConfigRevision, secondBody.ConfigRevision)
	}
	if firstBody.ConfigRevision == changedBody.ConfigRevision ||
		slices.Contains(changedBody.IntrospectionSources, second.ID) {
		t.Fatalf("relation change was not reflected: before=%#v after=%#v", firstBody, changedBody)
	}
}

func TestClientCapabilitiesAreRateLimitedPerClient(t *testing.T) {
	registered, secret := newCapabilitiesClient(t, "conspectus")
	handler, _ := newClientCapabilitiesHandler(
		t,
		client.NewMemoryRepository(registered),
		func(cfg *config.Config) {
			cfg.RateLimits.ClientStatus = ratelimit.Policy{Limit: 1, Window: time.Minute}
		},
	)

	if response := capabilitiesRequest(handler, registered.ID, secret); response.Code != http.StatusOK {
		t.Fatalf("first capabilities query: %d %s", response.Code, response.Body.String())
	}
	response := capabilitiesRequest(handler, registered.ID, secret)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("second capabilities query was not rate limited: %d %s", response.Code, response.Body.String())
	}
}

type failingClientListRepository struct {
	client.Repository
}

func (failingClientListRepository) List(context.Context) ([]client.Client, error) {
	return nil, errors.New("client storage unavailable")
}

func TestClientCapabilitiesFailClosedWhenClientListIsUnavailable(t *testing.T) {
	registered, secret := newCapabilitiesClient(t, "conspectus")
	repository := client.NewMemoryRepository(registered)
	handler, _ := newClientCapabilitiesHandler(t, failingClientListRepository{Repository: repository}, nil)

	response := capabilitiesRequest(handler, registered.ID, secret)
	if response.Code != http.StatusInternalServerError ||
		!strings.Contains(response.Body.String(), `"code":"server_error"`) {
		t.Fatalf("unexpected storage failure response: %d %s", response.Code, response.Body.String())
	}
}
