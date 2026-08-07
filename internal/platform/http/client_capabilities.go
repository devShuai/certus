package httpserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"sort"

	"certus/internal/audit"
)

const clientCapabilitiesSchemaVersion = 1

var supportedClientCapabilities = []string{
	"client_user_status",
	"cross_client_introspection",
	"email_verified",
}

type clientCapabilitiesResponse struct {
	SchemaVersion        int      `json:"schema_version"`
	Features             []string `json:"features"`
	IntrospectionSources []string `json:"introspection_sources"`
	ConfigRevision       string   `json:"config_revision"`
}

func (s *server) clientCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	attemptedClientID, _, _ := r.BasicAuth()
	registered, ok := s.authenticateConfidentialOAuthClientBasic(w, r)
	if !ok {
		details := map[string]any{"reason": "invalid_credentials"}
		if attemptedClientID == "" {
			details["reason"] = "missing_credentials"
		} else {
			// The client ID is only a claimed identity until Basic authentication
			// succeeds, so never attribute this event to an authenticated client.
			details["client_id"] = attemptedClientID
		}
		s.recordAudit(r, audit.Event{
			EventType: "client.authentication_failed",
			Outcome:   audit.OutcomeFailure,
			Details:   details,
		})
		return
	}
	if !s.allowClientCapabilitiesLookup(w, r, registered.ID) {
		s.recordClientCapabilitiesQuery(r, registered.ID, "rate_limited")
		return
	}

	clients, err := s.clients.List(r.Context())
	if err != nil {
		s.recordClientCapabilitiesQuery(r, registered.ID, "storage_error")
		s.logger.Error("list clients for capabilities", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取客户端能力失败")
		return
	}

	sources := make([]string, 0)
	for _, candidate := range clients {
		if candidate.ID == registered.ID ||
			!candidate.Enabled ||
			candidate.ArchivedAt != nil ||
			!candidate.SupportsOAuth() ||
			!slices.Contains(candidate.IntrospectableBy, registered.ID) {
			continue
		}
		sources = append(sources, candidate.ID)
	}
	sort.Strings(sources)

	features := slices.Clone(supportedClientCapabilities)
	response := clientCapabilitiesResponse{
		SchemaVersion:        clientCapabilitiesSchemaVersion,
		Features:             features,
		IntrospectionSources: sources,
		ConfigRevision:       clientCapabilitiesRevision(registered.ID, features, sources),
	}
	s.recordAudit(r, audit.Event{
		EventType: "client.capabilities_queried",
		ClientID:  auditClient(registered.ID),
		Outcome:   audit.OutcomeSuccess,
		Details: map[string]any{
			"schema_version":             response.SchemaVersion,
			"introspection_source_count": len(response.IntrospectionSources),
			"config_revision":            response.ConfigRevision,
		},
	})
	writeJSON(w, http.StatusOK, response)
}

func clientCapabilitiesRevision(clientID string, features, sources []string) string {
	payload, _ := json.Marshal(struct {
		SchemaVersion int      `json:"schema_version"`
		ClientID      string   `json:"client_id"`
		Features      []string `json:"features"`
		Sources       []string `json:"introspection_sources"`
	}{
		SchemaVersion: clientCapabilitiesSchemaVersion,
		ClientID:      clientID,
		Features:      features,
		Sources:       sources,
	})
	digest := sha256.Sum256(payload)
	return "v1." + base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *server) recordClientCapabilitiesQuery(r *http.Request, clientID, reason string) {
	s.recordAudit(r, audit.Event{
		EventType: "client.capabilities_queried",
		ClientID:  auditClient(clientID),
		Outcome:   audit.OutcomeFailure,
		Details:   map[string]any{"reason": reason},
	})
}
