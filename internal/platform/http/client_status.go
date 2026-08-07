package httpserver

import (
	"errors"
	"net/http"

	"certus/internal/audit"
	"certus/internal/identity"
	"certus/internal/oauth"
)

func (s *server) clientUserStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	attemptedClientID, _, _ := r.BasicAuth()
	registered, ok := s.authenticateConfidentialOAuthClientBasic(w, r)
	if !ok {
		details := map[string]any{"reason": "invalid_credentials"}
		if attemptedClientID == "" {
			details["reason"] = "missing_credentials"
		} else {
			// The client ID is not verified: it is recorded as the claimed
			// identity, never attributed as an authenticated subject.
			details["client_id"] = attemptedClientID
		}
		s.recordAudit(r, audit.Event{
			EventType: "client.authentication_failed",
			Outcome:   audit.OutcomeFailure,
			Details:   details,
		})
		return
	}
	userID := r.PathValue("userID")
	if !s.allowClientStatusLookup(w, r, registered.ID) {
		s.recordClientStatusQuery(r, registered.ID, userID, "rate_limited")
		return
	}
	if !identity.ValidUserID(userID) {
		s.recordClientStatusQuery(r, registered.ID, userID, "not_found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := s.oauth.FindConsent(r.Context(), userID, registered.ID); errors.Is(err, oauth.ErrConsentNotFound) {
		s.recordClientStatusQuery(r, registered.ID, userID, "not_found")
		w.WriteHeader(http.StatusNotFound)
		return
	} else if err != nil {
		s.recordClientStatusQuery(r, registered.ID, userID, "consent_unavailable")
		s.logger.Error("find user consent", "user_id", userID, "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户授权状态失败")
		return
	}
	user, err := s.users.Find(r.Context(), userID)
	if errors.Is(err, identity.ErrNotFound) {
		s.recordClientStatusQuery(r, registered.ID, userID, "not_found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		s.recordClientStatusQuery(r, registered.ID, userID, "storage_error")
		s.logger.Error("find user status", "user_id", userID, "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户状态失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "user.status_queried",
		ClientID:  auditClient(registered.ID),
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": user.ID},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":            user.ID,
		"status":         user.Status,
		"email_verified": user.EmailVerified,
		"updated_at":     user.UpdatedAt,
	})
}

func (s *server) recordClientStatusQuery(r *http.Request, clientID, userID, reason string) {
	s.recordAudit(r, audit.Event{
		EventType: "user.status_queried",
		ClientID:  auditClient(clientID),
		Outcome:   audit.OutcomeFailure,
		Details:   map[string]any{"user_id": userID, "reason": reason},
	})
}
