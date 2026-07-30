package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"certus/internal/audit"
	"certus/internal/identity"
)

type auditStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditStatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (s *server) auditMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/admin/") ||
			(r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete) {
			next.ServeHTTP(w, r)
			return
		}
		principalState := &adminPrincipal{}
		r = r.WithContext(context.WithValue(r.Context(), adminPrincipalContextKey{}, principalState))
		writer := &auditStatusWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		outcome := audit.OutcomeSuccess
		if status >= 400 {
			outcome = audit.OutcomeFailure
		}
		s.recordAudit(r, audit.Event{
			EventType: "admin.request",
			Outcome:   outcome,
			Details: map[string]any{
				"method":            r.Method,
				"path":              r.URL.Path,
				"status":            status,
				"admin_auth_method": principalState.AuthMethod,
			},
		})
	})
}

func (s *server) recordAudit(r *http.Request, event audit.Event) {
	if principal, ok := adminPrincipalFrom(r); ok {
		if event.ActorUserID == nil && principal.Access.UserID != "" {
			event.ActorUserID = auditActor(principal.Access.UserID)
		}
		if event.Details == nil {
			event.Details = make(map[string]any)
		}
		event.Details["admin_auth_method"] = principal.AuthMethod
	}
	event.IPAddress = requestIPAddress(r)
	event.RequestID = requestIDValue(r)
	normalized, err := audit.Normalize(event, s.now().UTC())
	if err != nil {
		s.logger.Error("normalize audit event", "event_type", event.EventType, "error", err)
		return
	}
	if _, err := s.audit.Append(r.Context(), normalized); err != nil {
		s.logger.Error("append audit event", "event_type", event.EventType, "error", err)
	}
}

func (s *server) recordSystemAudit(ctx context.Context, event audit.Event) {
	normalized, err := audit.Normalize(event, s.now().UTC())
	if err != nil {
		s.logger.Error("normalize system audit event", "event_type", event.EventType, "error", err)
		return
	}
	if _, err := s.audit.Append(ctx, normalized); err != nil {
		s.logger.Error("append system audit event", "event_type", event.EventType, "error", err)
	}
}

func (s *server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := queryInt(r, "limit", 50, 1, 200)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1_000_000)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	actorUserID := strings.TrimSpace(r.URL.Query().Get("actor_user_id"))
	if actorUserID != "" && !identity.ValidUserID(actorUserID) {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "actor_user_id 无效")
		return
	}
	outcome := audit.Outcome(strings.TrimSpace(r.URL.Query().Get("outcome")))
	if outcome != "" && outcome != audit.OutcomeSuccess && outcome != audit.OutcomeFailure {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "outcome 无效")
		return
	}
	from, err := optionalTime(r.URL.Query().Get("from"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "from 必须是 RFC3339 时间")
		return
	}
	to, err := optionalTime(r.URL.Query().Get("to"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "to 必须是 RFC3339 时间")
		return
	}
	if from != nil && to != nil && !from.Before(*to) {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "from 必须早于 to")
		return
	}
	page, err := s.audit.List(r.Context(), audit.Filter{
		ActorUserID: actorUserID,
		EventType:   strings.TrimSpace(r.URL.Query().Get("event_type")),
		ClientID:    strings.TrimSpace(r.URL.Query().Get("client_id")),
		Outcome:     outcome,
		From:        from,
		To:          to,
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		s.logger.Error("list audit events", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取审计事件失败")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func optionalTime(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	value = value.UTC()
	return &value, nil
}

func auditActor(userID string) *string {
	if userID == "" {
		return nil
	}
	return &userID
}

func auditClient(clientID string) *string {
	if clientID == "" {
		return nil
	}
	return &clientID
}

func auditOutcome(err error) audit.Outcome {
	if err == nil {
		return audit.OutcomeSuccess
	}
	return audit.OutcomeFailure
}

func isMissingAuditRecord(err error) bool {
	return errors.Is(err, audit.ErrInvalid)
}
