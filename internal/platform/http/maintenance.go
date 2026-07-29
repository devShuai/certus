package httpserver

import (
	"net/http"

	"certus/internal/audit"
)

func (s *server) runMaintenance(w http.ResponseWriter, r *http.Request) {
	result, err := s.maintenance.RunOnce(r.Context())
	if err != nil {
		s.logger.Error("run maintenance cleanup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "清理过期数据失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "maintenance.cleanup",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"deleted": result.Deleted},
	})
	writeJSON(w, http.StatusOK, result)
}
