package httpserver

import (
	"net/http"

	"certus/internal/audit"
)

func (s *server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.signer.ListKeys(r.Context())
	if err != nil {
		s.logger.Error("list signing keys", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取签名密钥失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

func (s *server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	kid, err := s.signer.Rotate(r.Context())
	if err != nil {
		s.logger.Error("rotate signing key", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "轮换签名密钥失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "oidc.signing_key_rotated",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"kid": kid},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"kid": kid, "algorithm": "RS256", "active": true})
}
