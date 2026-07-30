package httpserver

import (
	"context"
	"net/http"
	"time"

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
		Details:   map[string]any{"kid": kid, "automatic": false},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"kid": kid, "algorithm": "RS256", "active": true})
}

func (s *server) runSigningKeyRotation(ctx context.Context, maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	run := func() {
		started := time.Now()
		kid, rotated, err := s.signer.RotateIfOlderThan(ctx, maxAge, s.now().UTC())
		if err != nil {
			s.metrics.RecordBackground("signing_key_rotation", "failure", time.Since(started))
			if ctx.Err() == nil {
				s.logger.Error("automatic OIDC signing key rotation failed", "error", err)
			}
			return
		}
		if !rotated {
			s.metrics.RecordBackground("signing_key_rotation", "not_due", time.Since(started))
			return
		}
		s.metrics.RecordBackground("signing_key_rotation", "success", time.Since(started))
		s.logger.Info("OIDC signing key automatically rotated", "kid", kid)
		s.recordSystemAudit(ctx, audit.Event{
			EventType: "oidc.signing_key_rotated",
			Outcome:   audit.OutcomeSuccess,
			Details:   map[string]any{"kid": kid, "automatic": true},
		})
	}
	run()
	checkInterval := min(maxAge/4, time.Hour)
	if checkInterval < time.Minute {
		checkInterval = time.Minute
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
