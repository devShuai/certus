package httpserver

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func (s *server) metricsEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	authorization := strings.Fields(r.Header.Get("Authorization"))
	if len(authorization) != 2 ||
		!strings.EqualFold(authorization[0], "Bearer") ||
		len(authorization[1]) != len(s.cfg.MetricsToken) ||
		subtle.ConstantTimeCompare(
			[]byte(authorization[1]),
			[]byte(s.cfg.MetricsToken),
		) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="certus-metrics"`)
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "指标访问凭据无效")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.metrics.WritePrometheus(w); err != nil {
		s.logger.Error("render metrics", "error", err)
	}
}
