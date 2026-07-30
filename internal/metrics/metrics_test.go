package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPMetricsUseRoutePatternWithoutSensitivePathValues(t *testing.T) {
	registry := NewRegistry()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	})
	request := httptest.NewRequest(http.MethodGet, "/users/alice-secret", nil)
	response := httptest.NewRecorder()
	registry.Middleware(mux).ServeHTTP(response, request)

	var output bytes.Buffer
	if err := registry.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{
		`certus_http_requests_total{method="GET",route="GET /users/{id}",status="201"} 1`,
		`certus_http_response_size_bytes_total{method="GET",route="GET /users/{id}",status="201"} 2`,
		`certus_http_request_duration_seconds_count{method="GET",route="GET /users/{id}",status="201"} 1`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("metrics do not contain %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "alice-secret") {
		t.Fatalf("raw path value leaked into metrics:\n%s", text)
	}
}

func TestMetricsRecordConcurrentDomainAndRuntimeValues(t *testing.T) {
	registry := NewRegistry()
	registry.SetBuildInfo(`v1"test`, "abc")
	registry.SetDatabaseStatsProvider(func() DatabaseStats {
		return DatabaseStats{
			MaxConnections:       10,
			TotalConnections:     3,
			AcquiredConnections:  1,
			IdleConnections:      2,
			AcquireCount:         5,
			EmptyAcquireCount:    1,
			CanceledAcquireCount: 2,
			AcquireDuration:      250 * time.Millisecond,
		}
	})
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			registry.RecordAuthentication("password", "success")
			registry.RecordRateLimit("login.source", "allowed")
			registry.RecordBackground("maintenance", "success", time.Second)
			registry.RecordReadiness("ready")
		}()
	}
	wait.Wait()

	var output bytes.Buffer
	if err := registry.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{
		`certus_build_info{version="v1\"test",commit="abc"} 1`,
		`certus_authentication_attempts_total{method="password",result="success"} 100`,
		`certus_rate_limit_decisions_total{scope="login.source",result="allowed"} 100`,
		`certus_background_runs_total{task="maintenance",result="success"} 100`,
		`certus_readiness_checks_total{result="ready"} 100`,
		`certus_postgres_connections{state="total"} 3`,
		`certus_postgres_acquire_duration_seconds_total 0.25`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("metrics do not contain %q:\n%s", expected, text)
		}
	}
}
