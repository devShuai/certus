package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.elastic.co/apm/v2/apmtest"
)

func TestElasticAPMEnabled(t *testing.T) {
	tests := []struct {
		name      string
		active    string
		activeSet bool
		serverURL string
		want      bool
		wantError bool
	}{
		{name: "not configured"},
		{name: "server URL configures agent", serverURL: "https://apm.example.com", want: true},
		{name: "active enables default endpoint", active: "true", activeSet: true, want: true},
		{name: "inactive overrides server URL", active: "false", activeSet: true, serverURL: "https://apm.example.com"},
		{name: "invalid active value", active: "sometimes", activeSet: true, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := elasticAPMEnabled(test.active, test.activeSet, test.serverURL)
			if (err != nil) != test.wantError {
				t.Fatalf("elasticAPMEnabled() error = %v, wantError %v", err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("elasticAPMEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestWrapHTTPUsesServeMuxRoutePattern(t *testing.T) {
	recording := apmtest.NewRecordingTracer()
	defer recording.Close()
	runtime := &ElasticAPM{tracer: recording.Tracer}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{userID}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/users/user-123", nil)
	response := httptest.NewRecorder()

	runtime.WrapHTTP(mux).ServeHTTP(response, request)
	recording.Flush(nil)

	payloads := recording.Payloads()
	if len(payloads.Transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(payloads.Transactions))
	}
	if got := payloads.Transactions[0].Name; got != "GET /users/{userID}" {
		t.Fatalf("transaction name = %q, want route pattern", got)
	}
}

func TestWrapHTTPBoundsUnknownRouteName(t *testing.T) {
	recording := apmtest.NewRecordingTracer()
	defer recording.Close()
	runtime := &ElasticAPM{tracer: recording.Tracer}

	request := httptest.NewRequest(http.MethodGet, "/not-found/user-123", nil)
	response := httptest.NewRecorder()

	runtime.WrapHTTP(http.NewServeMux()).ServeHTTP(response, request)
	recording.Flush(nil)

	payloads := recording.Payloads()
	if len(payloads.Transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(payloads.Transactions))
	}
	if got := payloads.Transactions[0].Name; got != "GET unknown route" {
		t.Fatalf("transaction name = %q, want bounded unknown route", got)
	}
}
