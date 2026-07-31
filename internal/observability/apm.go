package observability

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.elastic.co/apm/module/apmhttp/v2"
	"go.elastic.co/apm/module/apmslog/v2"
	"go.elastic.co/apm/v2"
)

const serviceName = "certus"

// ElasticAPM owns the process-wide Elastic APM tracer. A zero-value instance is
// disabled and leaves handlers, clients, and loggers unchanged.
type ElasticAPM struct {
	tracer *apm.Tracer
}

// NewElasticAPM creates the tracer when Elastic APM is explicitly configured.
// Requiring either ELASTIC_APM_SERVER_URL or ELASTIC_APM_ACTIVE=true prevents a
// development process from silently attempting to connect to localhost:8200.
func NewElasticAPM(serviceVersion string) (*ElasticAPM, error) {
	enabled, err := elasticAPMEnabled(
		os.Getenv("ELASTIC_APM_ACTIVE"),
		environmentPresent("ELASTIC_APM_ACTIVE"),
		os.Getenv("ELASTIC_APM_SERVER_URL"),
	)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return &ElasticAPM{}, nil
	}

	options := apm.TracerOptions{ServiceName: serviceName}
	if version := strings.TrimSpace(serviceVersion); version != "" && version != "dev" {
		options.ServiceVersion = version
	}
	tracer, err := apm.NewTracerOptions(options)
	if err != nil {
		return nil, fmt.Errorf("initialize Elastic APM tracer: %w", err)
	}
	apm.SetDefaultTracer(tracer)
	return &ElasticAPM{tracer: tracer}, nil
}

func environmentPresent(name string) bool {
	_, ok := os.LookupEnv(name)
	return ok
}

func elasticAPMEnabled(active string, activeSet bool, serverURL string) (bool, error) {
	if activeSet {
		enabled, err := strconv.ParseBool(strings.TrimSpace(active))
		if err != nil {
			return false, fmt.Errorf("parse ELASTIC_APM_ACTIVE: %w", err)
		}
		return enabled, nil
	}
	return strings.TrimSpace(serverURL) != "", nil
}

func (a *ElasticAPM) Enabled() bool {
	return a != nil && a.tracer != nil
}

// Logger preserves the existing JSON handler, adds trace correlation fields,
// and reports error-level slog records to Elastic APM.
func (a *ElasticAPM) Logger(handler slog.Handler) *slog.Logger {
	if !a.Enabled() {
		return slog.New(handler)
	}
	return slog.New(apmslog.NewApmHandler(
		apmslog.WithHandler(handler),
		apmslog.WithTracer(a.tracer),
	))
}

// WrapHTTP records inbound requests as transactions. The inner wrapper runs
// after ServeMux has selected a route, so transaction names use bounded route
// patterns instead of raw URLs containing user or client identifiers.
func (a *ElasticAPM) WrapHTTP(handler http.Handler) http.Handler {
	if !a.Enabled() {
		return handler
	}
	routeNamed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			name := r.Pattern
			if name == "" {
				name = r.Method + " unknown route"
			}
			if transaction := apm.TransactionFromContext(r.Context()); transaction != nil {
				transaction.Name = name
			}
		}()
		handler.ServeHTTP(w, r)
	})
	return apmhttp.Wrap(routeNamed, apmhttp.WithTracer(a.tracer))
}

// WrapClient records outbound HTTP requests as spans when their context carries
// a sampled APM transaction.
func (a *ElasticAPM) WrapClient(client *http.Client) *http.Client {
	if !a.Enabled() {
		return client
	}
	return apmhttp.WrapClient(client)
}

// Close flushes queued events within the supplied deadline and stops the
// tracer. It is safe to call on a disabled runtime.
func (a *ElasticAPM) Close(timeout time.Duration) {
	if !a.Enabled() {
		return
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	abort := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		close(abort)
	})
	a.tracer.Flush(abort)
	timer.Stop()
	a.tracer.Close()
}
