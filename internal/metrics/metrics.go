package metrics

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var requestDurationBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

type HTTPKey struct {
	Method string
	Route  string
	Status int
}

type HTTPSeries struct {
	Count        uint64
	DurationSum  float64
	DurationBins []uint64
	ResponseSize uint64
}

type ResultKey struct {
	Operation string
	Result    string
}

type BackgroundSeries struct {
	Count       uint64
	DurationSum float64
}

type DatabaseStats struct {
	MaxConnections       int32
	TotalConnections     int32
	AcquiredConnections  int32
	IdleConnections      int32
	AcquireCount         int64
	EmptyAcquireCount    int64
	CanceledAcquireCount int64
	AcquireDuration      time.Duration
}

type Registry struct {
	mu sync.RWMutex

	http           map[HTTPKey]HTTPSeries
	authentication map[ResultKey]uint64
	rateLimits     map[ResultKey]uint64
	background     map[ResultKey]BackgroundSeries
	readiness      map[string]uint64

	version  string
	commit   string
	database func() DatabaseStats
}

func NewRegistry() *Registry {
	return &Registry{
		http:           make(map[HTTPKey]HTTPSeries),
		authentication: make(map[ResultKey]uint64),
		rateLimits:     make(map[ResultKey]uint64),
		background:     make(map[ResultKey]BackgroundSeries),
		readiness:      make(map[string]uint64),
	}
}

func (r *Registry) SetBuildInfo(version, commit string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.version = strings.TrimSpace(version)
	r.commit = strings.TrimSpace(commit)
}

func (r *Registry) SetDatabaseStatsProvider(provider func() DatabaseStats) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.database = provider
}

func (r *Registry) RecordHTTPRequest(
	method, route string,
	status int,
	duration time.Duration,
	responseBytes int,
) {
	if r == nil {
		return
	}
	if route == "" {
		route = "unmatched"
	}
	if status == 0 {
		status = http.StatusOK
	}
	if duration < 0 {
		duration = 0
	}
	key := HTTPKey{Method: method, Route: route, Status: status}
	r.mu.Lock()
	defer r.mu.Unlock()
	series := r.http[key]
	if series.DurationBins == nil {
		series.DurationBins = make([]uint64, len(requestDurationBuckets))
	}
	seconds := duration.Seconds()
	series.Count++
	series.DurationSum += seconds
	if responseBytes > 0 {
		series.ResponseSize += uint64(responseBytes)
	}
	for index, upperBound := range requestDurationBuckets {
		if seconds <= upperBound {
			series.DurationBins[index]++
		}
	}
	r.http[key] = series
}

func (r *Registry) RecordAuthentication(method, result string) {
	if r == nil {
		return
	}
	r.incrementResult(r.authentication, method, result)
}

func (r *Registry) RecordRateLimit(scope, result string) {
	if r == nil {
		return
	}
	r.incrementResult(r.rateLimits, scope, result)
}

func (r *Registry) RecordReadiness(result string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readiness[result]++
}

func (r *Registry) RecordBackground(task, result string, duration time.Duration) {
	if r == nil {
		return
	}
	if duration < 0 {
		duration = 0
	}
	key := ResultKey{Operation: task, Result: result}
	r.mu.Lock()
	defer r.mu.Unlock()
	series := r.background[key]
	series.Count++
	series.DurationSum += duration.Seconds()
	r.background[key] = series
}

func (r *Registry) incrementResult(target map[ResultKey]uint64, operation, result string) {
	if r == nil {
		return
	}
	key := ResultKey{Operation: operation, Result: result}
	r.mu.Lock()
	defer r.mu.Unlock()
	target[key]++
}

func (r *Registry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		writer := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(writer, request)
		r.RecordHTTPRequest(
			request.Method,
			request.Pattern,
			writer.status,
			time.Since(started),
			writer.bytes,
		)
	})
}

func (r *Registry) WritePrometheus(output io.Writer) error {
	snapshot := r.snapshot()
	writer := bufio.NewWriter(output)
	write := func(format string, values ...any) error {
		_, err := fmt.Fprintf(writer, format, values...)
		return err
	}

	if err := write("# HELP certus_build_info Certus build information.\n# TYPE certus_build_info gauge\n"); err != nil {
		return err
	}
	if err := write(
		"certus_build_info{version=%s,commit=%s} 1\n",
		label(snapshot.version), label(snapshot.commit),
	); err != nil {
		return err
	}
	if err := write("# HELP certus_http_requests_total HTTP requests received.\n# TYPE certus_http_requests_total counter\n"); err != nil {
		return err
	}
	for _, key := range sortedHTTPKeys(snapshot.http) {
		series := snapshot.http[key]
		labels := httpLabels(key)
		if err := write("certus_http_requests_total%s %d\n", labels, series.Count); err != nil {
			return err
		}
	}
	if err := write("# HELP certus_http_request_duration_seconds HTTP request duration.\n# TYPE certus_http_request_duration_seconds histogram\n"); err != nil {
		return err
	}
	for _, key := range sortedHTTPKeys(snapshot.http) {
		series := snapshot.http[key]
		base := httpLabelsWithoutClosing(key)
		for index, upperBound := range requestDurationBuckets {
			if err := write(
				"certus_http_request_duration_seconds_bucket%s,le=%s} %d\n",
				base,
				label(strconv.FormatFloat(upperBound, 'g', -1, 64)),
				series.DurationBins[index],
			); err != nil {
				return err
			}
		}
		if err := write(
			"certus_http_request_duration_seconds_bucket%s,le=\"+Inf\"} %d\n",
			base, series.Count,
		); err != nil {
			return err
		}
		if err := write(
			"certus_http_request_duration_seconds_sum%s %s\n",
			httpLabels(key),
			number(series.DurationSum),
		); err != nil {
			return err
		}
		if err := write(
			"certus_http_request_duration_seconds_count%s %d\n",
			httpLabels(key), series.Count,
		); err != nil {
			return err
		}
	}
	if err := write("# HELP certus_http_response_size_bytes_total HTTP response bytes written.\n# TYPE certus_http_response_size_bytes_total counter\n"); err != nil {
		return err
	}
	for _, key := range sortedHTTPKeys(snapshot.http) {
		if err := write(
			"certus_http_response_size_bytes_total%s %d\n",
			httpLabels(key), snapshot.http[key].ResponseSize,
		); err != nil {
			return err
		}
	}
	if err := writeResultCounters(
		writer,
		"certus_authentication_attempts_total",
		"Authentication stages completed.",
		"method",
		snapshot.authentication,
	); err != nil {
		return err
	}
	if err := writeResultCounters(
		writer,
		"certus_rate_limit_decisions_total",
		"Rate-limit decisions.",
		"scope",
		snapshot.rateLimits,
	); err != nil {
		return err
	}
	if err := writeBackground(writer, snapshot.background); err != nil {
		return err
	}
	if err := writeSimpleResults(
		writer,
		"certus_readiness_checks_total",
		"Readiness check results.",
		snapshot.readiness,
	); err != nil {
		return err
	}
	if snapshot.database != nil {
		if err := writeDatabase(writer, snapshot.database()); err != nil {
			return err
		}
	}
	return writer.Flush()
}

type registrySnapshot struct {
	http           map[HTTPKey]HTTPSeries
	authentication map[ResultKey]uint64
	rateLimits     map[ResultKey]uint64
	background     map[ResultKey]BackgroundSeries
	readiness      map[string]uint64
	version        string
	commit         string
	database       func() DatabaseStats
}

func (r *Registry) snapshot() registrySnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := registrySnapshot{
		http:           make(map[HTTPKey]HTTPSeries, len(r.http)),
		authentication: cloneResultCounters(r.authentication),
		rateLimits:     cloneResultCounters(r.rateLimits),
		background:     make(map[ResultKey]BackgroundSeries, len(r.background)),
		readiness:      make(map[string]uint64, len(r.readiness)),
		version:        r.version,
		commit:         r.commit,
		database:       r.database,
	}
	for key, value := range r.http {
		value.DurationBins = append([]uint64(nil), value.DurationBins...)
		result.http[key] = value
	}
	for key, value := range r.background {
		result.background[key] = value
	}
	for key, value := range r.readiness {
		result.readiness[key] = value
	}
	return result
}

func cloneResultCounters(source map[ResultKey]uint64) map[ResultKey]uint64 {
	result := make(map[ResultKey]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	count, err := w.ResponseWriter.Write(value)
	w.bytes += count
	return count, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func sortedHTTPKeys(values map[HTTPKey]HTTPSeries) []HTTPKey {
	result := make([]HTTPKey, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Slice(result, func(left, right int) bool {
		a, b := result[left], result[right]
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		return a.Status < b.Status
	})
	return result
}

func sortedResultKeys[T any](values map[ResultKey]T) []ResultKey {
	result := make([]ResultKey, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Slice(result, func(left, right int) bool {
		a, b := result[left], result[right]
		if a.Operation != b.Operation {
			return a.Operation < b.Operation
		}
		return a.Result < b.Result
	})
	return result
}

func httpLabels(key HTTPKey) string {
	return fmt.Sprintf(
		"{method=%s,route=%s,status=%s}",
		label(key.Method), label(key.Route), label(strconv.Itoa(key.Status)),
	)
}

func httpLabelsWithoutClosing(key HTTPKey) string {
	return fmt.Sprintf(
		"{method=%s,route=%s,status=%s",
		label(key.Method), label(key.Route), label(strconv.Itoa(key.Status)),
	)
}

func writeResultCounters(
	writer *bufio.Writer,
	name, help, operationLabel string,
	values map[ResultKey]uint64,
) error {
	if _, err := fmt.Fprintf(
		writer, "# HELP %s %s\n# TYPE %s counter\n",
		name, help, name,
	); err != nil {
		return err
	}
	for _, key := range sortedResultKeys(values) {
		if _, err := fmt.Fprintf(
			writer,
			"%s{%s=%s,result=%s} %d\n",
			name,
			operationLabel, label(key.Operation),
			label(key.Result), values[key],
		); err != nil {
			return err
		}
	}
	return nil
}

func writeBackground(
	writer *bufio.Writer,
	values map[ResultKey]BackgroundSeries,
) error {
	if _, err := fmt.Fprint(
		writer,
		"# HELP certus_background_runs_total Background task runs.\n"+
			"# TYPE certus_background_runs_total counter\n",
	); err != nil {
		return err
	}
	for _, key := range sortedResultKeys(values) {
		if _, err := fmt.Fprintf(
			writer,
			"certus_background_runs_total{task=%s,result=%s} %d\n",
			label(key.Operation), label(key.Result), values[key].Count,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(
		writer,
		"# HELP certus_background_run_duration_seconds Background task duration.\n"+
			"# TYPE certus_background_run_duration_seconds summary\n",
	); err != nil {
		return err
	}
	for _, key := range sortedResultKeys(values) {
		series := values[key]
		labels := fmt.Sprintf(
			"{task=%s,result=%s}",
			label(key.Operation), label(key.Result),
		)
		if _, err := fmt.Fprintf(
			writer,
			"certus_background_run_duration_seconds_sum%s %s\n"+
				"certus_background_run_duration_seconds_count%s %d\n",
			labels, number(series.DurationSum),
			labels, series.Count,
		); err != nil {
			return err
		}
	}
	return nil
}

func writeSimpleResults(
	writer *bufio.Writer,
	name, help string,
	values map[string]uint64,
) error {
	if _, err := fmt.Fprintf(
		writer, "# HELP %s %s\n# TYPE %s counter\n",
		name, help, name,
	); err != nil {
		return err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := fmt.Fprintf(
			writer, "%s{result=%s} %d\n",
			name, label(key), values[key],
		); err != nil {
			return err
		}
	}
	return nil
}

func writeDatabase(writer *bufio.Writer, stats DatabaseStats) error {
	if _, err := fmt.Fprint(
		writer,
		"# HELP certus_postgres_connections PostgreSQL pool connections by state.\n"+
			"# TYPE certus_postgres_connections gauge\n",
	); err != nil {
		return err
	}
	for _, value := range []struct {
		state string
		count int32
	}{
		{"max", stats.MaxConnections},
		{"total", stats.TotalConnections},
		{"acquired", stats.AcquiredConnections},
		{"idle", stats.IdleConnections},
	} {
		if _, err := fmt.Fprintf(
			writer,
			"certus_postgres_connections{state=%s} %d\n",
			label(value.state), value.count,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(
		writer,
		"# HELP certus_postgres_acquires_total PostgreSQL pool acquire attempts.\n"+
			"# TYPE certus_postgres_acquires_total counter\n"+
			"certus_postgres_acquires_total{result=\"acquired\"} %d\n"+
			"certus_postgres_acquires_total{result=\"empty\"} %d\n"+
			"certus_postgres_acquires_total{result=\"canceled\"} %d\n"+
			"# HELP certus_postgres_acquire_duration_seconds_total Total PostgreSQL connection acquire time.\n"+
			"# TYPE certus_postgres_acquire_duration_seconds_total counter\n"+
			"certus_postgres_acquire_duration_seconds_total %s\n",
		stats.AcquireCount,
		stats.EmptyAcquireCount,
		stats.CanceledAcquireCount,
		number(stats.AcquireDuration.Seconds()),
	); err != nil {
		return err
	}
	return nil
}

func label(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func number(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
