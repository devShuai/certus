package observability

import (
	"context"
	"strings"
	"testing"

	"go.elastic.co/apm/v2"
	"go.elastic.co/apm/v2/apmtest"
)

func TestSQLParameterCaptureEnabled(t *testing.T) {
	tests := []struct {
		value     string
		want      bool
		wantError bool
	}{
		{value: ""},
		{value: "off"},
		{value: "detailed", want: true},
		{value: "true", want: true},
		{value: "everything", wantError: true},
	}
	for _, test := range tests {
		got, err := sqlParameterCaptureEnabled(test.value)
		if (err != nil) != test.wantError {
			t.Fatalf("sqlParameterCaptureEnabled(%q) error = %v, wantError %v", test.value, err, test.wantError)
		}
		if got != test.want {
			t.Fatalf("sqlParameterCaptureEnabled(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestSensitiveSQLParameter(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		position  int
		sensitive bool
	}{
		{name: "insert user ID", sql: `INSERT INTO sessions (user_id, token_hash) VALUES ($1, $2)`, position: 1},
		{name: "insert token hash", sql: `INSERT INTO sessions (user_id, token_hash) VALUES ($1, $2)`, position: 2, sensitive: true},
		{name: "update client ID", sql: `UPDATE clients SET client_secret_hash = $2 WHERE id = $1`, position: 1},
		{name: "update client secret", sql: `UPDATE clients SET client_secret_hash = $2 WHERE id = $1`, position: 2, sensitive: true},
		{name: "selected secret does not taint predicate", sql: `SELECT client_secret_hash FROM clients WHERE id = $1`, position: 1},
		{name: "token predicate", sql: `SELECT user_id FROM sessions WHERE token_hash = $1`, position: 1, sensitive: true},
		{name: "ordinary role", sql: `SELECT id FROM access_roles WHERE client_id = $1`, position: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sensitiveSQLParameter(test.sql, test.position); got != test.sensitive {
				t.Fatalf("sensitiveSQLParameter() = %v, want %v", got, test.sensitive)
			}
		})
	}
}

func TestCaptureSQLParametersAddsDetailedLabelsAndRedactsSecrets(t *testing.T) {
	recording := apmtest.NewRecordingTracer()
	defer recording.Close()

	_, spans, _ := recording.WithTransaction(func(ctx context.Context) {
		span, _ := apm.StartSpan(ctx, "INSERT sessions", "db.postgresql.query")
		captureSQLParameters(
			span,
			`INSERT INTO sessions (user_id, token_hash, enabled) VALUES ($1, $2, $3)`,
			[]any{"user-123", []byte("secret-token-hash"), true},
		)
		span.End()
	})
	if len(spans) != 1 || spans[0].Context == nil {
		t.Fatalf("spans = %#v, want one span with context", spans)
	}
	labels := make(map[string]any)
	for _, item := range spans[0].Context.Tags {
		labels[item.Key] = item.Value
	}
	if got := labels["db_parameter_count"]; got != float64(3) && got != 3 {
		t.Fatalf("db_parameter_count = %#v, want 3", got)
	}
	if got := labels["db_parameter_01"]; !strings.Contains(got.(string), `value="user-123"`) {
		t.Fatalf("db_parameter_01 = %q, want detailed user ID", got)
	}
	if got := labels["db_parameter_02"]; !strings.Contains(got.(string), "[REDACTED]") || strings.Contains(got.(string), "secret-token-hash") {
		t.Fatalf("db_parameter_02 = %q, want redacted token hash", got)
	}
	if got := labels["db_parameter_03"]; !strings.Contains(got.(string), "value=true") {
		t.Fatalf("db_parameter_03 = %q, want boolean value", got)
	}
}
