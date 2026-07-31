package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"go.elastic.co/apm/module/apmpgxv5/v2"
	"go.elastic.co/apm/v2"
)

const (
	maxSQLParameterCount      = 32
	maxSQLParameterValueRunes = 768
)

var sensitiveSQLIdentifiers = []string{
	"password",
	"secret",
	"token",
	"session",
	"ticket",
	"private_key",
	"ciphertext",
	"encrypted",
	"totp",
	"recovery_code",
	"authorization_code",
	"device_code",
	"user_code",
	"code_challenge",
	"nonce",
	"credential",
	"assertion",
	"hash",
}

type pgxAPMTracer struct {
	apmpgxv5.Tracer
	captureParameters bool
}

func sqlParameterCaptureEnabled(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off", "false", "0":
		return false, nil
	case "detailed", "true", "1":
		return true, nil
	default:
		return false, fmt.Errorf("CERTUS_APM_SQL_PARAMETERS must be off or detailed")
	}
}

// InstrumentPGX installs the official pgx tracer and optionally enriches query
// spans with bounded, individually labelled bind parameters.
func (a *ElasticAPM) InstrumentPGX(config *pgx.ConnConfig) {
	if !a.Enabled() || config == nil {
		return
	}
	config.Tracer = pgxAPMTracer{
		Tracer:            apmpgxv5.Tracer{},
		captureParameters: a.captureSQLParameters,
	}
}

func (t pgxAPMTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	spanContext := t.Tracer.QueryTracer.TraceQueryStart(ctx, conn, data)
	if !t.captureParameters {
		return spanContext
	}
	if span := apm.SpanFromContext(spanContext); span != nil {
		captureSQLParameters(span, data.SQL, data.Args)
	}
	return spanContext
}

func (t pgxAPMTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	t.Tracer.QueryTracer.TraceQueryEnd(ctx, conn, data)
}

func captureSQLParameters(span *apm.Span, sql string, arguments []any) {
	span.Context.SetLabel("db_parameter_count", len(arguments))
	captured := min(len(arguments), maxSQLParameterCount)
	span.Context.SetLabel("db_parameters_captured", captured)
	if captured < len(arguments) {
		span.Context.SetLabel("db_parameters_truncated", true)
	}
	for index := range captured {
		value := arguments[index]
		redacted := sensitiveSQLParameter(sql, index+1) || sensitiveSQLValue(value)
		span.Context.SetLabel(
			fmt.Sprintf("db_parameter_%02d", index+1),
			describeSQLParameter(value, redacted),
		)
	}
}

func describeSQLParameter(value any, redacted bool) string {
	typeName := fmt.Sprintf("%T", value)
	if value == nil {
		return "type=<nil> value=null"
	}
	if redacted {
		if length, ok := sqlParameterLength(value); ok {
			return fmt.Sprintf("type=%s value=[REDACTED] length=%d", typeName, length)
		}
		return fmt.Sprintf("type=%s value=[REDACTED]", typeName)
	}

	encoded := encodeSQLParameter(value)
	runes := []rune(encoded)
	if len(runes) > maxSQLParameterValueRunes {
		return fmt.Sprintf(
			"type=%s value=%s… [TRUNCATED original_runes=%d]",
			typeName,
			string(runes[:maxSQLParameterValueRunes]),
			len(runes),
		)
	}
	return fmt.Sprintf("type=%s value=%s", typeName, encoded)
}

func encodeSQLParameter(value any) string {
	switch typed := value.(type) {
	case time.Time:
		return strconv.Quote(typed.UTC().Format(time.RFC3339Nano))
	case fmt.Stringer:
		return strconv.Quote(typed.String())
	}
	encoded, err := json.Marshal(value)
	if err == nil {
		return string(encoded)
	}
	return strconv.Quote(fmt.Sprint(value))
}

func sqlParameterLength(value any) (int, bool) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return 0, false
	}
	switch reflected.Kind() {
	case reflect.String, reflect.Array, reflect.Slice, reflect.Map:
		return reflected.Len(), true
	default:
		return 0, false
	}
}

func sensitiveSQLValue(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	if (reflected.Kind() == reflect.Array || reflected.Kind() == reflect.Slice) && reflected.Type().Elem().Kind() == reflect.Uint8 {
		return true
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(text))
	if strings.HasPrefix(lower, "$argon2") ||
		strings.HasPrefix(lower, "$2a$") ||
		strings.HasPrefix(lower, "$2b$") ||
		strings.HasPrefix(lower, "$2y$") ||
		strings.HasPrefix(lower, "-----begin ") ||
		strings.Count(lower, ".") == 2 && len(lower) >= 48 {
		return true
	}
	if len(lower) < 48 {
		return false
	}
	for _, character := range lower {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("-_=+/", character) {
			continue
		}
		return false
	}
	return utf8.ValidString(text)
}

func sensitiveSQLParameter(sql string, position int) bool {
	normalized := strings.ToLower(sql)
	placeholder := regexp.QuoteMeta("$" + strconv.Itoa(position))
	direct := regexp.MustCompile(`(?i)([a-z_][a-z0-9_.]*)\s*(?:=|<>|!=|<=|>=|<|>|like|ilike)\s*` + placeholder + `\b`)
	for _, match := range direct.FindAllStringSubmatch(normalized, -1) {
		if sensitiveSQLIdentifier(match[1]) {
			return true
		}
	}
	reverse := regexp.MustCompile(`(?i)` + placeholder + `\s*(?:=|<>|!=|<=|>=|<|>|like|ilike)\s*([a-z_][a-z0-9_.]*)\b`)
	for _, match := range reverse.FindAllStringSubmatch(normalized, -1) {
		if sensitiveSQLIdentifier(match[1]) {
			return true
		}
	}

	columns, values := insertColumnsAndValues(normalized)
	for index, valueExpression := range values {
		if index >= len(columns) || !containsSQLPlaceholder(valueExpression, position) {
			continue
		}
		if sensitiveSQLIdentifier(columns[index]) {
			return true
		}
	}
	return false
}

func sensitiveSQLIdentifier(identifier string) bool {
	identifier = strings.Trim(strings.TrimSpace(identifier), `"`)
	if separator := strings.LastIndexByte(identifier, '.'); separator >= 0 {
		identifier = identifier[separator+1:]
	}
	for _, marker := range sensitiveSQLIdentifiers {
		if strings.Contains(identifier, marker) {
			return true
		}
	}
	return false
}

func insertColumnsAndValues(sql string) ([]string, []string) {
	insertIndex := strings.Index(sql, "insert into")
	if insertIndex < 0 {
		return nil, nil
	}
	columnOpen := strings.IndexByte(sql[insertIndex:], '(')
	if columnOpen < 0 {
		return nil, nil
	}
	columnOpen += insertIndex
	columnClose := matchingSQLParenthesis(sql, columnOpen)
	if columnClose < 0 {
		return nil, nil
	}
	valuesIndex := strings.Index(sql[columnClose+1:], "values")
	if valuesIndex < 0 {
		return nil, nil
	}
	valuesIndex += columnClose + 1
	valuesOpen := strings.IndexByte(sql[valuesIndex:], '(')
	if valuesOpen < 0 {
		return nil, nil
	}
	valuesOpen += valuesIndex
	valuesClose := matchingSQLParenthesis(sql, valuesOpen)
	if valuesClose < 0 {
		return nil, nil
	}
	return splitSQLList(sql[columnOpen+1 : columnClose]), splitSQLList(sql[valuesOpen+1 : valuesClose])
}

func matchingSQLParenthesis(value string, open int) int {
	depth := 0
	for index := open; index < len(value); index++ {
		switch value[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func splitSQLList(value string) []string {
	var result []string
	start := 0
	depth := 0
	for index := range value {
		switch value[index] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	return append(result, strings.TrimSpace(value[start:]))
}

func containsSQLPlaceholder(expression string, position int) bool {
	pattern := regexp.MustCompile(`\$` + strconv.Itoa(position) + `\b`)
	return pattern.MatchString(expression)
}
