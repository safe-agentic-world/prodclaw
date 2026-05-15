package executor

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

const (
	DefaultOutputMaxBytes = 64 * 1024
	DefaultOutputMaxLines = 200
	DefaultTimeout        = 30 * time.Second

	ResultSuccess         = "success"
	ResultDeniedPolicy    = "denied_policy"
	ResultInvalidRequest  = "invalid_request"
	ResultExecutionFailed = "execution_failed"
	ResultTimeout         = "timeout"
	ResultUnsupported     = "unsupported"
)

type RedactionSummary struct {
	Applied   bool `json:"applied"`
	Truncated bool `json:"truncated"`
}

type Outcome struct {
	ResultCode       string
	Retryable        bool
	RedactionSummary RedactionSummary
}

func SanitizeOutput(redactor *redact.Redactor, text string, obligations map[string]any, requestedMaxBytes, requestedMaxLines int) (string, RedactionSummary) {
	redacted := redactText(redactor, text)
	out := redacted
	summary := RedactionSummary{Applied: redacted != text}
	maxBytes := effectiveLimit(DefaultOutputMaxBytes, obligationInt(obligations["output_max_bytes"]), requestedMaxBytes)
	if maxBytes >= 0 && len(out) > maxBytes {
		out = trimToBytes(out, maxBytes)
		summary.Truncated = true
	}
	maxLines := effectiveLimit(DefaultOutputMaxLines, obligationInt(obligations["output_max_lines"]), requestedMaxLines)
	if maxLines >= 0 {
		limited, truncated := trimToLines(out, maxLines)
		out = limited
		summary.Truncated = summary.Truncated || truncated
	}
	return out, summary
}

func WithTimeout(ctx context.Context, obligations map[string]any) (context.Context, context.CancelFunc) {
	timeout := DefaultTimeout
	if raw, ok := obligations["timeout_ms"]; ok {
		if parsed, ok := intValue(raw); ok && parsed > 0 {
			timeout = time.Duration(parsed) * time.Millisecond
		}
	}
	return context.WithTimeout(ctx, timeout)
}

func ClassifyError(err error) (string, bool) {
	switch {
	case err == nil:
		return ResultSuccess, false
	case errors.Is(err, context.DeadlineExceeded):
		return ResultTimeout, true
	default:
		return ResultExecutionFailed, false
	}
}

func obligationInt(raw any) int {
	value, ok := intValue(raw)
	if !ok {
		return -1
	}
	return value
}

func intValue(raw any) (int, bool) {
	switch typed := raw.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case jsonNumber:
		value, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(value), true
	default:
		return 0, false
	}
}

// jsonNumber is the small subset needed from encoding/json.Number without
// importing encoding/json into call sites that only need executor helpers.
type jsonNumber interface {
	Int64() (int64, error)
}

func effectiveLimit(defaultLimit, obligationLimit, requestedLimit int) int {
	limit := defaultLimit
	if obligationLimit >= 0 && obligationLimit < limit {
		limit = obligationLimit
	}
	if requestedLimit > 0 && requestedLimit < limit {
		limit = requestedLimit
	}
	return limit
}

func redactText(redactor *redact.Redactor, text string) string {
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	return redactor.RedactText(text)
}

func trimToBytes(text string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(text) <= maxBytes {
		return text
	}
	out := text[:maxBytes]
	for len(out) > 0 && !utf8.ValidString(out) {
		_, size := utf8.DecodeLastRuneInString(out)
		if size <= 0 {
			break
		}
		out = out[:len(out)-size]
	}
	return out
}

func trimToLines(text string, maxLines int) (string, bool) {
	if maxLines < 0 {
		return text, false
	}
	if maxLines == 0 {
		return "", text != ""
	}
	lines := strings.SplitAfter(text, "\n")
	if len(lines) <= maxLines {
		return text, false
	}
	return strings.Join(lines[:maxLines], ""), true
}
