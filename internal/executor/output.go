package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/prodclaw/internal/redact"
	"github.com/safe-agentic-world/prodclaw/internal/scan"
)

const (
	DefaultOutputMaxBytes = 64 * 1024
	DefaultOutputMaxLines = 200
	DefaultTimeout        = 30 * time.Second

	ResultSuccess          = "success"
	ResultDeniedPolicy     = "denied_policy"
	ResultBudgetExceeded   = "budget_exhausted"
	ResultInvalidRequest   = "invalid_request"
	ResultExecutionFailed  = "execution_failed"
	ResultTimeout          = "timeout"
	ResultUnsupported      = "unsupported"
	ResultReturnPathDenied = "return_path_denied"
)

const (
	ReturnPathAllow = "allow"
	ReturnPathFence = "fence"
	ReturnPathStrip = "strip"
	ReturnPathDeny  = "deny"
)

type RedactionSummary struct {
	Applied            bool           `json:"applied"`
	Truncated          bool           `json:"truncated"`
	ScannerRulePack    string         `json:"scanner_rule_pack,omitempty"`
	ReturnPathHandling string         `json:"return_path_handling,omitempty"`
	ScannerFindings    []scan.Finding `json:"scanner_findings,omitempty"`
	Fenced             bool           `json:"fenced,omitempty"`
	Stripped           bool           `json:"stripped,omitempty"`
	Denied             bool           `json:"denied,omitempty"`
}

type Outcome struct {
	ResultCode        string
	Retryable         bool
	RedactionSummary  RedactionSummary
	ReturnedBytes     int
	ArtifactBytes     int
	HTTPStatusCode    int
	HTTPFinalResource string
	HTTPRedirectHops  int
}

func SanitizeOutput(redactor *redact.Redactor, text string, obligations map[string]any, requestedMaxBytes, requestedMaxLines int) (string, RedactionSummary) {
	return SanitizeOutputForLocation(redactor, text, obligations, requestedMaxBytes, requestedMaxLines, "executor.response")
}

func SanitizeOutputForLocation(redactor *redact.Redactor, text string, obligations map[string]any, requestedMaxBytes, requestedMaxLines int, locationKind string) (string, RedactionSummary) {
	redacted := redactText(redactor, text)
	out := redacted
	mode, modeOK := returnPathHandling(obligations)
	findings := scan.ScanText(out, locationKind)
	if !modeOK {
		findings = append(findings, scan.NewFinding("return_path.invalid_handling", "high", locationKind, fmt.Sprintf("%T", obligations["return_path_handling"])))
		findings = scan.DedupeFindings(findings)
		mode = ReturnPathDeny
	}
	summary := RedactionSummary{
		Applied:            redacted != text,
		ScannerRulePack:    scan.RulePackVersion,
		ReturnPathHandling: mode,
		ScannerFindings:    findings,
	}
	if len(findings) > 0 {
		switch mode {
		case ReturnPathFence:
			out = fenceReturnPath(out, findings)
			summary.Fenced = true
		case ReturnPathStrip:
			stripped := scan.StripText(out)
			if stripped != out {
				out = stripped
				summary.Stripped = true
			}
		case ReturnPathDeny:
			out = "[ProdClaw return-path denied: scanner findings blocked content]"
			summary.Denied = true
		}
	}
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
	summary.Applied = summary.Applied || summary.Fenced || summary.Stripped || summary.Denied
	return out, summary
}

func MergeRedactionSummaries(first, second RedactionSummary) RedactionSummary {
	out := RedactionSummary{
		Applied:            first.Applied || second.Applied,
		Truncated:          first.Truncated || second.Truncated,
		ScannerRulePack:    mergeLabel(first.ScannerRulePack, second.ScannerRulePack),
		ReturnPathHandling: mergeLabel(first.ReturnPathHandling, second.ReturnPathHandling),
		ScannerFindings:    scan.DedupeFindings(append(append([]scan.Finding{}, first.ScannerFindings...), second.ScannerFindings...)),
		Fenced:             first.Fenced || second.Fenced,
		Stripped:           first.Stripped || second.Stripped,
		Denied:             first.Denied || second.Denied,
	}
	return out
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
	case errors.Is(err, ErrRedirectDenied), errors.Is(err, ErrRedirectHopLimit), errors.Is(err, ErrRedirectDisallowedHost), errors.Is(err, ErrHTTPRedirectAllowlistReq):
		return ResultDeniedPolicy, false
	case errors.Is(err, ErrHTTPRequestTooLarge), errors.Is(err, ErrRedirectInvalidTarget):
		return ResultInvalidRequest, false
	case errors.Is(err, context.DeadlineExceeded):
		return ResultTimeout, true
	default:
		return ResultExecutionFailed, false
	}
}

func returnPathHandling(obligations map[string]any) (string, bool) {
	if obligations == nil {
		return ReturnPathStrip, true
	}
	raw, ok := obligations["return_path_handling"]
	if !ok {
		return ReturnPathStrip, true
	}
	value, ok := raw.(string)
	if !ok {
		return ReturnPathDeny, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ReturnPathStrip:
		return ReturnPathStrip, true
	case ReturnPathAllow:
		return ReturnPathAllow, true
	case ReturnPathFence:
		return ReturnPathFence, true
	case ReturnPathDeny:
		return ReturnPathDeny, true
	default:
		return ReturnPathDeny, false
	}
}

func fenceReturnPath(text string, findings []scan.Finding) string {
	return fmt.Sprintf("[ProdClaw fenced return-path content: rule_pack=%s findings=%d]\n```text\n%s\n```\n", scan.RulePackVersion, len(findings), text)
}

func mergeLabel(first, second string) string {
	switch {
	case first == "":
		return second
	case second == "":
		return first
	case first == second:
		return first
	default:
		return "mixed"
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
