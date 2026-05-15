package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

func TestSanitizeOutputRedactsAndCaps(t *testing.T) {
	out, summary := SanitizeOutput(redact.DefaultRedactor(), "Authorization: Bearer abcdefghijklmnop\nline2\nline3\n", map[string]any{
		"output_max_bytes": 80,
		"output_max_lines": 2,
	}, 0, 0)
	if strings.Contains(out, "abcdefghijklmnop") {
		t.Fatalf("expected secret redaction, got %q", out)
	}
	if strings.Count(out, "\n") != 2 {
		t.Fatalf("expected line cap, got %q", out)
	}
	if !summary.Applied || !summary.Truncated {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestWithTimeoutUsesPolicyObligation(t *testing.T) {
	ctx, cancel := WithTimeout(context.Background(), map[string]any{"timeout_ms": 1})
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected timeout context to expire")
	}
}
