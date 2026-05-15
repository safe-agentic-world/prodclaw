package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLoggerRedactsSensitiveFieldsAndValues(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	logger.now = func() time.Time { return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC) }
	if err := logger.Info("job.plan", map[string]any{
		"token":   "abc123",
		"message": "using sk-proj-secret",
	}); err != nil {
		t.Fatalf("write log: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	fields := got["fields"].(map[string]any)
	if fields["token"] != "[REDACTED]" {
		t.Fatalf("expected token redaction, got %+v", fields)
	}
	if strings.Contains(fields["message"].(string), "sk-proj-secret") {
		t.Fatalf("expected secret value redaction, got %+v", fields)
	}
}
