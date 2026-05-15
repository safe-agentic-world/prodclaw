package audit

import (
	"testing"

	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

func TestValidateEventSchema(t *testing.T) {
	event := Event{
		SchemaVersion:     SchemaVersionV1,
		Timestamp:         "2026-05-15T12:00:00Z",
		ActionID:          "act-1",
		TraceID:           "trace-1",
		Tool:              "run_command",
		ActionType:        "process.exec",
		Resource:          "file://workspace/",
		ParamsHash:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Principal:         "system",
		Agent:             "prodclaw",
		Environment:       "ci",
		ActionFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Decision:          "ALLOW",
		ReasonCode:        "allow_by_rule",
		MatchedRuleIDs:    []string{"allow-git-status"},
		PolicyBundleHash:  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ResultCode:        "success",
		Retryable:         false,
		RedactionSummary:  executor.RedactionSummary{},
	}
	if err := ValidateEventSchema(event); err != nil {
		t.Fatalf("validate event: %v", err)
	}
	event.Decision = "REQUIRE_APPROVAL"
	if err := ValidateEventSchema(event); err == nil {
		t.Fatal("expected unsupported decision rejection")
	}
}

func TestRedactEventDoesNotLeakKnownSecretPatterns(t *testing.T) {
	event := RedactEvent(Event{
		SchemaVersion:    SchemaVersionV1,
		Resource:         "file://workspace/sk-proj-secret",
		Principal:        "Authorization: Bearer abcdefghijklmnop",
		MatchedRuleIDs:   []string{"rule-sk-proj-secret"},
		RedactionSummary: executor.RedactionSummary{},
	}, redact.DefaultRedactor())
	if event.Resource == "file://workspace/sk-proj-secret" || event.Principal == "Authorization: Bearer abcdefghijklmnop" || event.MatchedRuleIDs[0] == "rule-sk-proj-secret" {
		t.Fatalf("expected audit redaction, got %+v", event)
	}
}
