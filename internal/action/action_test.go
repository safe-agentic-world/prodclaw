package action

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/safe-agentic-world/prodclaw/internal/identity"
)

func TestDecodeActionRequestRejectsUnknownFields(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}},"unknown":1}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestDecodeActionRequestAllowsContextExtensions(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{"foo":1,"bar":{"x":"y"}}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("expected extensions to be allowed, got %v", err)
	}
}

func TestDecodeActionRequestRejectsUnknownContextField(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"foo":"bar"}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected unknown context field error")
	}
}

func TestDecodeActionRequestRequiresSchemaVersion(t *testing.T) {
	payload := `{"action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected schema_version error")
	}
}

func TestDecodeActionRequestRequiresParamsAndContext(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","trace_id":"trace1"}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected params/context error")
	}
}

func TestDecodeActionRequestRejectsInvalidIDs(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"bad id","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected invalid action_id error")
	}
}

func TestDecodeActionRequestEnforcesParamsSize(t *testing.T) {
	large := strings.Repeat("x", MaxParamsBytes+1)
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{"data":"` + large + `"},"trace_id":"trace1","context":{"extensions":{}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected params size error")
	}
}

func TestToActionOverridesAgentSuppliedIdentityContext(t *testing.T) {
	req := Request{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params:        []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`),
		TraceID:       "trace1",
		Context: Context{Extensions: map[string]json.RawMessage{
			"prodclaw.identity": []byte(`{"principal":"attacker","agent":"attacker","environment":"local","ci":{"branch":"main"}}`),
		}},
	}
	act, err := ToAction(req, identity.VerifiedIdentity{
		Principal:   "github:org/repo:actor",
		Agent:       "codex",
		Environment: "ci",
		CI:          identity.CIIdentity{Provider: "github", Branch: "feature/acdk-1"},
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	var injected identity.VerifiedIdentity
	if err := json.Unmarshal(act.Context.Extensions["prodclaw.identity"], &injected); err != nil {
		t.Fatalf("decode injected identity: %v", err)
	}
	if injected.Principal != "github:org/repo:actor" || injected.Agent != "codex" || injected.Environment != "ci" || injected.CI.Branch != "feature/acdk-1" {
		t.Fatalf("agent-supplied identity was not overridden: %+v", injected)
	}
}

func TestActionSchemaValidation(t *testing.T) {
	req := Request{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace1",
		Context:       Context{},
	}
	act, err := ToAction(req, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "prodclaw",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("expected schema validation to pass, got %v", err)
	}
	act.ActionType = ""
	if err := ValidateActionSchema(act); err == nil {
		t.Fatal("expected schema validation error for empty action_type")
	}
}
