package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/profiles"
)

func TestServerAllowsAndDeniesRunCommand(t *testing.T) {
	bundle, err := profiles.Load("ci-standard")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	server, err := NewServer(Options{Bundle: bundle, Workspace: t.TempDir()})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var executed [][]string
	server.commandExec = func(ctx context.Context, workspace string, req commandRequest) commandResult {
		executed = append(executed, append([]string(nil), req.Argv...))
		return commandResult{Stdout: "ok\n"}
	}
	in := strings.NewReader(
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"run_command\",\"arguments\":{\"argv\":[\"git\",\"status\"]}}}\n" +
			"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"run_command\",\"arguments\":{\"argv\":[\"git\",\"push\",\"origin\",\"main\"]}}}\n",
	)
	var out bytes.Buffer
	if err := server.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("response lines = %d, want 2:\n%s", len(lines), out.String())
	}
	first := decodeResponse(t, lines[0])
	if first.Error != nil {
		t.Fatalf("allow response error: %+v", first.Error)
	}
	if strings.Contains(mustMarshal(t, first.Result), `"isError":true`) {
		t.Fatalf("allow response unexpectedly errored: %+v", first.Result)
	}
	second := decodeResponse(t, lines[1])
	if second.Error != nil {
		t.Fatalf("deny response protocol error: %+v", second.Error)
	}
	if !strings.Contains(mustMarshal(t, second.Result), `"isError":true`) {
		t.Fatalf("deny response missing isError: %+v", second.Result)
	}
	if len(executed) != 1 || strings.Join(executed[0], " ") != "git status" {
		t.Fatalf("executed commands = %+v, want only git status", executed)
	}
}

func TestAuthorizeUsesProfilePolicy(t *testing.T) {
	bundle, err := profiles.Load("ci-standard")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	server, err := NewServer(Options{Bundle: bundle, Workspace: t.TempDir()})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	auth, err := server.authorize("run_command", "process.exec", "file://workspace/", map[string]any{"argv": []string{"git", "push", "origin", "main"}, "cwd": "", "env_allowlist_keys": []string{}, "stdin_mode": "none", "shell_mode": false, "output_max_bytes": 0, "output_max_lines": 0})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.decision.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %s, want DENY", auth.decision.Decision)
	}
}

func TestAuthorizeWritesCanonicalAuditEvent(t *testing.T) {
	bundle, err := profiles.Load("ci-standard")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	server, err := NewServer(Options{Bundle: bundle, Workspace: t.TempDir(), AuditPath: auditPath})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	server.commandExec = func(ctx context.Context, workspace string, req commandRequest) commandResult {
		return commandResult{Stdout: "ok\n"}
	}
	if _, err := server.runCommand(context.Background(), json.RawMessage(`{"argv":["git","status"]}`)); err != nil {
		t.Fatalf("run command: %v", err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if event.SchemaVersion != audit.SchemaVersionV1 || event.ActionFingerprint == "" || event.ParamsHash == "" || event.ResultCode != "success" || event.ExecCondition != "argv_pattern_match" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	if err := audit.ValidateEventSchema(event); err != nil {
		t.Fatalf("validate audit schema: %v", err)
	}
}

func TestReadFileRedactsCapsAndAuditsWithoutSecretLeak(t *testing.T) {
	bundle := mustBundle(t, `version: v1
rules:
  - id: allow-read
    action_type: fs.read
    resource: file://workspace/**
    decision: ALLOW
    obligations:
      output_max_lines: 1
`)
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "secret.txt"), []byte("Authorization: Bearer abcdefghijklmnop\nline2\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	server, err := NewServer(Options{Bundle: bundle, Workspace: workspace, AuditPath: auditPath})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	result, err := server.readFile(context.Background(), json.RawMessage(`{"path":"secret.txt"}`))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	payload := mustMarshal(t, result)
	if strings.Contains(payload, "abcdefghijklmnop") || !strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("expected redacted response, got %s", payload)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if strings.Contains(string(data), "abcdefghijklmnop") {
		t.Fatalf("expected redacted audit artifact, got %s", string(data))
	}
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if !event.RedactionSummary.Applied || !event.RedactionSummary.Truncated {
		t.Fatalf("expected redaction summary, got %+v", event)
	}
}

func TestServerSupportsArtifactWriteAndForwardedToolCalls(t *testing.T) {
	bundle := mustBundle(t, `version: v1
rules:
  - id: allow-artifact
    action_type: artifact.write
    resource: artifact://job/**
    decision: ALLOW
  - id: allow-upstream-tool
    action_type: mcp.call
    resource: mcp://retail/refund.request
    decision: ALLOW
`)
	workspace := t.TempDir()
	artifactDir := t.TempDir()
	server, err := NewServer(Options{
		Bundle:      bundle,
		Workspace:   workspace,
		ArtifactDir: artifactDir,
		ForwardTool: func(ctx context.Context, server, tool string, args json.RawMessage) (any, error) {
			return map[string]any{"server": server, "tool": tool, "args": json.RawMessage(args)}, nil
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if _, err := server.writeArtifact(context.Background(), json.RawMessage(`{"path":"summary.txt","content":"ok"}`)); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(artifactDir, "summary.txt")); err != nil || string(data) != "ok" {
		t.Fatalf("artifact content = %q, err=%v", string(data), err)
	}
	result, err := server.callToolForward(context.Background(), json.RawMessage(`{"server":"retail","tool":"refund.request","arguments":{"order_id":"ORD-1001"}}`))
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !strings.Contains(mustMarshal(t, result), `"result_code":"success"`) {
		t.Fatalf("expected successful forwarded tool result, got %+v", result)
	}
}

func TestCommandEnvironmentUsesSafeBaselinePlusExplicitAllowlist(t *testing.T) {
	t.Setenv("PATH", "safe-path")
	t.Setenv("HOME", "safe-home")
	t.Setenv("CUSTOM_ALLOWED", "custom-value")
	t.Setenv("GITLAB_TOKEN", "must-not-leak")
	env := commandEnvironment([]string{"CUSTOM_ALLOWED"})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH=safe-path") || !strings.Contains(joined, "HOME=safe-home") || !strings.Contains(joined, "CUSTOM_ALLOWED=custom-value") {
		t.Fatalf("expected safe baseline and allowlist, got %q", joined)
	}
	if strings.Contains(joined, "GITLAB_TOKEN=must-not-leak") {
		t.Fatalf("unexpected secret env leak: %q", joined)
	}
}

func decodeResponse(t *testing.T, line string) rpcResponse {
	t.Helper()
	var resp rpcResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("decode response: %v\n%s", err, line)
	}
	return resp
}

func mustMarshal(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}

func mustBundle(t *testing.T, data string) policy.Bundle {
	t.Helper()
	bundle, err := policy.LoadBundleBytes([]byte(data), "bundle.yaml")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return bundle
}
