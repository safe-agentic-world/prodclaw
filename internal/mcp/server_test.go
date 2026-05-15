package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

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
	server.commandExec = func(ctx context.Context, workspace string, argv []string, cwd string) commandResult {
		executed = append(executed, append([]string(nil), argv...))
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
	decision, err := server.authorize("run_command", "process.exec", "file://workspace/", map[string]any{"argv": []string{"git", "push", "origin", "main"}})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %s, want DENY", decision.Decision)
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
