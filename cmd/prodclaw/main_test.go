package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	if code := run([]string{"version"}); code != 0 {
		t.Fatalf("version exit code = %d, want 0", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if code := run([]string{"unknown"}); code != 2 {
		t.Fatalf("unknown command exit code = %d, want 2", code)
	}
}

func TestPolicyCheckAllowsMatchingAction(t *testing.T) {
	bundle, actionFile := writePolicyFixture(t, "ALLOW")
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"check", "--bundle", bundle, "--action", actionFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("policy check exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got policyCheckOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Decision != "ALLOW" || got.ReasonCode != "allow_by_rule" {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if len(got.MatchedRuleIDs) != 1 || got.MatchedRuleIDs[0] != "allow-git-status" {
		t.Fatalf("unexpected matched rules: %+v", got.MatchedRuleIDs)
	}
}

func TestPolicyExplainIncludesDenyDetails(t *testing.T) {
	bundle, actionFile := writePolicyFixture(t, "DENY")
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"explain", "--bundle", bundle, "--action", actionFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("policy explain exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got policyExplainOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Decision != "DENY" || got.ReasonCode != "deny_by_rule" {
		t.Fatalf("unexpected decision: %+v", got.policyCheckOutput)
	}
	if len(got.DenyRules) != 1 || got.DenyRules[0].RuleID != "allow-git-status" {
		t.Fatalf("unexpected deny details: %+v", got.DenyRules)
	}
}

func TestPolicyCheckMissingBundleFailsClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"check", "--action", "action.json"}, &stdout, &stderr)
	if code != 30 {
		t.Fatalf("policy check exit code = %d, want 30", code)
	}
	if !strings.Contains(stderr.String(), "--bundle is required") {
		t.Fatalf("expected bundle error, got %q", stderr.String())
	}
}

func writePolicyFixture(t *testing.T, decision string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bundle := filepath.Join(dir, "policy.yaml")
	actionFile := filepath.Join(dir, "action.json")
	bundleText := `version: v1
rules:
  - id: allow-git-status
    action_type: process.exec
    resource: file://workspace/
    decision: ` + decision + `
    principals: ["system"]
    agents: ["prodclaw"]
    environments: ["ci"]
    exec_match:
      argv_patterns:
        - ["git", "status"]
`
	actionText := `{
  "schema_version": "v1",
  "action_id": "act-1",
  "action_type": "process.exec",
  "resource": "file://workspace/",
  "params": {
    "argv": ["git", "status"],
    "cwd": "",
    "env_allowlist_keys": []
  },
  "trace_id": "trace-1",
  "context": {"extensions": {}}
}
`
	if err := os.WriteFile(bundle, []byte(bundleText), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(actionFile, []byte(actionText), 0o600); err != nil {
		t.Fatalf("write action: %v", err)
	}
	return bundle, actionFile
}
