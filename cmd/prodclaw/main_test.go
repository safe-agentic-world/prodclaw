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

func TestProfilesListShowsBuiltInProfiles(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runProfiles([]string{"list", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("profiles list exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var records []struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &records); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if len(records) != 2 {
		t.Fatalf("profile count = %d, want 2: %+v", len(records), records)
	}
	if records[0].Name != "ci-standard" || records[0].Hash == "" {
		t.Fatalf("unexpected first profile: %+v", records[0])
	}
}

func TestProfilesShowReturnsYAML(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runProfiles([]string{"show", "ci-standard"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("profiles show exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "version: v1") || !strings.Contains(stdout.String(), "ci-standard-deny-protected-branch-push") {
		t.Fatalf("unexpected profile yaml:\n%s", stdout.String())
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
	if !strings.Contains(stderr.String(), "--bundle or --profile is required") {
		t.Fatalf("expected bundle error, got %q", stderr.String())
	}
}

func TestPolicyCheckUsesBuiltInProfile(t *testing.T) {
	_, actionFile := writePolicyFixture(t, "ALLOW")
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"check", "--profile", "ci-standard", "--action", actionFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("policy check exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got policyCheckOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Decision != "ALLOW" {
		t.Fatalf("decision = %s, want ALLOW: %+v", got.Decision, got)
	}
}

func TestPolicyCheckRejectsBundleAndProfileTogether(t *testing.T) {
	bundle, actionFile := writePolicyFixture(t, "ALLOW")
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"check", "--bundle", bundle, "--profile", "ci-standard", "--action", actionFile}, &stdout, &stderr)
	if code != 30 {
		t.Fatalf("policy check exit code = %d, want 30", code)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got %q", stderr.String())
	}
}

func TestJobRunDryRunDefaultsToCIStrictProfile(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Mode != "dry_run" || got.Agent != "codex" {
		t.Fatalf("unexpected job metadata: %+v", got)
	}
	if got.Profile != "ci-strict" || got.PolicySource != "embedded_profile" || got.PolicyBundleHash == "" {
		t.Fatalf("expected embedded ci-strict profile metadata, got %+v", got)
	}
}

func TestJobRunRejectsBundleAndProfileTogether(t *testing.T) {
	bundle, _ := writePolicyFixture(t, "ALLOW")
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run", "--bundle", bundle, "--profile", "ci-standard"}, &stdout, &stderr)
	if code != 30 {
		t.Fatalf("job run exit code = %d, want 30", code)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got %q", stderr.String())
	}
}

func TestJobRunLoadsConfigWithFlagPrecedence(t *testing.T) {
	dir := t.TempDir()
	taskPath := filepath.Join(dir, "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	configPath := filepath.Join(dir, "prodclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"agent":"claude","task":"`+escapeJSONPath(taskPath)+`","profile":"ci-standard"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("PRODCLAW_PROFILE", "ci-strict")
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--config", configPath, "--agent", "codex", "--dry-run"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Agent != "codex" || got.Profile != "ci-strict" {
		t.Fatalf("expected flags over env over file, got %+v", got)
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

func escapeJSONPath(path string) string {
	data, _ := json.Marshal(path)
	return strings.Trim(string(data), `"`)
}
