package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/prodclaw/internal/policy"
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
		Name   string `json:"name"`
		Source string `json:"source"`
		Hash   string `json:"hash"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &records); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if len(records) != 2 {
		t.Fatalf("profile count = %d, want 2: %+v", len(records), records)
	}
	if records[0].Name != "ci-standard" || records[0].Source != "embedded" || records[0].Hash == "" {
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

func TestProfilesVerifyReportsEmbeddedAndCanonicalState(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runProfiles([]string{"verify", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("profiles verify exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var records []struct {
		Name             string `json:"name"`
		Source           string `json:"source"`
		EmbeddedValid    bool   `json:"embedded_valid"`
		CanonicalPresent bool   `json:"canonical_present"`
		CanonicalMatches bool   `json:"canonical_matches"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &records); err != nil {
		t.Fatalf("decode verify output: %v\n%s", err, stdout.String())
	}
	if len(records) != 2 {
		t.Fatalf("verify record count = %d, want 2", len(records))
	}
	for _, record := range records {
		if record.Source != "embedded" || !record.EmbeddedValid || !record.CanonicalPresent || !record.CanonicalMatches {
			t.Fatalf("unexpected verify record: %+v", record)
		}
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
	if !strings.Contains(stderr.String(), "--bundle, --profile, or layered policy inputs are required") {
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

func TestMCPReadinessLogsToStderrOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCP([]string{"--profile", "ci-standard"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("mcp exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("expected MCP stdout to stay protocol-only and empty without requests, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "mcp.start") {
		t.Fatalf("expected readiness log on stderr, got %q", stderr.String())
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

func TestPolicyExplainIncludesLayeredPolicyProvenance(t *testing.T) {
	base, env, actionPath := writeLayeredPolicyFixture(t)
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{
		"explain",
		"--policy-baseline", base,
		"--policy-environment", env,
		"--action", actionPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("policy explain exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got policyExplainOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Decision != "DENY" || got.PolicySource != "layered_bundles" || len(got.PolicyBundleInputs) != 2 {
		t.Fatalf("unexpected layered policy output: %+v", got)
	}
	if got.PolicyBundleInputs[0].Role != "baseline" || got.PolicyBundleInputs[1].Role != "environment" {
		t.Fatalf("unexpected policy input order: %+v", got.PolicyBundleInputs)
	}
	if len(got.MatchedRuleProvenance) != 2 || got.MatchedRuleProvenance[0].BundleSource == "" || got.MatchedRuleProvenance[1].BundleSource == "" {
		t.Fatalf("expected matched source bundle provenance, got %+v", got.MatchedRuleProvenance)
	}
}

func TestPolicyRejectsAmbiguousLayeredSelectionAndInvalidHash(t *testing.T) {
	bundle, actionPath := writePolicyFixture(t, "ALLOW")
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"check", "--bundle", bundle, "--policy-baseline", bundle, "--action", actionPath}, &stdout, &stderr)
	if code != 30 || !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected ambiguous policy failure, code=%d stderr=%q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runPolicy([]string{"check", "--policy-baseline", bundle, "--policy-baseline-sha256", "not-a-hash", "--action", actionPath}, &stdout, &stderr)
	if code != 30 || !strings.Contains(stderr.String(), "invalid sha256") {
		t.Fatalf("expected invalid hash failure, code=%d stderr=%q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runPolicy([]string{"check", "--policy-baseline", bundle, "--policy-baseline-sha256", strings.Repeat("0", 64), "--action", actionPath}, &stdout, &stderr)
	if code != 30 || !strings.Contains(stderr.String(), "hash mismatch") {
		t.Fatalf("expected hash mismatch failure, code=%d stderr=%q", code, stderr.String())
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

func TestJobRunSingleBundleRemainsExplicitCustomerPolicy(t *testing.T) {
	bundle, _ := writePolicyFixture(t, "ALLOW")
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run", "--bundle", bundle}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Profile != "" || got.PolicySource != "customer_bundle" || len(got.PolicyBundleInputs) != 1 || got.PolicyBundleInputs[0].Path != bundle {
		t.Fatalf("single bundle should not inherit defaults: %+v", got)
	}
}

func TestJobRunLayeredPolicyMetadata(t *testing.T) {
	base, env, _ := writeLayeredPolicyFixture(t)
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	baseBundle, err := policy.LoadBundle(base)
	if err != nil {
		t.Fatalf("load base bundle: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--dry-run",
		"--policy-baseline", base,
		"--policy-baseline-sha256", baseBundle.Hash,
		"--policy-environment", env,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.PolicySource != "layered_bundles" || len(got.PolicyBundleInputs) != 2 || len(got.PolicyBundleSources) != 2 {
		t.Fatalf("unexpected layered job metadata: %+v", got)
	}
	if got.PolicyBundleInputs[0].Role != "baseline" || got.PolicyBundleInputs[1].Role != "environment" || got.PolicyBundleHash == "" {
		t.Fatalf("unexpected layered input ordering: %+v", got.PolicyBundleInputs)
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

func TestJobRunControlledCIIncludesVerifiedIdentity(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_PATH", "firstgroup365/devops/codex-ci-agent")
	t.Setenv("CI_COMMIT_REF_NAME", "feature/acdk-1")
	t.Setenv("CI_COMMIT_SHA", "abcdef0123456789")
	t.Setenv("CI_PIPELINE_ID", "2002")
	t.Setenv("CI_JOB_ID", "3003")
	t.Setenv("GITLAB_USER_LOGIN", "ps-tech-geek")
	t.Setenv("CI_PIPELINE_SOURCE", "push")
	t.Setenv("GITLAB_TOKEN", "raw-token-never-returned")

	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run", "--controlled-ci"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if !got.ControlledCI || got.Principal != "gitlab:firstgroup365/devops/codex-ci-agent:ps-tech-geek" || got.Environment != "ci" {
		t.Fatalf("unexpected identity metadata: %+v", got)
	}
	if got.CIIdentity.Provider != "gitlab" || got.CIIdentity.Branch != "feature/acdk-1" || got.CIIdentity.PipelineID != "2002" {
		t.Fatalf("unexpected CI identity: %+v", got.CIIdentity)
	}
	payload := stdout.String() + stderr.String()
	if strings.Contains(payload, "raw-token-never-returned") {
		t.Fatalf("secret leaked in job output: %s", payload)
	}
	if !got.CredentialExposure.CredentialScopes["gitlab_token"] {
		t.Fatalf("expected credential scope summary, got %+v", got.CredentialExposure)
	}
}

func TestJobRunControlledCIFailsWithoutSupportedIdentity(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run", "--controlled-ci"}, &stdout, &stderr)
	if code != 40 {
		t.Fatalf("job run exit code = %d, want 40; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "controlled CI identity is required") {
		t.Fatalf("expected controlled CI identity error, got %q", stderr.String())
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

func writeLayeredPolicyFixture(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	env := filepath.Join(dir, "env.yaml")
	actionPath := filepath.Join(dir, "action.json")
	if err := os.WriteFile(base, []byte(`version: v1
rules:
  - id: allow-workspace-read
    action_type: fs.read
    resource: file://workspace/**
    decision: ALLOW
`), 0o600); err != nil {
		t.Fatalf("write base bundle: %v", err)
	}
	if err := os.WriteFile(env, []byte(`version: v1
rules:
  - id: deny-dotenv
    action_type: fs.read
    resource: file://workspace/.env
    decision: DENY
`), 0o600); err != nil {
		t.Fatalf("write env bundle: %v", err)
	}
	if err := os.WriteFile(actionPath, []byte(`{
  "schema_version": "v1",
  "action_id": "act-1",
  "action_type": "fs.read",
  "resource": "file://workspace/.env",
  "params": {},
  "trace_id": "trace-1",
  "context": {"extensions": {}}
}`), 0o600); err != nil {
		t.Fatalf("write action: %v", err)
	}
	return base, env, actionPath
}

func escapeJSONPath(path string) string {
	data, _ := json.Marshal(path)
	return strings.Trim(string(data), `"`)
}
