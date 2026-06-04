package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agentkit "github.com/safe-agentic-world/prodclaw/internal/agent"
	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
	jobkit "github.com/safe-agentic-world/prodclaw/internal/job"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/scan"
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
	if got.AssuranceLevel == "" || len(got.MediationCoverage) == 0 {
		t.Fatalf("expected assurance metadata in explain output: %+v", got)
	}
	if got.WhyDenied == "" || got.SafeRemediationHint == "" {
		t.Fatalf("expected incident-review denial guidance, got %+v", got)
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
	if !got.LaunchPlanned || got.MCPWiringMethod != agentkit.MCPWiringCodexConfigOverride || !got.LaunchPlan.MCPAttachmentVerified {
		t.Fatalf("expected verified codex launch plan, got %+v", got)
	}
	if got.AgentCapabilities.RequiresGlobalConfigMutation || len(got.LaunchPlan.MCPConfig.MCPServers) != 1 {
		t.Fatalf("expected isolated generated mcp config, got %+v", got)
	}
	if got.AssuranceLevel == "" || len(got.MediationCoverage) == 0 {
		t.Fatalf("expected assurance metadata in job output: %+v", got)
	}
}

func TestJobRunDryRunAcceptsTaskFileFlag(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task-file", taskPath, "--dry-run"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Task != taskPath {
		t.Fatalf("task = %q, want %q", got.Task, taskPath)
	}
}

func TestJobRunDryRunAcceptsTaskTextFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task-text", "say hi", "--dry-run"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Task != jobkit.InlineTaskSource {
		t.Fatalf("task = %q, want %q", got.Task, jobkit.InlineTaskSource)
	}
	prompt := strings.Join(got.LaunchPlan.Argv, "\n")
	if !strings.Contains(prompt, "Task source: inline text") || !strings.Contains(prompt, "say hi") {
		t.Fatalf("launch prompt missing inline task text: %s", prompt)
	}
}

func TestJobRunPassesCodexSkipGitRepoCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task-text", "say hi", "--skip-git-repo-check", "--dry-run"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if argv := strings.Join(got.LaunchPlan.Argv, "\x00"); !strings.Contains(argv, "exec\x00--skip-git-repo-check\x00-o\x00") {
		t.Fatalf("launch argv missing codex exec skip flag: %+v", got.LaunchPlan.Argv)
	}
}

func TestJobRunRejectsMultipleTaskSources(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task-file", taskPath, "--task-text", "say hi", "--dry-run"}, &stdout, &stderr)
	if code != jobkit.ExitInvalidConfig {
		t.Fatalf("job run exit code = %d, want %d", code, jobkit.ExitInvalidConfig)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got %q", stderr.String())
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

func TestJobRunDetectsRawUpstreamMCPBeforeLaunch(t *testing.T) {
	t.Setenv("PRODCLAW_RAW_MCP_SERVERS", "filesystem")
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run"}, &stdout, &stderr)
	if code != jobkit.ExitRuntimeGuaranteeFailure {
		t.Fatalf("job run exit code = %d, want %d; stdout=%s stderr=%s", code, jobkit.ExitRuntimeGuaranteeFailure, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "raw upstream MCP servers") {
		t.Fatalf("expected raw MCP overlap error, got %q", stderr.String())
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

func TestDoctorContainerDoesNotPrintStrongClaimWhenChecksFail(t *testing.T) {
	t.Setenv("PRODCLAW_CONTAINER", "true")
	t.Setenv("PRODCLAW_EGRESS_BLOCKED", "")
	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runDoctor([]string{
		"--mode", "container",
		"--workspace", workspace,
		"--artifact-dir", filepath.Join(dir, "artifacts"),
	}, &stdout, &stderr)
	if code != jobkit.ExitRuntimeGuaranteeFailure {
		t.Fatalf("doctor exit code = %d, want %d; stderr=%s", code, jobkit.ExitRuntimeGuaranteeFailure, stderr.String())
	}
	if strings.Contains(stdout.String(), "Strong enforcement claim:") {
		t.Fatalf("doctor printed strong claim despite failed checks:\n%s", stdout.String())
	}
}

func TestAgentProcessEnvironmentUsesAllowlist(t *testing.T) {
	t.Setenv("PATH", "safe-path")
	t.Setenv("HOME", "safe-home")
	t.Setenv("GITHUB_TOKEN", "raw-token")
	t.Setenv("CUSTOM_ALLOWED", "allowed")
	env := agentProcessEnvironment([]string{"CUSTOM_ALLOWED=plan-value", "GITHUB_TOKEN=plan-token"})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH=safe-path") || !strings.Contains(joined, "HOME=safe-home") || !strings.Contains(joined, "CUSTOM_ALLOWED=plan-value") {
		t.Fatalf("expected safe allowlist and non-sensitive plan env, got %q", joined)
	}
	if strings.Contains(joined, "raw-token") || strings.Contains(joined, "plan-token") || strings.Contains(joined, "GITHUB_TOKEN=") {
		t.Fatalf("sensitive env leaked to agent process: %q", joined)
	}
}

func TestJobRunDryRunSupportsClaudeWithSharedMetadataShape(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}

	run := func(agentName string) (jobRunOutput, map[string]json.RawMessage) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := runJob([]string{"run", "--agent", agentName, "--task", taskPath, "--dry-run"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("job run %s exit code = %d, want 0; stderr=%s", agentName, code, stderr.String())
		}
		var got jobRunOutput
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("decode %s output: %v\n%s", agentName, err, stdout.String())
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
			t.Fatalf("decode %s raw output: %v", agentName, err)
		}
		return got, raw
	}

	codex, codexRaw := run("codex")
	claude, claudeRaw := run("claude")
	if claude.MCPWiringMethod != agentkit.MCPWiringConfigFlag || !claude.LaunchPlan.MCPAttachmentVerified {
		t.Fatalf("expected verified claude launch plan, got %+v", claude)
	}
	if got := strings.Join(claude.LaunchPlan.Argv[:3], "\x00"); got != "--strict-mcp-config\x00--mcp-config\x00"+claude.LaunchPlan.MCPConfigPath {
		t.Fatalf("unexpected claude launch argv: %+v", claude.LaunchPlan.Argv)
	}
	if !sameJSONKeys(codexRaw, claudeRaw) {
		t.Fatalf("codex and claude job metadata keys differ: codex=%v claude=%v", mapKeys(codexRaw), mapKeys(claudeRaw))
	}
	if codex.Profile != claude.Profile || codex.PolicyBundleHash != claude.PolicyBundleHash || codex.Task != claude.Task || codex.Workspace != claude.Workspace {
		t.Fatalf("shared job metadata diverged: codex=%+v claude=%+v", codex, claude)
	}
}

func TestJobRunDryRunOutputIsDeterministic(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	run := func() string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--dry-run"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
		}
		return stdout.String()
	}
	if first, second := run(), run(); first != second {
		t.Fatalf("dry-run output changed across identical runs:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestJobRunNoLaunchRecordsAgentVersionWhenAvailable(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	original := discoverJobAgentVersion
	discoverJobAgentVersion = func(agentkit.Builder) string { return "codex 0.130.0" }
	t.Cleanup(func() { discoverJobAgentVersion = original })

	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--workspace", workspace, "--no-launch"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.AgentVersion != "codex 0.130.0" {
		t.Fatalf("expected discovered agent version, got %+v", got)
	}
	if _, err := os.Stat(got.LaunchPlan.MCPConfigPath); err != nil {
		t.Fatalf("expected no-launch to materialize generated mcp config: %v", err)
	}
}

func TestJobRunRealLaunchUsesVerifiedAgentPlan(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}

	for _, agentName := range []string{"codex", "claude"} {
		t.Run(agentName, func(t *testing.T) {
			originalLaunch := launchJobAgent
			originalDiscover := discoverJobAgentVersion
			var launched agentkit.LaunchPlan
			launchJobAgent = func(plan agentkit.LaunchPlan, stdout, stderr io.Writer) error {
				launched = plan
				if agentName == "codex" {
					if path := codexOutputPath(plan.Argv); path != "" {
						if err := os.WriteFile(path, []byte("Completed.\n"), 0o600); err != nil {
							return err
						}
					}
				}
				if agentName == "claude" {
					if _, err := stdout.Write([]byte("Completed.\n")); err != nil {
						return err
					}
				}
				return writeAuditEvent(mcpArgValue(plan, "--audit"), successfulAuditEvent("run_command", "process.exec", "file://workspace/"))
			}
			discoverJobAgentVersion = func(agentkit.Builder) string { return agentName + " version" }
			t.Cleanup(func() {
				launchJobAgent = originalLaunch
				discoverJobAgentVersion = originalDiscover
			})

			var stdout, stderr bytes.Buffer
			code := runJob([]string{"run", "--agent", agentName, "--task", taskPath, "--workspace", workspace}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
			}
			if !launched.MCPAttachmentVerified || len(launched.MCPConfig.MCPServers) != 1 || launched.MCPConfig.MCPServers["prodclaw"].Command != "prodclaw" {
				t.Fatalf("unexpected launched plan: %+v", launched)
			}
			if _, err := os.Stat(launched.MCPConfigPath); err != nil {
				t.Fatalf("expected real launch to materialize generated mcp config: %v", err)
			}
			switch agentName {
			case "codex":
				if launched.MCPWiringMethod != agentkit.MCPWiringCodexConfigOverride || !strings.Contains(strings.Join(launched.Argv, "\x00"), "mcp_servers.prodclaw.command") {
					t.Fatalf("unexpected codex launch plan: %+v", launched)
				}
			case "claude":
				if launched.MCPWiringMethod != agentkit.MCPWiringConfigFlag || len(launched.Argv) < 3 || launched.Argv[0] != "--strict-mcp-config" || launched.Argv[1] != "--mcp-config" || launched.Argv[2] != launched.MCPConfigPath {
					t.Fatalf("unexpected claude launch plan: %+v", launched)
				}
			}
		})
	}
}

func TestJobRunAgentMessageOnlyFailsWithoutGovernedEvidence(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	restore := stubSuccessfulLaunch(t, nil)
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
	}, &stdout, &stderr)
	if code != jobkit.ExitAgentFailure {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitAgentFailure, stderr.String())
	}
	result := readLatestJobResult(t, workspace)
	if len(result.MissingEvidence) != 1 || result.MissingEvidence[0] != "governed_action_audit" {
		t.Fatalf("expected missing governed action evidence, got %+v", result)
	}
}

func TestJobRunDryRunWritesRequiredArtifacts(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	artifactDir := filepath.Join(t.TempDir(), "artifacts")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
		"--artifact-dir", artifactDir,
		"--probe-tools",
		"--dry-run",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("job run exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var got jobRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	for _, path := range []string{
		got.Artifacts.Job,
		got.Artifacts.Plan,
		got.Artifacts.Policy,
		got.Artifacts.PolicyInputs,
		got.Artifacts.Launch,
		got.Artifacts.MCPConfig,
		got.Artifacts.Audit,
		got.Artifacts.Decisions,
		got.Artifacts.ChangedFiles,
		got.Artifacts.Result,
		got.Artifacts.Replay,
		got.Artifacts.Manifest,
		got.Artifacts.Summary,
		got.LaunchPlan.MCPConfigPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	if len(got.PreflightTools) == 0 {
		t.Fatalf("expected preflight tool probe output, got %+v", got)
	}
	var result jobkit.Result
	readJSONFile(t, got.Artifacts.Result, &result)
	if result.ExitReason != jobkit.ReasonDryRun || result.ExitCode != jobkit.ExitSuccess {
		t.Fatalf("unexpected dry-run result: %+v", result)
	}
	var replayStdout, replayStderr bytes.Buffer
	replayCode := runReplay([]string{"--artifact-dir", artifactDir, "--format", "json"}, &replayStdout, &replayStderr)
	if replayCode != jobkit.ExitSuccess {
		t.Fatalf("replay exit code = %d, want %d; stdout=%s stderr=%s", replayCode, jobkit.ExitSuccess, replayStdout.String(), replayStderr.String())
	}
	var replay replayReport
	if err := json.Unmarshal(replayStdout.Bytes(), &replay); err != nil {
		t.Fatalf("decode replay report: %v\n%s", err, replayStdout.String())
	}
	if !replay.Valid || replay.ManifestFiles == 0 {
		t.Fatalf("expected valid replay report, got %+v", replay)
	}
	if err := os.WriteFile(got.Artifacts.Summary, []byte("tampered\n"), 0o600); err != nil {
		t.Fatalf("tamper summary: %v", err)
	}
	replayStdout.Reset()
	replayStderr.Reset()
	replayCode = runReplay([]string{"--artifact-dir", artifactDir}, &replayStdout, &replayStderr)
	if replayCode != jobkit.ExitRuntimeGuaranteeFailure || !strings.Contains(replayStdout.String(), "sha256 mismatch") {
		t.Fatalf("expected replay manifest failure, code=%d stdout=%s stderr=%s", replayCode, replayStdout.String(), replayStderr.String())
	}
}

func TestJobRunExpectedActionMissingFailsClosed(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	restore := stubSuccessfulLaunch(t, nil)
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
		"--expect-action", "process.exec",
	}, &stdout, &stderr)
	if code != jobkit.ExitAgentFailure {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitAgentFailure, stderr.String())
	}
	result := readLatestJobResult(t, workspace)
	if len(result.MissingExpectedActions) != 1 || result.MissingExpectedActions[0] != "process.exec" {
		t.Fatalf("expected missing process.exec evidence, got %+v", result)
	}
}

func TestJobRunPolicyDenialReturnsExit10(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	restore := stubSuccessfulLaunch(t, func(plan agentkit.LaunchPlan, stdout io.Writer) error {
		return writeAuditEvent(mcpArgValue(plan, "--audit"), audit.Event{
			SchemaVersion:     audit.SchemaVersionV1,
			Timestamp:         "2026-05-18T00:00:00Z",
			ActionID:          "deny-1",
			TraceID:           "trace",
			Tool:              "run_command",
			ActionType:        "process.exec",
			Resource:          "file://workspace/",
			ParamsHash:        strings.Repeat("a", 64),
			Principal:         "system",
			Agent:             "codex",
			Environment:       "local",
			ActionFingerprint: strings.Repeat("b", 64),
			Decision:          "DENY",
			ReasonCode:        "deny_by_rule",
			MatchedRuleIDs:    []string{"deny"},
			PolicyBundleHash:  "hash",
			ResultCode:        executor.ResultDeniedPolicy,
			RedactionSummary:  executor.RedactionSummary{},
		})
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
		"--expect-action", "process.exec",
	}, &stdout, &stderr)
	if code != jobkit.ExitPolicyDenied {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitPolicyDenied, stderr.String())
	}
}

func TestJobRunBudgetExhaustionReturnsExit60(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	restore := stubSuccessfulLaunch(t, func(plan agentkit.LaunchPlan, stdout io.Writer) error {
		for idx := 0; idx < 2; idx++ {
			if err := writeAuditEvent(mcpArgValue(plan, "--audit"), successfulAuditEvent("run_command", "process.exec", "file://workspace/")); err != nil {
				return err
			}
		}
		return nil
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
		"--expect-action", "process.exec",
		"--max-tool-calls", "1",
	}, &stdout, &stderr)
	if code != jobkit.ExitBudgetExhausted {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitBudgetExhausted, stderr.String())
	}
}

func TestJobRunMutationWithoutGovernedEvidenceFails(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := initGitWorkspace(t)
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	restore := stubSuccessfulLaunch(t, func(plan agentkit.LaunchPlan, stdout io.Writer) error {
		return os.WriteFile(filepath.Join(plan.Workspace, "README.md"), []byte("changed\n"), 0o600)
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{"run", "--agent", "codex", "--task", taskPath, "--workspace", workspace}, &stdout, &stderr)
	if code != jobkit.ExitAgentFailure {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitAgentFailure, stderr.String())
	}
	result := readLatestJobResult(t, workspace)
	if len(result.MissingMutationEvidence) != 1 || result.MissingMutationEvidence[0] != "README.md" {
		t.Fatalf("expected README.md mutation evidence gap, got %+v", result)
	}
}

func TestJobRunSucceedsWithExpectedGovernedMutationEvidence(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := initGitWorkspace(t)
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	restore := stubSuccessfulLaunch(t, func(plan agentkit.LaunchPlan, stdout io.Writer) error {
		if err := os.WriteFile(filepath.Join(plan.Workspace, "README.md"), []byte("changed\n"), 0o600); err != nil {
			return err
		}
		return writeAuditEvent(mcpArgValue(plan, "--audit"), successfulAuditEvent("write_file", "fs.write", "file://workspace/README.md"))
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
		"--expect-action", "fs.write",
	}, &stdout, &stderr)
	if code != jobkit.ExitSuccess {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitSuccess, stderr.String())
	}
	result := readLatestJobResult(t, workspace)
	if result.ExitReason != jobkit.ReasonSuccess || len(result.MissingExpectedActions) != 0 || len(result.MissingMutationEvidence) != 0 {
		t.Fatalf("expected successful governed mutation result, got %+v", result)
	}
}

func TestJobRunNoLeakHarnessFailsClosedAndRedactsRawArtifactLeak(t *testing.T) {
	taskPath := filepath.Join(t.TempDir(), "task.md")
	workspace := t.TempDir()
	artifactDir := filepath.Join(t.TempDir(), "artifacts")
	if err := os.WriteFile(taskPath, []byte("fix the build\n"), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	secret := scan.CorpusSecrets()[0]
	restore := stubSuccessfulLaunch(t, func(plan agentkit.LaunchPlan, stdout io.Writer) error {
		leakPath := filepath.Join(filepath.Dir(plan.MCPConfigPath), "raw-leak.txt")
		return os.WriteFile(leakPath, []byte("leaked "+secret+"\n"), 0o600)
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runJob([]string{
		"run",
		"--agent", "codex",
		"--task", taskPath,
		"--workspace", workspace,
		"--artifact-dir", artifactDir,
	}, &stdout, &stderr)
	if code != jobkit.ExitInternalError {
		t.Fatalf("job run exit code = %d, want %d; stderr=%s", code, jobkit.ExitInternalError, stderr.String())
	}
	var result jobkit.Result
	readJSONFile(t, filepath.Join(artifactDir, "job-result.json"), &result)
	if result.ExitReason != jobkit.ReasonReturnPathViolation || len(result.ReturnPathFindings) == 0 {
		t.Fatalf("expected return-path violation findings, got %+v", result)
	}
	findingBytes, err := json.Marshal(result.ReturnPathFindings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if strings.Contains(string(findingBytes), secret) {
		t.Fatalf("findings leaked raw secret: %s", findingBytes)
	}
	data, err := os.ReadFile(filepath.Join(artifactDir, "raw-leak.txt"))
	if err != nil {
		t.Fatalf("read raw leak artifact: %v", err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), "[REDACTED]") {
		t.Fatalf("raw artifact leak was not redacted: %q", string(data))
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

func sameJSONKeys(a, b map[string]json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

func mapKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func codexOutputPath(argv []string) string {
	for idx := 0; idx+1 < len(argv); idx++ {
		if argv[idx] == "-o" {
			return argv[idx+1]
		}
	}
	return ""
}

func stubSuccessfulLaunch(t *testing.T, hook func(agentkit.LaunchPlan, io.Writer) error) func() {
	t.Helper()
	original := launchJobAgent
	launchJobAgent = func(plan agentkit.LaunchPlan, stdout, stderr io.Writer) error {
		if hook != nil {
			if err := hook(plan, stdout); err != nil {
				return err
			}
		}
		switch plan.Agent {
		case agentkit.AgentCodex:
			if path := codexOutputPath(plan.Argv); path != "" {
				if err := os.WriteFile(path, []byte("Completed.\n"), 0o600); err != nil {
					return err
				}
			}
		case agentkit.AgentClaude:
			if _, err := stdout.Write([]byte("Completed.\n")); err != nil {
				return err
			}
		}
		return nil
	}
	return func() { launchJobAgent = original }
}

func mcpArgValue(plan agentkit.LaunchPlan, name string) string {
	server := plan.MCPConfig.MCPServers["prodclaw"]
	for idx := 0; idx+1 < len(server.Args); idx++ {
		if server.Args[idx] == name {
			return server.Args[idx+1]
		}
	}
	return ""
}

func writeAuditEvent(path string, event audit.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, err = file.Write(data)
	return err
}

func successfulAuditEvent(tool, actionType, resource string) audit.Event {
	return audit.Event{
		SchemaVersion:     audit.SchemaVersionV1,
		Timestamp:         "2026-05-18T00:00:00Z",
		ActionID:          tool + "-1",
		TraceID:           "trace",
		Tool:              tool,
		ActionType:        actionType,
		Resource:          resource,
		ParamsHash:        strings.Repeat("a", 64),
		Principal:         "system",
		Agent:             "codex",
		Environment:       "local",
		ActionFingerprint: strings.Repeat("b", 64),
		Decision:          "ALLOW",
		ReasonCode:        "allow_by_rule",
		MatchedRuleIDs:    []string{"allow"},
		PolicyBundleHash:  "hash",
		ResultCode:        executor.ResultSuccess,
		RedactionSummary:  executor.RedactionSummary{},
	}
}

func readLatestJobResult(t *testing.T, workspace string) jobkit.Result {
	t.Helper()
	var result jobkit.Result
	readJSONFile(t, filepath.Join(workspace, ".prodclaw", "job", "job-result.json"), &result)
	return result
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode json %s: %v\n%s", path, err, data)
	}
}

func initGitWorkspace(t *testing.T) string {
	t.Helper()
	workspace := t.TempDir()
	runGit(t, workspace, "init")
	runGit(t, workspace, "config", "user.email", "ci@example.com")
	runGit(t, workspace, "config", "user.name", "CI")
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("baseline\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGit(t, workspace, "add", "README.md")
	runGit(t, workspace, "commit", "-m", "init")
	return workspace
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func escapeJSONPath(path string) string {
	data, _ := json.Marshal(path)
	return strings.Trim(string(data), `"`)
}
