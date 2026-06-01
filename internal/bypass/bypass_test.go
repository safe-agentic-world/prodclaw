package bypass

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/doctor"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/job"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/profiles"
)

func TestBypassPathTraversalCorpus(t *testing.T) {
	for _, resource := range []string{
		"file://workspace/../secret.txt",
		"file://workspace/%2e%2e/secret.txt",
		"file://workspace/a%2fb",
	} {
		if got, err := normalize.NormalizeResource(resource); err == nil {
			t.Fatalf("expected traversal bypass rejection for %s, got %s", resource, got)
		}
	}
}

func TestBypassDirectCredentialReadIsExcludedFromAgentEnvironment(t *testing.T) {
	env := mapLookup(map[string]string{
		"PATH":           "/usr/bin",
		"GITHUB_TOKEN":   "raw-github-token",
		"OPENAI_API_KEY": "raw-openai-token",
		"SSH_AUTH_SOCK":  "/tmp/agent.sock",
	})
	agentEnv := strings.Join(identity.AgentEnvironment(env, nil), "\n")
	for _, denied := range []string{"GITHUB_TOKEN=", "OPENAI_API_KEY=", "SSH_AUTH_SOCK=", "raw-github-token", "raw-openai-token"} {
		if strings.Contains(agentEnv, denied) {
			t.Fatalf("sensitive credential reached agent environment: %s", agentEnv)
		}
	}
	exposure := identity.CredentialExposure(env, nil)
	if !exposure.CredentialScopes["github_token"] || !exposure.CredentialScopes["openai_api"] || !exposure.CredentialScopes["ssh_agent"] {
		t.Fatalf("expected executor-only credential scopes, got %+v", exposure)
	}
}

func TestBypassSecretFixturePathDeniedByDefaultProfile(t *testing.T) {
	bundle, err := profiles.Load("ci-strict")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	decision := evaluateDecision(t, bundle, "fs.read", "file://workspace/.env", map[string]any{"resource": ".env"})
	if decision.Decision != policy.DecisionDeny {
		t.Fatalf("expected secret fixture path denial, got %+v", decision)
	}
}

func TestBypassDirectWorkspaceMutationDetected(t *testing.T) {
	now := time.Now()
	result := job.Evaluate(job.EvaluationInput{
		ChangedFiles: job.ChangedFilesSummary{
			Changed: []job.ChangedFile{{Status: "M", Path: "README.md"}},
		},
		StartTime: now,
		EndTime:   now,
	})
	if result.ExitCode != job.ExitAgentFailure || len(result.MissingMutationEvidence) != 1 {
		t.Fatalf("expected direct workspace mutation detection, got %+v", result)
	}
}

func TestBypassRedirectEscapeDenied(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done", http.StatusFound)
	}))
	defer redirect.Close()

	runner := executor.NewHTTPRunner(nil)
	_, err := runner.DoWithPolicy(
		context.Background(),
		redirect.URL,
		executor.HTTPParams{Method: http.MethodGet},
		executor.RedirectPolicy{Enabled: true, AllowHosts: []string{"allowed.example"}},
		0,
		0,
	)
	if !errors.Is(err, executor.ErrRedirectDisallowedHost) {
		t.Fatalf("expected redirect escape denial, got %v", err)
	}
}

func TestBypassDirectShellNetworkCommandDeniedByDefaultProfile(t *testing.T) {
	bundle, err := profiles.Load("ci-strict")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	decision := evaluateDecision(t, bundle, "process.exec", "file://workspace/", map[string]any{
		"argv":               []string{"sh", "-lc", "curl https://denied.example.invalid"},
		"cwd":                "",
		"env_allowlist_keys": []string{},
		"stdin_mode":         "none",
		"shell_mode":         true,
		"output_max_bytes":   0,
		"output_max_lines":   0,
	})
	if decision.Decision != policy.DecisionDeny {
		t.Fatalf("expected direct shell/network command denial, got %+v", decision)
	}
}

func TestBypassProtectedBranchPushDeniedByDefaultProfile(t *testing.T) {
	bundle, err := profiles.Load("ci-standard")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	decision := evaluateDecision(t, bundle, "process.exec", "file://workspace/", map[string]any{
		"argv":               []string{"git", "push", "origin", "main"},
		"cwd":                "",
		"env_allowlist_keys": []string{},
		"stdin_mode":         "none",
		"shell_mode":         false,
		"output_max_bytes":   0,
		"output_max_lines":   0,
	})
	if decision.Decision != policy.DecisionDeny {
		t.Fatalf("expected protected branch push denial, got %+v", decision)
	}
}

func TestBypassRawMCPOverlapFailsRuntimeGuarantee(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("repo\n"), 0o600); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
	report, err := doctor.Run(doctor.Options{
		Mode:        "container",
		Workspace:   workspace,
		ArtifactDir: filepath.Join(t.TempDir(), "artifacts"),
		LookupEnv: mapLookup(map[string]string{
			"PRODCLAW_CONTAINER":                 "true",
			"PRODCLAW_EGRESS_BLOCKED":            "true",
			"PRODCLAW_WORKSPACE_MUTATION_DETECT": "true",
			"PRODCLAW_RAW_MCP_SERVERS":           "filesystem",
		}),
	})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if report.StrongEnforcement {
		t.Fatalf("raw MCP overlap should prevent strong enforcement: %+v", report)
	}
	for _, check := range report.Checks {
		if check.ID == "raw_mcp_overlap" && check.Status == doctor.StatusFail {
			return
		}
	}
	t.Fatalf("expected raw MCP overlap failure, got %+v", report.Checks)
}

func TestBypassDeniedGovernedAttemptAuditable(t *testing.T) {
	event := audit.Event{
		SchemaVersion:     audit.SchemaVersionV1,
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		ActionID:          "bypass-denied",
		TraceID:           "trace-bypass",
		ActionType:        "process.exec",
		Resource:          "file://workspace/",
		ParamsHash:        strings.Repeat("a", 64),
		Principal:         "system",
		Agent:             "prodclaw",
		Environment:       "ci",
		AssuranceLevel:    doctor.AssurancePartial,
		MediationCoverage: []doctor.Coverage{{Surface: "process", Level: doctor.AssurancePartial, Evidence: "governed bypass attempt was denied before execution"}},
		ActionFingerprint: strings.Repeat("b", 64),
		Decision:          policy.DecisionDeny,
		ReasonCode:        "deny_by_rule",
		MatchedRuleIDs:    []string{"ci-standard-deny-protected-branch-push"},
		PolicyBundleHash:  "ci-standard",
		ResultCode:        executor.ResultDeniedPolicy,
		Retryable:         false,
		RedactionSummary:  executor.RedactionSummary{},
	}
	if err := audit.ValidateEventSchema(event); err != nil {
		t.Fatalf("denied governed bypass event should validate: %v", err)
	}
}

func evaluateDecision(t *testing.T, bundle policy.Bundle, actionType, resource string, params map[string]any) policy.Decision {
	t.Helper()
	paramBytes, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "bypass",
		ActionType:    actionType,
		Resource:      resource,
		Params:        paramBytes,
		TraceID:       "bypass-trace",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "prodclaw", Environment: "ci"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	normalized, err := normalize.Action(act)
	if err != nil {
		t.Fatalf("normalize action: %v", err)
	}
	return policy.NewEngine(bundle).Evaluate(normalized)
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
