package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunContainerDoctorPassesOnlyWhenHardeningChecksPass(t *testing.T) {
	originalUID := currentUID
	currentUID = func() (string, error) { return "10001", nil }
	t.Cleanup(func() { currentUID = originalUID })

	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("repo\n"), 0o600); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
	report, err := Run(Options{
		Mode:        "container",
		Workspace:   workspace,
		ArtifactDir: filepath.Join(dir, "artifacts"),
		LookupEnv: mapLookup(map[string]string{
			"PRODCLAW_CONTAINER":                 "true",
			"PRODCLAW_EGRESS_BLOCKED":            "true",
			"PRODCLAW_WORKSPACE_MUTATION_DETECT": "true",
			"GITHUB_TOKEN":                       "raw-token",
			"PATH":                               "/usr/local/bin",
		}),
	})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !report.StrongEnforcement || report.StrongEnforcementClaim == "" {
		t.Fatalf("expected strong enforcement pass, got %+v", report)
	}
	if contains(report.AgentEnvironmentKeys, "GITHUB_TOKEN") {
		t.Fatalf("credential leaked into agent environment keys: %+v", report)
	}
	if !contains(report.ExecutorOnlyCredentials, "GITHUB_TOKEN") {
		t.Fatalf("expected executor-only credential summary: %+v", report)
	}
	if report.AssuranceLevel != AssuranceStrong {
		t.Fatalf("expected strong assurance level, got %+v", report)
	}
	if !coverageContains(report.MediationCoverage, "network", AssuranceStrong) {
		t.Fatalf("expected strong network coverage: %+v", report.MediationCoverage)
	}
}

func TestRunContainerDoctorDoesNotClaimStrongWithoutEgressDeclaration(t *testing.T) {
	originalUID := currentUID
	currentUID = func() (string, error) { return "10001", nil }
	t.Cleanup(func() { currentUID = originalUID })

	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("repo\n"), 0o600); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
	report, err := Run(Options{
		Mode:        "container",
		Workspace:   workspace,
		ArtifactDir: filepath.Join(dir, "artifacts"),
		LookupEnv: mapLookup(map[string]string{
			"PRODCLAW_CONTAINER":                 "true",
			"PRODCLAW_WORKSPACE_MUTATION_DETECT": "true",
		}),
	})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if report.StrongEnforcement || report.StrongEnforcementClaim != "" {
		t.Fatalf("unexpected strong enforcement claim: %+v", report)
	}
	if report.AssuranceLevel != AssurancePartial {
		t.Fatalf("expected partial assurance without egress declaration, got %+v", report)
	}
}

func TestRunCIDoctorRequiresCIIdentityAndRuntimeControls(t *testing.T) {
	originalUID := currentUID
	currentUID = func() (string, error) { return "10001", nil }
	t.Cleanup(func() { currentUID = originalUID })

	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("repo\n"), 0o600); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
	report, err := Run(Options{
		Mode:        "ci",
		Workspace:   workspace,
		ArtifactDir: filepath.Join(dir, "artifacts"),
		LookupEnv: mapLookup(map[string]string{
			"PRODCLAW_CONTAINER":                 "true",
			"PRODCLAW_EGRESS_BLOCKED":            "true",
			"PRODCLAW_WORKSPACE_MUTATION_DETECT": "true",
			"GITHUB_ACTIONS":                     "true",
			"GITHUB_REPOSITORY":                  "safe-agentic-world/prodclaw",
			"GITHUB_REF":                         "refs/heads/main",
			"GITHUB_SHA":                         "abc123",
			"GITHUB_RUN_ID":                      "42",
			"GITHUB_JOB":                         "test",
			"GITHUB_ACTOR":                       "octocat",
			"GITHUB_EVENT_NAME":                  "push",
			"GITHUB_WORKSPACE":                   workspace,
		}),
	})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if report.Mode != "ci" || !report.StrongEnforcement {
		t.Fatalf("expected strong CI report, got %+v", report)
	}
	if !containsCheck(report.Checks, "ci_identity", StatusPass) {
		t.Fatalf("expected CI identity pass, got %+v", report.Checks)
	}
}

func TestRunCIDoctorDetectsRawMCPOverlap(t *testing.T) {
	originalUID := currentUID
	currentUID = func() (string, error) { return "10001", nil }
	t.Cleanup(func() { currentUID = originalUID })

	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("repo\n"), 0o600); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
	report, err := Run(Options{
		Mode:        "ci",
		Workspace:   workspace,
		ArtifactDir: filepath.Join(dir, "artifacts"),
		LookupEnv: mapLookup(map[string]string{
			"PRODCLAW_CONTAINER":                 "true",
			"PRODCLAW_EGRESS_BLOCKED":            "true",
			"PRODCLAW_WORKSPACE_MUTATION_DETECT": "true",
			"PRODCLAW_RAW_MCP_SERVERS":           "filesystem,github",
			"GITHUB_ACTIONS":                     "true",
			"GITHUB_REPOSITORY":                  "safe-agentic-world/prodclaw",
			"GITHUB_REF":                         "refs/heads/main",
			"GITHUB_SHA":                         "abc123",
			"GITHUB_RUN_ID":                      "42",
			"GITHUB_JOB":                         "test",
			"GITHUB_ACTOR":                       "octocat",
			"GITHUB_EVENT_NAME":                  "push",
			"GITHUB_WORKSPACE":                   workspace,
		}),
	})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if report.StrongEnforcement {
		t.Fatalf("expected raw MCP overlap to block strong enforcement: %+v", report)
	}
	if !containsCheck(report.Checks, "raw_mcp_overlap", StatusFail) {
		t.Fatalf("expected raw MCP overlap failure, got %+v", report.Checks)
	}
}

func TestRunRejectsUnsupportedMode(t *testing.T) {
	if _, err := Run(Options{Mode: "local"}); err == nil {
		t.Fatal("expected unsupported mode error")
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsCheck(checks []Check, id, status string) bool {
	for _, check := range checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}

func coverageContains(coverage []Coverage, surface, level string) bool {
	for _, entry := range coverage {
		if entry.Surface == surface && entry.Level == level {
			return true
		}
	}
	return false
}
