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
			"PRODCLAW_CONTAINER":      "true",
			"PRODCLAW_EGRESS_BLOCKED": "true",
			"GITHUB_TOKEN":            "raw-token",
			"PATH":                    "/usr/local/bin",
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
			"PRODCLAW_CONTAINER": "true",
		}),
	})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if report.StrongEnforcement || report.StrongEnforcementClaim != "" {
		t.Fatalf("unexpected strong enforcement claim: %+v", report)
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
