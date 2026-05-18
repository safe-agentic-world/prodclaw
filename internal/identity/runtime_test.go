package identity

import (
	"strings"
	"testing"
)

func TestDetectRuntimeIdentityGitHub(t *testing.T) {
	env := map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "safe-agentic-world/prodclaw",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "0123456789abcdef",
		"GITHUB_RUN_ID":     "1001",
		"GITHUB_JOB":        "test",
		"GITHUB_ACTOR":      "octocat",
		"GITHUB_EVENT_NAME": "push",
		"GITHUB_TOKEN":      "raw-token-never-returned",
	}
	workspace := t.TempDir()
	id, err := DetectRuntimeIdentity(mapLookup(env), RuntimeOptions{Agent: "codex", WorkspaceRoot: workspace, ControlledCI: true})
	if err != nil {
		t.Fatalf("detect identity: %v", err)
	}
	if id.Principal != "github:safe-agentic-world/prodclaw:octocat" || id.Agent != "codex" || id.Environment != "ci" {
		t.Fatalf("unexpected base identity: %+v", id)
	}
	if id.CI.Provider != "github" || id.CI.Branch != "main" || id.CI.WorkflowRunID != "1001" || id.CI.WorkspaceRoot != workspace {
		t.Fatalf("unexpected github identity: %+v", id.CI)
	}
	if !id.CredentialExposure.CredentialScopes["github_token"] || strings.Contains(strings.Join(id.CredentialExposure.ExecutorOnlyKeys, ","), "raw-token") {
		t.Fatalf("unexpected credential summary: %+v", id.CredentialExposure)
	}
}

func TestDetectRuntimeIdentityGitLab(t *testing.T) {
	env := map[string]string{
		"GITLAB_CI":          "true",
		"CI_PROJECT_PATH":    "firstgroup365/devops/codex-ci-agent",
		"CI_COMMIT_REF_NAME": "feature/acdk-1",
		"CI_COMMIT_SHA":      "abcdef0123456789",
		"CI_PIPELINE_ID":     "2002",
		"CI_JOB_ID":          "3003",
		"GITLAB_USER_LOGIN":  "ps-tech-geek",
		"CI_PIPELINE_SOURCE": "push",
		"GITLAB_TOKEN":       "raw-token-never-returned",
	}
	workspace := t.TempDir()
	id, err := DetectRuntimeIdentity(mapLookup(env), RuntimeOptions{Agent: "claude", WorkspaceRoot: workspace, ControlledCI: true})
	if err != nil {
		t.Fatalf("detect identity: %v", err)
	}
	if id.Principal != "gitlab:firstgroup365/devops/codex-ci-agent:ps-tech-geek" || id.Agent != "claude" || id.Environment != "ci" {
		t.Fatalf("unexpected base identity: %+v", id)
	}
	if id.CI.Provider != "gitlab" || id.CI.Branch != "feature/acdk-1" || id.CI.PipelineID != "2002" || id.CI.JobID != "3003" {
		t.Fatalf("unexpected gitlab identity: %+v", id.CI)
	}
	if !id.CredentialExposure.CredentialScopes["gitlab_token"] {
		t.Fatalf("expected gitlab token scope, got %+v", id.CredentialExposure)
	}
}

func TestDetectRuntimeIdentityControlledCIFailsClosed(t *testing.T) {
	_, err := DetectRuntimeIdentity(mapLookup(map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "safe-agentic-world/prodclaw",
	}), RuntimeOptions{Agent: "codex", ControlledCI: true})
	if err == nil || !strings.Contains(err.Error(), "missing required fields") {
		t.Fatalf("expected missing identity failure, got %v", err)
	}
	_, err = DetectRuntimeIdentity(mapLookup(map[string]string{}), RuntimeOptions{Agent: "codex", ControlledCI: true})
	if err == nil || !strings.Contains(err.Error(), "no supported CI provider") {
		t.Fatalf("expected missing provider failure, got %v", err)
	}
	_, err = DetectRuntimeIdentity(mapLookup(map[string]string{"GITHUB_ACTIONS": "true", "GITLAB_CI": "true"}), RuntimeOptions{Agent: "codex", ControlledCI: true})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous identity failure, got %v", err)
	}
}

func TestAgentEnvironmentScrubsSensitiveAllowlist(t *testing.T) {
	env := map[string]string{
		"PATH":           "/bin",
		"CUSTOM_ALLOWED": "ok",
		"GITLAB_TOKEN":   "must-not-leak",
		"OPENAI_API_KEY": "must-not-leak",
		"SSH_AUTH_SOCK":  "/tmp/agent.sock",
	}
	got := strings.Join(AgentEnvironment(mapLookup(env), []string{"CUSTOM_ALLOWED", "GITLAB_TOKEN", "OPENAI_API_KEY", "SSH_AUTH_SOCK"}), "\n")
	if !strings.Contains(got, "PATH=/bin") || !strings.Contains(got, "CUSTOM_ALLOWED=ok") {
		t.Fatalf("expected safe env keys, got %q", got)
	}
	if strings.Contains(got, "must-not-leak") || strings.Contains(got, "SSH_AUTH_SOCK") {
		t.Fatalf("sensitive env leaked: %q", got)
	}
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
