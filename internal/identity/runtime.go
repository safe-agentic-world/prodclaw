package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type LookupEnv func(string) (string, bool)

type RuntimeOptions struct {
	Agent         string
	Principal     string
	Environment   string
	WorkspaceRoot string
	ControlledCI  bool
}

func DetectRuntimeIdentity(lookup LookupEnv, opts RuntimeOptions) (VerifiedIdentity, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	workspaceRoot := strings.TrimSpace(opts.WorkspaceRoot)
	if workspaceRoot != "" {
		if abs, err := filepath.Abs(workspaceRoot); err == nil {
			workspaceRoot = abs
		}
	}
	github := truthyEnv(lookup, "GITHUB_ACTIONS")
	gitlab := truthyEnv(lookup, "GITLAB_CI")
	if github && gitlab && opts.ControlledCI {
		return VerifiedIdentity{}, errors.New("controlled CI identity is ambiguous: both GitHub Actions and GitLab CI were detected")
	}

	ci := CIIdentity{}
	var err error
	switch {
	case github:
		ci, err = githubIdentity(lookup, workspaceRoot)
	case gitlab:
		ci, err = gitlabIdentity(lookup, workspaceRoot)
	case opts.ControlledCI:
		return VerifiedIdentity{}, errors.New("controlled CI identity is required but no supported CI provider was detected")
	}
	if err != nil && opts.ControlledCI {
		return VerifiedIdentity{}, err
	}

	environment := classifyEnvironment(lookup, ci.Provider, opts.Environment)
	principal := strings.TrimSpace(opts.Principal)
	if principal == "" {
		principal = principalForCI(ci)
	}
	if principal == "" {
		principal = "system"
	}
	agent := strings.ToLower(strings.TrimSpace(opts.Agent))
	if agent == "" {
		agent = "prodclaw"
	}
	return VerifiedIdentity{
		Principal:          principal,
		Agent:              agent,
		Environment:        environment,
		CI:                 ci,
		CredentialExposure: CredentialExposure(lookup, nil),
	}, nil
}

func githubIdentity(lookup LookupEnv, workspaceRoot string) (CIIdentity, error) {
	ci := CIIdentity{
		Provider:      "github",
		Repo:          envValue(lookup, "GITHUB_REPOSITORY"),
		Project:       envValue(lookup, "GITHUB_REPOSITORY"),
		Ref:           envValue(lookup, "GITHUB_REF"),
		Branch:        branchFromGitHubRef(envValue(lookup, "GITHUB_REF")),
		CommitSHA:     envValue(lookup, "GITHUB_SHA"),
		RunID:         envValue(lookup, "GITHUB_RUN_ID"),
		WorkflowRunID: envValue(lookup, "GITHUB_RUN_ID"),
		JobID:         envValue(lookup, "GITHUB_JOB"),
		Actor:         envValue(lookup, "GITHUB_ACTOR"),
		EventType:     envValue(lookup, "GITHUB_EVENT_NAME"),
		WorkspaceRoot: firstNonEmpty(workspaceRoot, envValue(lookup, "GITHUB_WORKSPACE")),
	}
	return ci, requireCIFields("github", map[string]string{
		"repo":            ci.Repo,
		"ref":             ci.Ref,
		"commit_sha":      ci.CommitSHA,
		"workflow_run_id": ci.WorkflowRunID,
		"job_id":          ci.JobID,
		"actor":           ci.Actor,
		"event_type":      ci.EventType,
		"workspace_root":  ci.WorkspaceRoot,
	})
}

func gitlabIdentity(lookup LookupEnv, workspaceRoot string) (CIIdentity, error) {
	project := envValue(lookup, "CI_PROJECT_PATH")
	ref := firstNonEmpty(envValue(lookup, "CI_COMMIT_REF_NAME"), envValue(lookup, "CI_COMMIT_BRANCH"))
	ci := CIIdentity{
		Provider:      "gitlab",
		Repo:          project,
		Project:       project,
		Ref:           ref,
		Branch:        firstNonEmpty(envValue(lookup, "CI_COMMIT_BRANCH"), ref),
		CommitSHA:     envValue(lookup, "CI_COMMIT_SHA"),
		RunID:         envValue(lookup, "CI_PIPELINE_ID"),
		PipelineID:    envValue(lookup, "CI_PIPELINE_ID"),
		JobID:         envValue(lookup, "CI_JOB_ID"),
		Actor:         firstNonEmpty(envValue(lookup, "GITLAB_USER_LOGIN"), envValue(lookup, "GITLAB_USER_NAME")),
		EventType:     envValue(lookup, "CI_PIPELINE_SOURCE"),
		WorkspaceRoot: firstNonEmpty(workspaceRoot, envValue(lookup, "CI_PROJECT_DIR")),
	}
	return ci, requireCIFields("gitlab", map[string]string{
		"project":        ci.Project,
		"ref":            ci.Ref,
		"commit_sha":     ci.CommitSHA,
		"pipeline_id":    ci.PipelineID,
		"job_id":         ci.JobID,
		"actor":          ci.Actor,
		"event_type":     ci.EventType,
		"workspace_root": ci.WorkspaceRoot,
	})
}

func requireCIFields(provider string, fields map[string]string) error {
	missing := make([]string, 0)
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("%s CI identity missing required fields: %s", provider, strings.Join(missing, ", "))
	}
	return nil
}

func classifyEnvironment(lookup LookupEnv, provider, configured string) string {
	if provider != "" {
		return "ci"
	}
	if truthyEnv(lookup, "CI") || truthyEnv(lookup, "BUILD_BUILDID") {
		return "ci"
	}
	if truthyEnv(lookup, "PRODCLAW_CONTAINER") || envValue(lookup, "KUBERNETES_SERVICE_HOST") != "" || fileExists("/.dockerenv") {
		return "container"
	}
	if configured = strings.ToLower(strings.TrimSpace(configured)); configured == "ci" || configured == "container" || configured == "local" {
		return configured
	}
	return "local"
}

func principalForCI(ci CIIdentity) string {
	switch ci.Provider {
	case "github":
		return joinIdentityParts("github", ci.Repo, ci.Actor)
	case "gitlab":
		return joinIdentityParts("gitlab", ci.Project, ci.Actor)
	default:
		return ""
	}
}

func joinIdentityParts(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, ":")
}

func branchFromGitHubRef(ref string) string {
	ref = strings.TrimSpace(ref)
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		if strings.HasPrefix(ref, prefix) {
			return strings.TrimPrefix(ref, prefix)
		}
	}
	return ref
}

func PolicyContextJSON(id VerifiedIdentity) ([]byte, error) {
	data, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func CredentialExposure(lookup LookupEnv, extraAgentAllowlist []string) CredentialExposureSummary {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	executorOnly := make([]string, 0)
	scrubbed := make([]string, 0)
	scopes := map[string]bool{}
	for _, key := range knownCredentialKeys {
		if _, ok := lookup(key); !ok {
			continue
		}
		executorOnly = append(executorOnly, key)
		scrubbed = append(scrubbed, key)
		for _, scope := range credentialScopesForKey(key) {
			scopes[scope] = true
		}
	}
	sort.Strings(executorOnly)
	sort.Strings(scrubbed)
	if len(scopes) == 0 {
		scopes = nil
	}
	return CredentialExposureSummary{
		AgentEnvKeys:     AgentEnvironmentKeys(lookup, extraAgentAllowlist),
		ExecutorOnlyKeys: executorOnly,
		ScrubbedKeys:     scrubbed,
		CredentialScopes: scopes,
	}
}

func AgentEnvironment(lookup LookupEnv, extraAllowlist []string) []string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	keys := AgentEnvironmentKeys(lookup, extraAllowlist)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := lookup(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func AgentEnvironmentKeys(lookup LookupEnv, extraAllowlist []string) []string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	keySet := map[string]string{}
	addKey := func(key string) {
		key = strings.TrimSpace(key)
		if key == "" || SensitiveEnvKey(key) {
			return
		}
		keySet[strings.ToUpper(key)] = key
	}
	for _, key := range defaultAgentEnvAllowlist {
		addKey(key)
	}
	for _, key := range extraAllowlist {
		addKey(key)
	}
	keys := make([]string, 0, len(keySet))
	for _, key := range keySet {
		if _, ok := lookup(key); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func SensitiveEnvKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "credential") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "cookie") ||
		strings.Contains(lower, "auth") ||
		strings.HasSuffix(lower, "_key") ||
		strings.Contains(lower, "private_key") {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "SSH_AUTH_SOCK", "GOOGLE_APPLICATION_CREDENTIALS":
		return true
	default:
		return false
	}
}

func credentialScopesForKey(key string) []string {
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "GITHUB_TOKEN":
		return []string{"github_api", "github_token"}
	case "GITLAB_TOKEN", "CI_JOB_TOKEN":
		return []string{"gitlab_api", "gitlab_token"}
	case "OPENAI_API_KEY":
		return []string{"openai_api"}
	case "ANTHROPIC_API_KEY":
		return []string{"anthropic_api"}
	case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN":
		return []string{"aws"}
	case "GOOGLE_APPLICATION_CREDENTIALS":
		return []string{"gcp"}
	case "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_CLIENT_ID":
		return []string{"azure"}
	case "SSH_AUTH_SOCK":
		return []string{"ssh_agent"}
	default:
		return []string{"credential"}
	}
}

func truthyEnv(lookup LookupEnv, key string) bool {
	value, ok := lookup(key)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envValue(lookup LookupEnv, key string) string {
	value, _ := lookup(key)
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var defaultAgentEnvAllowlist = []string{
	"PATH",
	"HOME",
	"TMPDIR",
	"TEMP",
	"TMP",
	"SYSTEMROOT",
	"WINDIR",
	"COMSPEC",
	"PATHEXT",
	"LANG",
}

var knownCredentialKeys = []string{
	"GITHUB_TOKEN",
	"GITLAB_TOKEN",
	"CI_JOB_TOKEN",
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
	"AZURE_TENANT_ID",
	"SSH_AUTH_SOCK",
}
