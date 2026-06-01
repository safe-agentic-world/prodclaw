package doctor

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/identity"
)

const (
	StatusPass = "pass"
	StatusFail = "fail"

	AssuranceStrong  = "strong"
	AssurancePartial = "partial"
	AssuranceNone    = "none"
)

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Coverage struct {
	Surface  string `json:"surface"`
	Level    string `json:"level"`
	Evidence string `json:"evidence"`
}

type Report struct {
	Mode                    string     `json:"mode"`
	Workspace               string     `json:"workspace"`
	ArtifactDir             string     `json:"artifact_dir"`
	AssuranceLevel          string     `json:"assurance_level"`
	MediationCoverage       []Coverage `json:"mediation_coverage"`
	StrongEnforcement       bool       `json:"strong_enforcement"`
	StrongEnforcementClaim  string     `json:"strong_enforcement_claim,omitempty"`
	AgentEnvironmentKeys    []string   `json:"agent_environment_keys"`
	ExecutorOnlyCredentials []string   `json:"executor_only_credentials,omitempty"`
	Checks                  []Check    `json:"checks"`
}

type Options struct {
	Mode        string
	Workspace   string
	ArtifactDir string
	LookupEnv   identity.LookupEnv
}

var currentUID = func() (string, error) {
	if runtime.GOOS == "windows" {
		return "non-windows-root", nil
	}
	current, err := user.Current()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(current.Uid), nil
}

func Run(opts Options) (Report, error) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = "container"
	}
	if mode == "docker" {
		mode = "container"
	}
	if mode != "container" && mode != "ci" {
		return Report{}, fmt.Errorf("unsupported doctor mode %q", strings.TrimSpace(opts.Mode))
	}
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	workspace := defaultPath(opts.Workspace, envValue(lookup, "PRODCLAW_WORKSPACE"), "/workspace")
	artifactDir := defaultPath(opts.ArtifactDir, envValue(lookup, "PRODCLAW_ARTIFACT_DIR"), "/artifacts")
	exposure := identity.CredentialExposure(lookup, nil)
	report := Report{
		Mode:                    mode,
		Workspace:               workspace,
		ArtifactDir:             artifactDir,
		AgentEnvironmentKeys:    exposure.AgentEnvKeys,
		ExecutorOnlyCredentials: exposure.ExecutorOnlyKeys,
	}
	if mode == "ci" {
		report.Checks = append(report.Checks, checkCIIdentity(lookup, workspace))
	}
	report.Checks = append(report.Checks,
		checkContainerRuntime(lookup),
		checkNonRootUser(),
		checkWorkspace(workspace),
		checkArtifactDir(artifactDir),
		checkAgentEnvAllowlist(lookup, exposure.AgentEnvKeys),
		checkEgressControlDeclared(lookup),
		checkWorkspaceMutationControl(lookup),
		checkRawMCPOverlap(lookup),
	)
	report.StrongEnforcement = allChecksPass(report.Checks)
	report.AssuranceLevel = assuranceLevel(report.Checks)
	report.MediationCoverage = coverageFromChecks(report.Checks)
	if report.StrongEnforcement {
		if mode == "ci" {
			report.StrongEnforcementClaim = "controlled CI/container runtime checks passed"
		} else {
			report.StrongEnforcementClaim = "controlled container runtime checks passed"
		}
	}
	return report, nil
}

func AssuranceFromEnv(lookup identity.LookupEnv) (string, []Coverage) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	checks := []Check{
		checkContainerRuntime(lookup),
		checkAgentEnvAllowlist(lookup, identity.AgentEnvironmentKeys(lookup, nil)),
		checkEgressControlDeclared(lookup),
		checkWorkspaceMutationControl(lookup),
		checkRawMCPOverlap(lookup),
	}
	if _, err := identity.DetectRuntimeIdentity(lookup, identity.RuntimeOptions{ControlledCI: true}); err == nil {
		checks = append([]Check{pass("ci_identity", "supported CI identity evidence detected")}, checks...)
	}
	level := assuranceLevel(checks)
	if level == AssuranceStrong {
		level = AssurancePartial
	}
	return level, coverageFromChecks(checks)
}

func checkCIIdentity(lookup identity.LookupEnv, workspace string) Check {
	id, err := identity.DetectRuntimeIdentity(lookup, identity.RuntimeOptions{
		WorkspaceRoot: workspace,
		ControlledCI:  true,
	})
	if err != nil {
		return fail("ci_identity", err.Error())
	}
	return pass("ci_identity", "supported "+id.CI.Provider+" CI identity is complete")
}

func checkContainerRuntime(lookup identity.LookupEnv) Check {
	if truthyEnv(lookup, "PRODCLAW_CONTAINER") || fileExists("/.dockerenv") || fileExists("/run/.containerenv") || cgroupLooksContainerized() {
		return pass("container_runtime", "container runtime evidence detected")
	}
	return fail("container_runtime", "no container runtime evidence detected; set PRODCLAW_CONTAINER=true only inside the controlled image")
}

func checkNonRootUser() Check {
	uid, err := currentUID()
	if err != nil {
		return fail("non_root_user", "could not determine runtime user: "+err.Error())
	}
	if uid == "0" {
		return fail("non_root_user", "runtime user is root")
	}
	return pass("non_root_user", "runtime user is non-root")
}

func checkWorkspace(path string) Check {
	info, err := os.Stat(path)
	if err != nil {
		return fail("workspace_mount", "workspace is not mounted or readable: "+err.Error())
	}
	if !info.IsDir() {
		return fail("workspace_mount", "workspace path is not a directory")
	}
	if filepath.Clean(path) == string(filepath.Separator) {
		return fail("workspace_mount", "workspace must not be the filesystem root")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fail("workspace_mount", "workspace cannot be listed: "+err.Error())
	}
	if len(entries) == 0 {
		return fail("workspace_mount", "workspace directory is empty; mount the checked-out repository at this path")
	}
	return pass("workspace_mount", "workspace directory is mounted and non-empty")
}

func checkArtifactDir(path string) Check {
	if filepath.Clean(path) == string(filepath.Separator) {
		return fail("artifact_mount", "artifact directory must not be the filesystem root")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fail("artifact_mount", "artifact directory cannot be created: "+err.Error())
	}
	probe, err := os.CreateTemp(path, ".prodclaw-doctor-*")
	if err != nil {
		return fail("artifact_mount", "artifact directory is not writable: "+err.Error())
	}
	name := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	if err := errors.Join(closeErr, removeErr); err != nil {
		return fail("artifact_mount", "artifact directory probe cleanup failed: "+err.Error())
	}
	return pass("artifact_mount", "artifact directory is writable")
}

func checkAgentEnvAllowlist(lookup identity.LookupEnv, keys []string) Check {
	for _, key := range keys {
		if identity.SensitiveEnvKey(key) {
			return fail("agent_env_allowlist", "sensitive key would be exposed to agent process: "+key)
		}
	}
	exposure := identity.CredentialExposure(lookup, nil)
	if len(exposure.ExecutorOnlyKeys) > 0 && len(exposure.AgentEnvKeys) == 0 {
		return pass("agent_env_allowlist", "credential environment variables are executor-only and absent from agent environment")
	}
	return pass("agent_env_allowlist", "agent process environment uses the ProdClaw allowlist")
}

func checkEgressControlDeclared(lookup identity.LookupEnv) Check {
	if truthyEnv(lookup, "PRODCLAW_EGRESS_BLOCKED") {
		return pass("egress_control_declared", "network egress blocking is declared by the CI/container runtime")
	}
	return fail("egress_control_declared", "network egress blocking is not declared; do not claim strong enforcement")
}

func checkWorkspaceMutationControl(lookup identity.LookupEnv) Check {
	if truthyEnv(lookup, "PRODCLAW_WORKSPACE_MUTATION_PROTECTED") {
		return pass("workspace_mutation_control", "workspace writes are declared blocked except through ProdClaw")
	}
	if truthyEnv(lookup, "PRODCLAW_WORKSPACE_MUTATION_DETECT") {
		return pass("workspace_mutation_control", "unmediated workspace mutation detection is declared active")
	}
	return fail("workspace_mutation_control", "workspace mutation control is not declared; enable runtime write blocking or ProdClaw mutation detection")
}

func checkRawMCPOverlap(lookup identity.LookupEnv) Check {
	value := envValue(lookup, "PRODCLAW_RAW_MCP_SERVERS")
	if value == "" {
		return pass("raw_mcp_overlap", "no raw upstream MCP servers declared beside ProdClaw")
	}
	return fail("raw_mcp_overlap", "raw upstream MCP servers declared beside ProdClaw: "+value)
}

func allChecksPass(checks []Check) bool {
	for _, check := range checks {
		if check.Status != StatusPass {
			return false
		}
	}
	return true
}

func assuranceLevel(checks []Check) string {
	if len(checks) == 0 {
		return AssuranceNone
	}
	passCount := 0
	for _, check := range checks {
		if check.Status == StatusPass {
			passCount++
		}
	}
	switch {
	case passCount == len(checks):
		return AssuranceStrong
	case passCount > 0:
		return AssurancePartial
	default:
		return AssuranceNone
	}
}

func coverageFromChecks(checks []Check) []Coverage {
	checkStatus := map[string]Check{}
	for _, check := range checks {
		checkStatus[check.ID] = check
	}
	coverage := []Coverage{
		coverageEntry("filesystem", checkStatus, []string{"workspace_mount", "workspace_mutation_control"}, "workspace is mounted and unmediated mutation is blocked or detected"),
		coverageEntry("process", checkStatus, []string{"container_runtime", "non_root_user"}, "agent process runs inside controlled non-root runtime; governed commands route through ProdClaw MCP policy"),
		coverageEntry("network", checkStatus, []string{"egress_control_declared"}, "direct egress is blocked or forced through controlled paths by the CI/container runtime"),
		coverageEntry("credentials", checkStatus, []string{"agent_env_allowlist"}, "sensitive credential variables are executor-only and absent from the agent environment"),
		coverageEntry("repo_publishing", checkStatus, []string{"workspace_mutation_control"}, "repository publication is governed by process policy and unmediated mutation controls"),
		coverageEntry("upstream_tools", checkStatus, []string{"raw_mcp_overlap"}, "raw upstream MCP servers are not present beside ProdClaw for governed capabilities"),
		coverageEntry("artifacts", checkStatus, []string{"artifact_mount"}, "artifact directory is writable for audit and job evidence"),
	}
	return coverage
}

func coverageEntry(surface string, checks map[string]Check, required []string, evidence string) Coverage {
	present := 0
	passed := 0
	for _, id := range required {
		check, ok := checks[id]
		if !ok {
			continue
		}
		present++
		if check.Status == StatusPass {
			passed++
		}
	}
	level := AssuranceNone
	if present > 0 && passed == present && present == len(required) {
		level = AssuranceStrong
	} else if passed > 0 {
		level = AssurancePartial
	}
	return Coverage{Surface: surface, Level: level, Evidence: evidence}
}

func pass(id, message string) Check {
	return Check{ID: id, Status: StatusPass, Message: message}
}

func fail(id, message string) Check {
	return Check{ID: id, Status: StatusFail, Message: message}
}

func truthyEnv(lookup identity.LookupEnv, key string) bool {
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

func envValue(lookup identity.LookupEnv, key string) string {
	value, _ := lookup(key)
	return strings.TrimSpace(value)
}

func defaultPath(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			if abs, err := filepath.Abs(value); err == nil {
				return abs
			}
			return value
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cgroupLooksContainerized() bool {
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	text := strings.ToLower(string(data))
	return strings.Contains(text, "docker") ||
		strings.Contains(text, "kubepods") ||
		strings.Contains(text, "containerd") ||
		strings.Contains(text, "podman")
}
