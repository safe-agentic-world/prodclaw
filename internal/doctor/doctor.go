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
)

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Report struct {
	Mode                    string   `json:"mode"`
	Workspace               string   `json:"workspace"`
	ArtifactDir             string   `json:"artifact_dir"`
	StrongEnforcement       bool     `json:"strong_enforcement"`
	StrongEnforcementClaim  string   `json:"strong_enforcement_claim,omitempty"`
	AgentEnvironmentKeys    []string `json:"agent_environment_keys"`
	ExecutorOnlyCredentials []string `json:"executor_only_credentials,omitempty"`
	Checks                  []Check  `json:"checks"`
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
	if mode != "container" && mode != "docker" {
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
		Mode:                    "container",
		Workspace:               workspace,
		ArtifactDir:             artifactDir,
		AgentEnvironmentKeys:    exposure.AgentEnvKeys,
		ExecutorOnlyCredentials: exposure.ExecutorOnlyKeys,
	}
	report.Checks = append(report.Checks,
		checkContainerRuntime(lookup),
		checkNonRootUser(),
		checkWorkspace(workspace),
		checkArtifactDir(artifactDir),
		checkAgentEnvAllowlist(lookup, exposure.AgentEnvKeys),
		checkEgressControlDeclared(lookup),
	)
	report.StrongEnforcement = allChecksPass(report.Checks)
	if report.StrongEnforcement {
		report.StrongEnforcementClaim = "controlled container runtime checks passed"
	}
	return report, nil
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

func allChecksPass(checks []Check) bool {
	for _, check := range checks {
		if check.Status != StatusPass {
			return false
		}
	}
	return true
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
