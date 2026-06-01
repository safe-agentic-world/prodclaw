package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agentkit "github.com/safe-agentic-world/prodclaw/internal/agent"
	"github.com/safe-agentic-world/prodclaw/internal/audit"
	runtimeconfig "github.com/safe-agentic-world/prodclaw/internal/config"
	"github.com/safe-agentic-world/prodclaw/internal/doctor"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	jobkit "github.com/safe-agentic-world/prodclaw/internal/job"
	"github.com/safe-agentic-world/prodclaw/internal/logging"
	"github.com/safe-agentic-world/prodclaw/internal/mcp"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

type jobRunOutput struct {
	Mode                string                             `json:"mode"`
	Agent               string                             `json:"agent"`
	Task                string                             `json:"task"`
	Workspace           string                             `json:"workspace"`
	ArtifactDir         string                             `json:"artifact_dir"`
	Profile             string                             `json:"profile,omitempty"`
	PolicyBundle        string                             `json:"policy_bundle,omitempty"`
	PolicyBundleHash    string                             `json:"policy_bundle_hash"`
	PolicySource        string                             `json:"policy_source"`
	PolicyBundleSources []string                           `json:"policy_bundle_sources,omitempty"`
	PolicyBundleInputs  []policy.BundleSource              `json:"policy_bundle_inputs,omitempty"`
	LaunchPlanned       bool                               `json:"launch_planned"`
	MCPWiringMethod     string                             `json:"mcp_wiring_method"`
	AgentVersion        string                             `json:"agent_version,omitempty"`
	AgentCapabilities   agentkit.Capabilities              `json:"agent_capabilities"`
	LaunchPlan          agentkit.LaunchPlan                `json:"launch_plan"`
	ExpectedActions     []string                           `json:"expected_actions,omitempty"`
	BudgetLimits        jobkit.BudgetLimits                `json:"budget_limits"`
	PreflightTools      []string                           `json:"preflight_tools,omitempty"`
	ControlledCI        bool                               `json:"controlled_ci"`
	AssuranceLevel      string                             `json:"assurance_level"`
	MediationCoverage   []doctor.Coverage                  `json:"mediation_coverage"`
	Principal           string                             `json:"principal"`
	Environment         string                             `json:"environment"`
	CIIdentity          identity.CIIdentity                `json:"ci_identity,omitempty"`
	CredentialExposure  identity.CredentialExposureSummary `json:"credential_exposure,omitempty"`
	Artifacts           jobArtifactPaths                   `json:"artifacts"`
}

type jobArtifactPaths struct {
	Job            string `json:"job"`
	Plan           string `json:"job_plan"`
	Policy         string `json:"policy"`
	PolicyInputs   string `json:"policy_inputs"`
	Launch         string `json:"agent_launch"`
	MCPConfig      string `json:"mcp_config"`
	Audit          string `json:"audit"`
	Decisions      string `json:"decisions"`
	ChangedFiles   string `json:"changed_files"`
	Result         string `json:"job_result"`
	Replay         string `json:"replay"`
	Manifest       string `json:"artifact_manifest"`
	Summary        string `json:"summary"`
	AgentMessage   string `json:"agent_message,omitempty"`
	AgentLog       string `json:"agent_log,omitempty"`
	AgentArtifacts string `json:"agent_artifacts"`
}

type repeatedStrings []string

func (values *repeatedStrings) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

var discoverJobAgentVersion = agentkit.DiscoverVersion
var launchJobAgent = launchPlannedAgent
var jobNow = time.Now

func runJob(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printJobHelp(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "run" {
		fmt.Fprintln(stderr, "job command required: run")
		printJobHelp(stderr)
		return 2
	}
	return runJobRun(args[1:], stdout, stderr)
}

func printJobHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  prodclaw job run --agent codex|claude --task <path> [--config <path>] [--profile <name> | --policy-bundle <path> | layered policy flags] [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "flags:")
	fmt.Fprintln(w, "  --artifact-dir <path>       artifact directory (default .prodclaw/job)")
	fmt.Fprintln(w, "  --expect-action <type>      expected governed action type; repeatable")
	fmt.Fprintln(w, "  --max-wall-clock-ms <n>     wall-clock budget")
	fmt.Fprintln(w, "  --max-tool-calls <n>        MCP tool-call budget")
	fmt.Fprintln(w, "  --max-exec-calls <n>        process.exec budget")
	fmt.Fprintln(w, "  --max-network-calls <n>     net.http_request budget")
	fmt.Fprintln(w, "  --max-returned-bytes <n>    aggregate returned-byte budget")
	fmt.Fprintln(w, "  --max-artifact-bytes <n>    aggregate artifact-byte budget")
	fmt.Fprintln(w, "  --probe-tools               record advertised ProdClaw tools before launch")
	fmt.Fprintln(w, "  --dry-run                   write deterministic preflight artifacts without launching")
	fmt.Fprintln(w, "  --no-launch                 materialize artifacts/config and stop before launch")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "notes:")
	fmt.Fprintln(w, "  - defaults to the embedded ci-strict profile when no policy is provided")
	fmt.Fprintln(w, "  - launch plans attach only ProdClaw MCP; changed files without governed write/patch evidence fail closed")
}

func runJobRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("job run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	var agent string
	var taskPath string
	var workspace string
	var artifactDir string
	var bundlePath string
	var profileName string
	var dryRun bool
	var noLaunch bool
	var controlledCI bool
	var probeTools bool
	var expectedActions repeatedStrings
	var policyInputFlags policyInputFlagValues
	var budgetLimits jobkit.BudgetLimits
	fs.StringVar(&configPath, "config", "", "json config path")
	fs.StringVar(&agent, "agent", "", "agent adapter: codex|claude")
	fs.StringVar(&taskPath, "task", "", "task file path")
	fs.StringVar(&workspace, "workspace", ".", "workspace root")
	fs.StringVar(&artifactDir, "artifact-dir", "", "artifact directory")
	fs.StringVar(&bundlePath, "bundle", "", "policy bundle path")
	fs.StringVar(&bundlePath, "policy-bundle", "", "policy bundle path")
	fs.StringVar(&profileName, "profile", "", "built-in profile name")
	fs.Var(&expectedActions, "expect-action", "expected governed action type; repeatable")
	bindPolicyInputFlags(fs, &policyInputFlags)
	fs.Int64Var(&budgetLimits.WallClockMS, "max-wall-clock-ms", 0, "maximum wall-clock milliseconds")
	fs.IntVar(&budgetLimits.ToolCalls, "max-tool-calls", 0, "maximum MCP tool calls")
	fs.IntVar(&budgetLimits.ExecCalls, "max-exec-calls", 0, "maximum process.exec calls")
	fs.IntVar(&budgetLimits.NetworkCalls, "max-network-calls", 0, "maximum net.http_request calls")
	fs.Int64Var(&budgetLimits.ReturnedBytes, "max-returned-bytes", 0, "maximum returned bytes")
	fs.Int64Var(&budgetLimits.ArtifactBytes, "max-artifact-bytes", 0, "maximum artifact bytes")
	fs.BoolVar(&probeTools, "probe-tools", false, "record advertised tools before launch")
	fs.BoolVar(&dryRun, "dry-run", false, "write artifacts without starting the agent")
	fs.BoolVar(&noLaunch, "no-launch", false, "prepare launch plan without starting the agent")
	fs.BoolVar(&controlledCI, "controlled-ci", false, "fail closed unless supported CI identity is complete")
	fs.Usage = func() { printJobHelp(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "job run: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	if invalidBudgetLimits(budgetLimits) {
		fmt.Fprintln(stderr, "job run: budget limits must be >= 0")
		return jobkit.ExitInvalidConfig
	}
	cfg, err := runtimeconfig.Load(configPath, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "job run: load config: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	overlayJobFlags(fs, &cfg, agent, taskPath, workspace, bundlePath, profileName, controlledCI, policyInputFlags)
	agent = cfg.Agent
	taskPath = cfg.TaskPath
	workspace = defaultString(cfg.Workspace, ".")
	bundlePath = cfg.PolicyBundle
	profileName = cfg.Profile
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case agentkit.AgentCodex, agentkit.AgentClaude:
	default:
		fmt.Fprintln(stderr, "job run: --agent must be codex or claude")
		return jobkit.ExitInvalidConfig
	}
	workspaceAbs, err := resolveJobWorkspace(workspace)
	if err != nil {
		fmt.Fprintf(stderr, "job run: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	taskAbs, taskText, err := jobkit.ReadTaskFile(workspaceAbs, taskPath)
	if err != nil {
		fmt.Fprintf(stderr, "job run: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	if bundlePath == "" && profileName == "" && !cfg.PolicyInputs.HasAny() {
		profileName = "ci-strict"
	}
	selection, err := loadSelectedPolicy(policyLoadRequest{BundlePath: bundlePath, ProfileName: profileName, PolicyInputs: cfg.PolicyInputs})
	if err != nil {
		fmt.Fprintf(stderr, "job run: load bundle: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	verifiedIdentity, err := identity.DetectRuntimeIdentity(os.LookupEnv, identity.RuntimeOptions{
		Agent:         agent,
		Principal:     cfg.Principal,
		Environment:   cfg.Environment,
		WorkspaceRoot: workspaceAbs,
		ControlledCI:  cfg.ControlledCI,
	})
	if err != nil {
		fmt.Fprintf(stderr, "job run: runtime identity: %v\n", err)
		return jobkit.ExitRuntimeGuaranteeFailure
	}
	artifactDirAbs, err := resolveJobArtifactDir(workspaceAbs, artifactDir)
	if err != nil {
		fmt.Fprintf(stderr, "job run: resolve artifact dir: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	if err := os.MkdirAll(artifactDirAbs, 0o700); err != nil {
		fmt.Fprintf(stderr, "job run: create artifact dir: %v\n", err)
		return jobkit.ExitInternalError
	}
	artifacts := newJobArtifactPaths(artifactDirAbs)
	if strings.TrimSpace(cfg.AuditPath) == "" {
		cfg.AuditPath = artifacts.Audit
	}
	adapter, err := agentkit.Lookup(agent)
	if err != nil {
		fmt.Fprintf(stderr, "job run: adapter: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	capabilities := adapter.Capabilities()
	if capabilities.FinalOutputCapture != "" && capabilities.FinalOutputCapture != "unsupported" {
		artifacts.AgentMessage = filepath.Join(artifactDirAbs, "agent-final-message.txt")
	}
	prompt := buildGovernedJobPrompt(workspaceAbs, taskAbs, taskText)
	mcpArgs := buildJobMCPArgs(selection, cfg, workspaceAbs, artifacts.AgentArtifacts, verifiedIdentity)
	mcpConfig, err := agentkit.BuildMCPConfig("prodclaw", mcpArgs)
	if err != nil {
		fmt.Fprintf(stderr, "job run: build mcp config: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	launchPlan, err := adapter.Build(agentkit.BuildInput{
		Workspace:        workspaceAbs,
		TaskPrompt:       prompt,
		MCPConfigPath:    filepath.Join(artifactDirAbs, adapter.Name()+".mcp.json"),
		MCPConfig:        mcpConfig,
		FinalMessagePath: artifacts.AgentMessage,
	})
	if err != nil {
		fmt.Fprintf(stderr, "job run: build launch plan: %v\n", err)
		return jobkit.ExitInvalidConfig
	}
	if !launchPlan.MCPAttachmentVerified {
		fmt.Fprintln(stderr, "job run: generated launch plan could not verify ProdClaw MCP attachment")
		return jobkit.ExitRuntimeGuaranteeFailure
	}
	if rawMCPServers := strings.TrimSpace(os.Getenv("PRODCLAW_RAW_MCP_SERVERS")); rawMCPServers != "" {
		fmt.Fprintf(stderr, "job run: raw upstream MCP servers declared beside ProdClaw: %s\n", rawMCPServers)
		return jobkit.ExitRuntimeGuaranteeFailure
	}
	var preflightTools []string
	if probeTools {
		preflightTools, err = probeJobTools(selection.Bundle, workspaceAbs, artifacts.AgentArtifacts, cfg.AuditPath, verifiedIdentity)
		if err != nil {
			fmt.Fprintf(stderr, "job run: probe tools: %v\n", err)
			return jobkit.ExitRuntimeGuaranteeFailure
		}
	}
	assuranceLevel, mediationCoverage := jobRuntimeAssurance(cfg.ControlledCI, workspaceAbs, artifactDirAbs)
	output := jobRunOutput{
		Mode:                selectJobRunMode(dryRun, noLaunch),
		Agent:               verifiedIdentity.Agent,
		Task:                taskAbs,
		Workspace:           workspaceAbs,
		ArtifactDir:         artifactDirAbs,
		Profile:             selection.ProfileName,
		PolicyBundle:        selection.BundlePath,
		PolicyBundleHash:    selection.Bundle.Hash,
		PolicySource:        selection.Source,
		PolicyBundleSources: policy.BundleSourceLabels(selection.Bundle),
		PolicyBundleInputs:  append([]policy.BundleSource{}, selection.Bundle.SourceBundles...),
		LaunchPlanned:       true,
		MCPWiringMethod:     launchPlan.MCPWiringMethod,
		AgentCapabilities:   capabilities,
		LaunchPlan:          launchPlan,
		ExpectedActions:     normalizedExpectedActions(expectedActions),
		BudgetLimits:        budgetLimits,
		PreflightTools:      preflightTools,
		ControlledCI:        cfg.ControlledCI,
		AssuranceLevel:      assuranceLevel,
		MediationCoverage:   mediationCoverage,
		Principal:           verifiedIdentity.Principal,
		Environment:         verifiedIdentity.Environment,
		CIIdentity:          verifiedIdentity.CI,
		CredentialExposure:  verifiedIdentity.CredentialExposure,
		Artifacts:           artifacts,
	}
	if !dryRun {
		output.AgentVersion = discoverJobAgentVersion(adapter)
	}
	if err := writePreparedJobArtifacts(output, selection); err != nil {
		fmt.Fprintf(stderr, "job run: prepare artifacts: %v\n", err)
		return jobkit.ExitInternalError
	}
	_ = logging.New(stderr).Info("job.plan", map[string]any{
		"agent":          output.Agent,
		"principal":      output.Principal,
		"environment":    output.Environment,
		"ci_provider":    output.CIIdentity.Provider,
		"profile":        output.Profile,
		"policy_bundle":  output.PolicyBundle,
		"workspace":      output.Workspace,
		"task":           output.Task,
		"mcp_wiring":     output.MCPWiringMethod,
		"agent_version":  output.AgentVersion,
		"artifact_dir":   output.ArtifactDir,
		"expected_count": len(output.ExpectedActions),
	})

	before := jobkit.GitStatus(workspaceAbs)
	start := jobNow().UTC()
	if dryRun || noLaunch {
		mode := jobkit.ReasonDryRun
		if noLaunch {
			mode = jobkit.ReasonNoLaunch
		}
		changed := jobkit.DiffChangedFiles(before, before)
		result := jobkit.Evaluate(jobkit.EvaluationInput{
			Mode:            mode,
			ExpectedActions: output.ExpectedActions,
			ChangedFiles:    changed,
			StartTime:       start,
			EndTime:         start,
			BudgetLimits:    budgetLimits,
		})
		result, err = finalizeJobArtifacts(output, changed, nil, result)
		if err != nil {
			fmt.Fprintf(stderr, "job run: write artifacts: %v\n", err)
			return jobkit.ExitInternalError
		}
		if err := writeJSON(stdout, output); err != nil {
			fmt.Fprintf(stderr, "job run: write output: %v\n", err)
			return jobkit.ExitInternalError
		}
		return result.ExitCode
	}

	launchStdout, launchStderr, closeLaunchOutput, err := agentLaunchWriters(output, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "job run: prepare agent output: %v\n", err)
		return jobkit.ExitInternalError
	}
	launchErr := launchJobAgent(launchPlan, launchStdout, launchStderr)
	if closeErr := closeLaunchOutput(); closeErr != nil && launchErr == nil {
		launchErr = closeErr
	}
	if err := sanitizeAgentMessageFile(artifacts.AgentMessage); err != nil && launchErr == nil {
		launchErr = err
	}
	end := jobNow().UTC()
	after := jobkit.GitStatus(workspaceAbs)
	changed := jobkit.DiffChangedFiles(before, after)
	auditEvents, err := jobkit.ReadAuditEvents(artifacts.Audit)
	if err != nil {
		fmt.Fprintf(stderr, "job run: read audit: %v\n", err)
		return jobkit.ExitInternalError
	}
	agentMessage, _ := readOptionalText(artifacts.AgentMessage)
	result := jobkit.Evaluate(jobkit.EvaluationInput{
		ExpectedActions:      output.ExpectedActions,
		AuditEvents:          auditEvents,
		ChangedFiles:         changed,
		AgentExitErr:         launchErr,
		AgentMessage:         agentMessage,
		AgentMessageExpected: artifacts.AgentMessage != "",
		StartTime:            start,
		EndTime:              end,
		BudgetLimits:         budgetLimits,
	})
	result, err = finalizeJobArtifacts(output, changed, auditEvents, result)
	if err != nil {
		fmt.Fprintf(stderr, "job run: write artifacts: %v\n", err)
		return jobkit.ExitInternalError
	}
	writeJobSummary(stderr, output, result)
	return result.ExitCode
}

func jobRuntimeAssurance(controlledCI bool, workspace, artifactDir string) (string, []doctor.Coverage) {
	mode := "container"
	if controlledCI {
		mode = "ci"
	}
	report, err := doctor.Run(doctor.Options{
		Mode:        mode,
		Workspace:   workspace,
		ArtifactDir: artifactDir,
		LookupEnv:   jobAssuranceLookup(os.LookupEnv),
	})
	if err == nil {
		return report.AssuranceLevel, report.MediationCoverage
	}
	return doctor.AssuranceFromEnv(jobAssuranceLookup(os.LookupEnv))
}

func jobAssuranceLookup(base identity.LookupEnv) identity.LookupEnv {
	if base == nil {
		base = os.LookupEnv
	}
	return func(key string) (string, bool) {
		if key == "PRODCLAW_WORKSPACE_MUTATION_DETECT" {
			return "true", true
		}
		return base(key)
	}
}

func overlayJobFlags(fs *flag.FlagSet, cfg *runtimeconfig.Values, agent, taskPath, workspace, bundlePath, profileName string, controlledCI bool, policyInputFlags policyInputFlagValues) {
	if flagWasSet(fs, "agent") {
		cfg.Agent = agent
	}
	if flagWasSet(fs, "task") {
		cfg.TaskPath = taskPath
	}
	if flagWasSet(fs, "workspace") {
		cfg.Workspace = workspace
	}
	if flagWasSet(fs, "bundle") || flagWasSet(fs, "policy-bundle") {
		cfg.PolicyBundle = bundlePath
	}
	if flagWasSet(fs, "profile") {
		cfg.Profile = profileName
	}
	overlayPolicyInputFlags(fs, &cfg.PolicyInputs, policyInputFlags)
	if flagWasSet(fs, "controlled-ci") {
		cfg.ControlledCI = controlledCI
	}
}

func selectJobRunMode(dryRun, noLaunch bool) string {
	if dryRun {
		return jobkit.ReasonDryRun
	}
	if noLaunch {
		return jobkit.ReasonNoLaunch
	}
	return "run"
}

func buildJobMCPArgs(selection loadedPolicy, cfg runtimeconfig.Values, workspace, artifactDir string, id identity.VerifiedIdentity) []string {
	args := []string{"mcp"}
	switch selection.Source {
	case "embedded_profile":
		args = append(args, "--profile", selection.ProfileName)
	case "customer_bundle":
		args = append(args, "--policy-bundle", selection.BundlePath)
	case "layered_bundles":
		for _, input := range cfg.PolicyInputs.Ordered() {
			if strings.TrimSpace(input.Path) == "" {
				continue
			}
			args = append(args, "--policy-"+input.Role, input.Path)
			if strings.TrimSpace(input.SHA256) != "" {
				args = append(args, "--policy-"+input.Role+"-sha256", input.SHA256)
			}
		}
	}
	args = append(args,
		"--workspace", workspace,
		"--artifact-dir", artifactDir,
		"--principal", id.Principal,
		"--agent", id.Agent,
		"--environment", id.Environment,
	)
	if strings.TrimSpace(cfg.AuditPath) != "" {
		args = append(args, "--audit", cfg.AuditPath)
	}
	return args
}

func writeGeneratedMCPConfig(path string, config agentkit.MCPClientConfig) error {
	data, err := agentkit.MarshalMCPConfig(config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func launchPlannedAgent(plan agentkit.LaunchPlan, stdout, stderr io.Writer) error {
	binary, err := exec.LookPath(plan.Executable)
	if err != nil {
		return err
	}
	cmd := exec.Command(binary, plan.Argv...)
	cmd.Dir = plan.Workspace
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = agentProcessEnvironment(plan.Env)
	return cmd.Run()
}

func agentProcessEnvironment(planEnv []string) []string {
	env := identity.AgentEnvironment(os.LookupEnv, nil)
	for _, entry := range planEnv {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || identity.SensitiveEnvKey(key) {
			continue
		}
		env = append(env, entry)
	}
	return env
}

func resolveJobWorkspace(raw string) (string, error) {
	abs, err := filepath.Abs(defaultString(raw, "."))
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("workspace does not exist: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace is not a directory: %s", abs)
	}
	return abs, nil
}

func resolveJobArtifactDir(workspace, raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return filepath.Join(workspace, ".prodclaw", "job"), nil
	}
	if filepath.IsAbs(raw) {
		return filepath.Abs(raw)
	}
	return filepath.Abs(filepath.Join(workspace, raw))
}

func newJobArtifactPaths(dir string) jobArtifactPaths {
	return jobArtifactPaths{
		Job:            filepath.Join(dir, "job.json"),
		Plan:           filepath.Join(dir, "job-plan.json"),
		Policy:         filepath.Join(dir, "policy.json"),
		PolicyInputs:   filepath.Join(dir, "policy-inputs.json"),
		Launch:         filepath.Join(dir, "agent-launch.json"),
		MCPConfig:      filepath.Join(dir, "mcp-config.json"),
		Audit:          filepath.Join(dir, "audit.jsonl"),
		Decisions:      filepath.Join(dir, "decisions.jsonl"),
		ChangedFiles:   filepath.Join(dir, "changed-files.json"),
		Result:         filepath.Join(dir, "job-result.json"),
		Replay:         filepath.Join(dir, "replay.json"),
		Manifest:       filepath.Join(dir, "artifact-manifest.json"),
		Summary:        filepath.Join(dir, "summary.txt"),
		AgentLog:       filepath.Join(dir, "agent-stderr.txt"),
		AgentArtifacts: filepath.Join(dir, "agent-artifacts"),
	}
}

func normalizedExpectedActions(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func invalidBudgetLimits(limits jobkit.BudgetLimits) bool {
	return limits.WallClockMS < 0 ||
		limits.ToolCalls < 0 ||
		limits.ExecCalls < 0 ||
		limits.NetworkCalls < 0 ||
		limits.ReturnedBytes < 0 ||
		limits.ArtifactBytes < 0
}

func buildGovernedJobPrompt(workspace, taskPath, task string) string {
	return "Run this ProdClaw-governed CI job in workspace " + workspace + ".\n" +
		"Use only ProdClaw MCP tools for file writes, patching, shell/git commands, HTTP requests, upstream tools, and artifacts.\n" +
		"Do not use native shell, native file-write, native patch, native HTTP, or raw upstream MCP tools for side effects.\n" +
		"If ProdClaw denies a required action, stop and explain the policy gap instead of bypassing it.\n" +
		"Task file: " + taskPath + "\n\n" + task
}

func probeJobTools(bundle policy.Bundle, workspace, artifactDir, auditPath string, id identity.VerifiedIdentity) ([]string, error) {
	server, err := mcp.NewServer(mcp.Options{
		Bundle:      bundle,
		Workspace:   workspace,
		ArtifactDir: artifactDir,
		AuditPath:   auditPath,
		Identity:    id,
	})
	if err != nil {
		return nil, err
	}
	return server.AdvertisedToolNames(), nil
}

func writePreparedJobArtifacts(output jobRunOutput, selection loadedPolicy) error {
	if err := os.MkdirAll(output.Artifacts.AgentArtifacts, 0o700); err != nil {
		return err
	}
	if err := ensureFile(output.Artifacts.AgentLog); err != nil {
		return err
	}
	if err := writeJSONFile(output.Artifacts.Job, output); err != nil {
		return err
	}
	if err := writeJSONFile(output.Artifacts.Plan, output); err != nil {
		return err
	}
	if err := writeJSONFile(output.Artifacts.Policy, newPolicyArtifact(selection)); err != nil {
		return err
	}
	if err := writeJSONFile(output.Artifacts.PolicyInputs, newPolicyInputsArtifact(selection)); err != nil {
		return err
	}
	if err := writeJSONFile(output.Artifacts.Launch, output.LaunchPlan); err != nil {
		return err
	}
	if err := writeGeneratedMCPConfig(output.Artifacts.MCPConfig, output.LaunchPlan.MCPConfig); err != nil {
		return err
	}
	if err := writeGeneratedMCPConfig(output.LaunchPlan.MCPConfigPath, output.LaunchPlan.MCPConfig); err != nil {
		return err
	}
	if err := ensureFile(output.Artifacts.Audit); err != nil {
		return err
	}
	return ensureFile(output.Artifacts.Decisions)
}

func writeFinalJobArtifacts(output jobRunOutput, changed jobkit.ChangedFilesSummary, result jobkit.Result) error {
	if err := writeJSONFile(output.Artifacts.ChangedFiles, changed); err != nil {
		return err
	}
	return writeJSONFile(output.Artifacts.Result, result)
}

func finalizeJobArtifacts(output jobRunOutput, changed jobkit.ChangedFilesSummary, auditEvents []audit.Event, result jobkit.Result) (jobkit.Result, error) {
	if err := writeFinalJobArtifacts(output, changed, result); err != nil {
		return result, err
	}
	findings, err := jobkit.SanitizeArtifactTree(output.ArtifactDir)
	if err != nil {
		return result, err
	}
	if len(findings) == 0 {
		return result, writeEvidenceArtifacts(output, changed, auditEvents, result)
	}
	result.ExitReason = jobkit.ReasonReturnPathViolation
	result.ExitCode = jobkit.ExitInternalError
	result.ReturnPathFindings = findings
	if err := writeJSONFile(output.Artifacts.Result, result); err != nil {
		return result, err
	}
	return result, writeEvidenceArtifacts(output, changed, auditEvents, result)
}

func writeEvidenceArtifacts(output jobRunOutput, changed jobkit.ChangedFilesSummary, auditEvents []audit.Event, result jobkit.Result) error {
	if auditEvents == nil {
		var err error
		auditEvents, err = jobkit.ReadAuditEvents(output.Artifacts.Audit)
		if err != nil {
			return err
		}
	}
	if err := writeDecisionStream(output.Artifacts.Decisions, auditEvents); err != nil {
		return err
	}
	if err := writeJSONFile(output.Artifacts.Replay, newReplayArtifact(output, changed, auditEvents, result)); err != nil {
		return err
	}
	if err := writeSummaryArtifact(output.Artifacts.Summary, output, result, auditEvents); err != nil {
		return err
	}
	return writeArtifactManifest(output.ArtifactDir, output.Artifacts.Manifest)
}

func writeJSONFile(path string, value any) error {
	safeValue, err := redact.DefaultRedactor().RedactJSONValue(value)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(safeValue, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ensureFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

func agentLaunchWriters(output jobRunOutput, stdout, stderr io.Writer) (io.Writer, io.Writer, func() error, error) {
	stdoutTargets := []io.Writer{stdout}
	var closers []io.Closer
	if output.Artifacts.AgentMessage != "" && output.AgentCapabilities.FinalOutputCapture == "stdout" {
		file, err := os.Create(output.Artifacts.AgentMessage)
		if err != nil {
			return nil, nil, nil, err
		}
		stdoutTargets = append(stdoutTargets, file)
		closers = append(closers, file)
	}
	stdoutWriter := newSanitizingWriter(stdoutTargets, closers, "agent.output")

	logFile, err := os.Create(output.Artifacts.AgentLog)
	if err != nil {
		_ = stdoutWriter.Close()
		return nil, nil, nil, err
	}
	stderrWriter := newSanitizingWriter([]io.Writer{stderr, logFile}, []io.Closer{logFile}, "agent.log")
	return stdoutWriter, stderrWriter, func() error {
		errs := []error{stdoutWriter.Close(), stderrWriter.Close()}
		for _, err := range errs {
			if err != nil {
				return err
			}
		}
		return nil
	}, nil
}

type sanitizingWriter struct {
	buffer   bytes.Buffer
	targets  []io.Writer
	closers  []io.Closer
	location string
	closed   bool
}

func newSanitizingWriter(targets []io.Writer, closers []io.Closer, location string) *sanitizingWriter {
	return &sanitizingWriter{targets: targets, closers: closers, location: location}
}

func (w *sanitizingWriter) Write(data []byte) (int, error) {
	if w.closed {
		return 0, os.ErrClosed
	}
	_, err := w.buffer.Write(data)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (w *sanitizingWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	text, _ := sanitizeReturnPathText(w.buffer.String(), w.location)
	var firstErr error
	if text != "" {
		for _, target := range w.targets {
			if _, err := io.WriteString(target, text); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, closer := range w.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func sanitizeAgentMessageFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	sanitized, _ := sanitizeReturnPathText(string(data), "agent.output")
	return os.WriteFile(path, []byte(sanitized), 0o600)
}

func sanitizeReturnPathText(text, location string) (string, executor.RedactionSummary) {
	return executor.SanitizeOutputForLocation(redact.DefaultRedactor(), text, nil, 0, 0, location)
}

func readOptionalText(path string) (string, bool) {
	if strings.TrimSpace(path) == "" {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func writeJobSummary(out io.Writer, output jobRunOutput, result jobkit.Result) {
	events, _ := jobkit.ReadAuditEvents(output.Artifacts.Audit)
	_, _ = fmt.Fprint(out, buildJobSummaryText(output, result, events))
}
