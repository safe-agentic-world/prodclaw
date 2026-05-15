package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	runtimeconfig "github.com/safe-agentic-world/prodclaw/internal/config"
	"github.com/safe-agentic-world/prodclaw/internal/logging"
)

type jobRunOutput struct {
	Mode             string `json:"mode"`
	Agent            string `json:"agent"`
	Task             string `json:"task"`
	Workspace        string `json:"workspace"`
	Profile          string `json:"profile,omitempty"`
	PolicyBundle     string `json:"policy_bundle,omitempty"`
	PolicyBundleHash string `json:"policy_bundle_hash"`
	PolicySource     string `json:"policy_source"`
	LaunchPlanned    bool   `json:"launch_planned"`
}

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
	fmt.Fprintln(w, "  prodclaw job run --agent codex|claude --task <path> [--config <path>] [--profile <name> | --policy-bundle <path>] --dry-run")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "notes:")
	fmt.Fprintln(w, "  - defaults to the embedded ci-strict profile when no policy is provided")
	fmt.Fprintln(w, "  - current milestone only emits the deterministic launch plan; real launch arrives in the job-runner milestone")
}

func runJobRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("job run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	var agent string
	var taskPath string
	var workspace string
	var bundlePath string
	var profileName string
	var dryRun bool
	var noLaunch bool
	fs.StringVar(&configPath, "config", "", "json config path")
	fs.StringVar(&agent, "agent", "", "agent adapter: codex|claude")
	fs.StringVar(&taskPath, "task", "", "task file path")
	fs.StringVar(&workspace, "workspace", ".", "workspace root")
	fs.StringVar(&bundlePath, "bundle", "", "policy bundle path")
	fs.StringVar(&bundlePath, "policy-bundle", "", "policy bundle path")
	fs.StringVar(&profileName, "profile", "", "built-in profile name")
	fs.BoolVar(&dryRun, "dry-run", false, "print launch plan without starting the agent")
	fs.BoolVar(&noLaunch, "no-launch", false, "prepare launch plan without starting the agent")
	fs.Usage = func() { printJobHelp(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "job run: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	cfg, err := runtimeconfig.Load(configPath, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "job run: load config: %v\n", err)
		return 30
	}
	overlayJobFlags(fs, &cfg, agent, taskPath, workspace, bundlePath, profileName)
	agent = cfg.Agent
	taskPath = cfg.TaskPath
	workspace = defaultString(cfg.Workspace, ".")
	bundlePath = cfg.PolicyBundle
	profileName = cfg.Profile
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case "codex", "claude":
	default:
		fmt.Fprintln(stderr, "job run: --agent must be codex or claude")
		return 30
	}
	if strings.TrimSpace(taskPath) == "" {
		fmt.Fprintln(stderr, "job run: --task is required")
		return 30
	}
	taskInfo, err := os.Stat(taskPath)
	if err != nil {
		fmt.Fprintf(stderr, "job run: stat task: %v\n", err)
		return 30
	}
	if taskInfo.IsDir() {
		fmt.Fprintln(stderr, "job run: --task must be a file")
		return 30
	}
	if !dryRun && !noLaunch {
		fmt.Fprintln(stderr, "job run: real agent launch is not implemented yet; use --dry-run or --no-launch")
		return 20
	}
	if bundlePath != "" && profileName != "" {
		fmt.Fprintln(stderr, "job run: --policy-bundle and --profile are mutually exclusive")
		return 30
	}
	if bundlePath == "" && profileName == "" {
		profileName = "ci-strict"
	}
	bundle, err := loadPolicyBundle(policyEvalOptions{BundlePath: bundlePath, ProfileName: profileName})
	if err != nil {
		fmt.Fprintf(stderr, "job run: load bundle: %v\n", err)
		return 30
	}
	workspaceAbs, err := filepath.Abs(workspace)
	if err != nil {
		fmt.Fprintf(stderr, "job run: resolve workspace: %v\n", err)
		return 30
	}
	taskAbs, err := filepath.Abs(taskPath)
	if err != nil {
		fmt.Fprintf(stderr, "job run: resolve task: %v\n", err)
		return 30
	}
	output := jobRunOutput{
		Mode:             selectJobRunMode(dryRun),
		Agent:            strings.ToLower(strings.TrimSpace(agent)),
		Task:             taskAbs,
		Workspace:        workspaceAbs,
		Profile:          profileName,
		PolicyBundle:     bundlePath,
		PolicyBundleHash: bundle.Hash,
		PolicySource:     selectPolicySource(profileName),
		LaunchPlanned:    false,
	}
	_ = logging.New(stderr).Info("job.plan", map[string]any{
		"agent":         output.Agent,
		"profile":       output.Profile,
		"policy_bundle": output.PolicyBundle,
		"workspace":     output.Workspace,
		"task":          output.Task,
	})
	if err := writeJSON(stdout, output); err != nil {
		fmt.Fprintf(stderr, "job run: write output: %v\n", err)
		return 50
	}
	return 0
}

func overlayJobFlags(fs *flag.FlagSet, cfg *runtimeconfig.Values, agent, taskPath, workspace, bundlePath, profileName string) {
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
}

func selectJobRunMode(dryRun bool) string {
	if dryRun {
		return "dry_run"
	}
	return "no_launch"
}

func selectPolicySource(profileName string) string {
	if profileName != "" {
		return "embedded_profile"
	}
	return "bundle"
}
