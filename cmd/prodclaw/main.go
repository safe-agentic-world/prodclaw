package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	runtimeconfig "github.com/safe-agentic-world/prodclaw/internal/config"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/logging"
	"github.com/safe-agentic-world/prodclaw/internal/mcp"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/version"
	"github.com/safe-agentic-world/prodclaw/profiles"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printHelp()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Printf("version=%s\n", version.Version)
		return 0
	case "policy":
		return runPolicy(args[1:], os.Stdout, os.Stderr)
	case "profiles":
		return runProfiles(args[1:], os.Stdout, os.Stderr)
	case "mcp":
		return runMCP(args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "job":
		return runJob(args[1:], os.Stdout, os.Stderr)
	case "-h", "--help", "help":
		printHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		printHelp()
		return 2
	}
}

func printHelp() {
	fmt.Fprintln(os.Stderr, "prodclaw: CI-first policy boundary for coding agents")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  version    print build metadata")
	fmt.Fprintln(os.Stderr, "  policy     check or explain policy decisions")
	fmt.Fprintln(os.Stderr, "  profiles   inspect built-in profiles")
	fmt.Fprintln(os.Stderr, "  mcp        start governed MCP stdio server")
	fmt.Fprintln(os.Stderr, "  job        inspect a governed CI job launch plan")
}

func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	var bundlePath string
	var profileName string
	var workspace string
	var auditPath string
	var principal string
	var agent string
	var environment string
	fs.StringVar(&configPath, "config", "", "json config path")
	fs.StringVar(&bundlePath, "bundle", "", "policy bundle path")
	fs.StringVar(&bundlePath, "policy-bundle", "", "policy bundle path")
	fs.StringVar(&profileName, "profile", "", "built-in profile name")
	fs.StringVar(&workspace, "workspace", ".", "workspace root")
	fs.StringVar(&auditPath, "audit", "", "audit jsonl path")
	fs.StringVar(&principal, "principal", "system", "verified principal")
	fs.StringVar(&agent, "agent", "prodclaw", "verified agent")
	fs.StringVar(&environment, "environment", "ci", "verified environment")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := runtimeconfig.Load(configPath, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "mcp: load config: %v\n", err)
		return 30
	}
	overlayMCPFlags(fs, &cfg, bundlePath, profileName, workspace, auditPath, principal, agent, environment)
	bundlePath = cfg.PolicyBundle
	profileName = cfg.Profile
	workspace = defaultString(cfg.Workspace, ".")
	auditPath = cfg.AuditPath
	principal = defaultString(cfg.Principal, "system")
	agent = defaultString(cfg.Agent, "prodclaw")
	environment = defaultString(cfg.Environment, "ci")
	if bundlePath == "" && profileName == "" {
		profileName = "ci-standard"
	}
	bundle, err := loadPolicyBundle(policyEvalOptions{BundlePath: bundlePath, ProfileName: profileName})
	if err != nil {
		fmt.Fprintf(stderr, "mcp: load bundle: %v\n", err)
		return 30
	}
	server, err := mcp.NewServer(mcp.Options{
		Bundle:    bundle,
		Workspace: workspace,
		AuditPath: auditPath,
		Identity: identity.VerifiedIdentity{
			Principal:   principal,
			Agent:       agent,
			Environment: environment,
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "mcp: %v\n", err)
		return 30
	}
	_ = logging.New(stderr).Info("mcp.start", map[string]any{
		"profile":       profileName,
		"policy_bundle": bundlePath,
		"workspace":     workspace,
		"audit":         auditPath,
	})
	if err := server.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "mcp: %v\n", err)
		return 40
	}
	return 0
}

func overlayMCPFlags(fs *flag.FlagSet, cfg *runtimeconfig.Values, bundlePath, profileName, workspace, auditPath, principal, agent, environment string) {
	if flagWasSet(fs, "bundle") || flagWasSet(fs, "policy-bundle") {
		cfg.PolicyBundle = bundlePath
	}
	if flagWasSet(fs, "profile") {
		cfg.Profile = profileName
	}
	if flagWasSet(fs, "workspace") {
		cfg.Workspace = workspace
	}
	if flagWasSet(fs, "audit") {
		cfg.AuditPath = auditPath
	}
	if flagWasSet(fs, "principal") {
		cfg.Principal = principal
	}
	if flagWasSet(fs, "agent") {
		cfg.Agent = agent
	}
	if flagWasSet(fs, "environment") {
		cfg.Environment = environment
	}
}

func runProfiles(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printProfilesHelp(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	var err error
	switch args[0] {
	case "list":
		err = executeProfilesList(args[1:], stdout, stderr)
	case "show":
		err = executeProfilesShow(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "profiles command required: list|show")
		printProfilesHelp(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "profiles %s: %v\n", args[0], err)
		return 30
	}
	return 0
}

func printProfilesHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  prodclaw profiles list [--format text|json]")
	fmt.Fprintln(w, "  prodclaw profiles show <name> [--format yaml|json]")
}

func executeProfilesList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("profiles list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	records, err := profiles.List()
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "text":
		for _, record := range records {
			if _, err := fmt.Fprintf(stdout, "%-12s %s  %s\n", record.Name, record.Hash, record.Summary); err != nil {
				return err
			}
		}
		return nil
	case "json":
		return writeJSON(stdout, records)
	default:
		return fmt.Errorf("--format must be text or json")
	}
}

func executeProfilesShow(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("profiles show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "yaml", "output format: yaml|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("profile name is required")
	}
	record, err := profiles.Show(fs.Arg(0))
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "yaml":
		_, err := stdout.Write([]byte(record.YAML))
		return err
	case "json":
		return writeJSON(stdout, record)
	default:
		return fmt.Errorf("--format must be yaml or json")
	}
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printPolicyHelp(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "check":
		return runPolicyDecision(args[1:], stdout, stderr, false)
	case "explain":
		return runPolicyDecision(args[1:], stdout, stderr, true)
	default:
		fmt.Fprintln(stderr, "policy command required: check|explain")
		printPolicyHelp(stderr)
		return 2
	}
}

func printPolicyHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  prodclaw policy check (--profile <name> | --bundle <path>) --action <path> [identity flags]")
	fmt.Fprintln(w, "  prodclaw policy explain (--profile <name> | --bundle <path>) --action <path> [identity flags]")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "built-in profiles: %s\n", strings.Join(profiles.Names(), ", "))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "identity flags:")
	fmt.Fprintln(w, "  --principal <name>     default system")
	fmt.Fprintln(w, "  --agent <name>         default prodclaw")
	fmt.Fprintln(w, "  --environment <name>   default ci")
}

func runPolicyDecision(args []string, stdout, stderr io.Writer, explain bool) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var bundlePath string
	var profileName string
	var actionPath string
	var principal string
	var agent string
	var environment string
	fs.StringVar(&bundlePath, "bundle", "", "policy bundle path")
	fs.StringVar(&bundlePath, "policy-bundle", "", "policy bundle path")
	fs.StringVar(&profileName, "profile", "", "built-in profile name")
	fs.StringVar(&actionPath, "action", "", "action json path")
	fs.StringVar(&principal, "principal", "system", "verified principal")
	fs.StringVar(&agent, "agent", "prodclaw", "verified agent")
	fs.StringVar(&environment, "environment", "ci", "verified environment")
	fs.Usage = func() { printPolicyHelp(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	result, err := evaluatePolicy(policyEvalOptions{
		BundlePath:  bundlePath,
		ProfileName: profileName,
		ActionPath:  actionPath,
		Principal:   principal,
		Agent:       agent,
		Environment: environment,
		Explain:     explain,
	})
	if err != nil {
		fmt.Fprintf(stderr, "policy: %v\n", err)
		return 30
	}
	if err := writeJSON(stdout, result); err != nil {
		fmt.Fprintf(stderr, "policy: write output: %v\n", err)
		return 50
	}
	return 0
}

type policyEvalOptions struct {
	BundlePath  string
	ProfileName string
	ActionPath  string
	Principal   string
	Agent       string
	Environment string
	Explain     bool
}

type policyCheckOutput struct {
	Decision         string         `json:"decision"`
	ReasonCode       string         `json:"reason_code"`
	MatchedRuleIDs   []string       `json:"matched_rule_ids"`
	PolicyBundleHash string         `json:"policy_bundle_hash"`
	Obligations      map[string]any `json:"obligations,omitempty"`
}

type policyExplainOutput struct {
	policyCheckOutput
	DenyRules             []policy.DeniedRuleExplanation  `json:"deny_rules"`
	AllowRuleIDs          []string                        `json:"allow_rule_ids"`
	ObligationsPreview    map[string]any                  `json:"obligations_preview"`
	ExecAuthorization     policy.ExecAuthorizationSummary `json:"exec_authorization"`
	MatchedRuleProvenance []policy.MatchedRuleProvenance  `json:"matched_rule_provenance"`
}

func evaluatePolicy(opts policyEvalOptions) (any, error) {
	if opts.BundlePath != "" && opts.ProfileName != "" {
		return nil, fmt.Errorf("--bundle and --profile are mutually exclusive")
	}
	if opts.BundlePath == "" && opts.ProfileName == "" {
		return nil, fmt.Errorf("--bundle or --profile is required")
	}
	if opts.ActionPath == "" {
		return nil, fmt.Errorf("--action is required")
	}
	bundle, err := loadPolicyBundle(opts)
	if err != nil {
		return nil, fmt.Errorf("load bundle: %w", err)
	}
	actionFile, err := os.Open(opts.ActionPath)
	if err != nil {
		return nil, fmt.Errorf("open action: %w", err)
	}
	defer func() { _ = actionFile.Close() }()
	req, err := action.DecodeActionRequest(actionFile)
	if err != nil {
		return nil, fmt.Errorf("decode action: %w", err)
	}
	act, err := action.ToAction(req, identity.VerifiedIdentity{
		Principal:   opts.Principal,
		Agent:       opts.Agent,
		Environment: opts.Environment,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare action: %w", err)
	}
	normalized, err := normalize.Action(act)
	if err != nil {
		return nil, fmt.Errorf("normalize action: %w", err)
	}
	details := policy.NewEngine(bundle).Explain(normalized)
	base := policyCheckOutput{
		Decision:         details.Decision.Decision,
		ReasonCode:       details.Decision.ReasonCode,
		MatchedRuleIDs:   details.Decision.MatchedRuleIDs,
		PolicyBundleHash: details.Decision.PolicyBundleHash,
		Obligations:      details.Decision.Obligations,
	}
	if !opts.Explain {
		return base, nil
	}
	return policyExplainOutput{
		policyCheckOutput:     base,
		DenyRules:             details.DenyRules,
		AllowRuleIDs:          details.AllowRuleIDs,
		ObligationsPreview:    details.ObligationsPreview,
		ExecAuthorization:     details.ExecAuthorization,
		MatchedRuleProvenance: details.MatchedRuleProvenance,
	}, nil
}

func loadPolicyBundle(opts policyEvalOptions) (policy.Bundle, error) {
	if opts.ProfileName != "" {
		return profiles.Load(opts.ProfileName)
	}
	return policy.LoadBundle(opts.BundlePath)
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			set = true
		}
	})
	return set
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
