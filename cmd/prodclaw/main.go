package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/version"
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
	fmt.Fprintln(os.Stderr, "prodclaw commands:")
	fmt.Fprintln(os.Stderr, "  version    print build metadata")
	fmt.Fprintln(os.Stderr, "  policy     check or explain policy decisions")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "planned:")
	fmt.Fprintln(os.Stderr, "  job run    run Codex or Claude Code in a governed CI boundary")
	fmt.Fprintln(os.Stderr, "  mcp        start the ProdClaw MCP stdio server")
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
	fmt.Fprintln(w, "  prodclaw policy check --bundle <path> --action <path> [identity flags]")
	fmt.Fprintln(w, "  prodclaw policy explain --bundle <path> --action <path> [identity flags]")
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
	var actionPath string
	var principal string
	var agent string
	var environment string
	fs.StringVar(&bundlePath, "bundle", "", "policy bundle path")
	fs.StringVar(&bundlePath, "policy-bundle", "", "policy bundle path")
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
	DenyRules              []policy.DeniedRuleExplanation  `json:"deny_rules"`
	AllowRuleIDs           []string                        `json:"allow_rule_ids"`
	RequireApprovalRuleIDs []string                        `json:"require_approval_rule_ids"`
	ObligationsPreview     map[string]any                  `json:"obligations_preview"`
	ExecAuthorization      policy.ExecAuthorizationSummary `json:"exec_authorization"`
	MatchedRuleProvenance  []policy.MatchedRuleProvenance  `json:"matched_rule_provenance"`
}

func evaluatePolicy(opts policyEvalOptions) (any, error) {
	if opts.BundlePath == "" {
		return nil, fmt.Errorf("--bundle is required")
	}
	if opts.ActionPath == "" {
		return nil, fmt.Errorf("--action is required")
	}
	bundle, err := policy.LoadBundle(opts.BundlePath)
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
		policyCheckOutput:      base,
		DenyRules:              details.DenyRules,
		AllowRuleIDs:           details.AllowRuleIDs,
		RequireApprovalRuleIDs: details.RequireApprovalRuleIDs,
		ObligationsPreview:     details.ObligationsPreview,
		ExecAuthorization:      details.ExecAuthorization,
		MatchedRuleProvenance:  details.MatchedRuleProvenance,
	}, nil
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
