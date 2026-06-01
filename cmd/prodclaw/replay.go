package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	jobkit "github.com/safe-agentic-world/prodclaw/internal/job"
)

func runReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var artifactDir string
	var format string
	fs.StringVar(&artifactDir, "artifact-dir", "", "ProdClaw artifact directory")
	fs.StringVar(&format, "format", "text", "output format: text|json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage:")
		fmt.Fprintln(stderr, "  prodclaw replay --artifact-dir <path> [--format text|json]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "replay: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	report := verifyReplayArtifacts(artifactDir)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		printReplayReport(stdout, report)
	case "json":
		if err := writeJSON(stdout, report); err != nil {
			fmt.Fprintf(stderr, "replay: write output: %v\n", err)
			return jobkit.ExitInternalError
		}
	default:
		fmt.Fprintln(stderr, "replay: --format must be text or json")
		return jobkit.ExitInvalidConfig
	}
	if !report.Valid {
		return jobkit.ExitRuntimeGuaranteeFailure
	}
	return jobkit.ExitSuccess
}

func printReplayReport(w io.Writer, report replayReport) {
	fmt.Fprintf(w, "Artifact dir: %s\n", report.ArtifactDir)
	fmt.Fprintf(w, "Valid: %t\n", report.Valid)
	fmt.Fprintf(w, "Policy bundle: %s\n", report.PolicyBundleHash)
	fmt.Fprintf(w, "Exit: %s (%d)\n", report.ExitReason, report.ExitCode)
	fmt.Fprintf(w, "Manifest files: %d\n", report.ManifestFiles)
	fmt.Fprintf(w, "Audit events: %d\n", report.AuditEvents)
	fmt.Fprintf(w, "Decisions: %d\n", report.Decisions)
	for _, errText := range report.Errors {
		fmt.Fprintf(w, "ERROR: %s\n", errText)
	}
}
