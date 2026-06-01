package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentkit "github.com/safe-agentic-world/prodclaw/internal/agent"
	"github.com/safe-agentic-world/prodclaw/internal/audit"
	jobkit "github.com/safe-agentic-world/prodclaw/internal/job"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

const replaySchemaVersion = "v1"

type policyArtifact struct {
	SchemaVersion       string                `json:"schema_version"`
	PolicySource        string                `json:"policy_source"`
	Profile             string                `json:"profile,omitempty"`
	BundlePath          string                `json:"bundle_path,omitempty"`
	EffectivePolicyHash string                `json:"effective_policy_hash"`
	BundleSources       []string              `json:"bundle_sources,omitempty"`
	Inputs              []policy.BundleSource `json:"inputs,omitempty"`
	Policy              policyBundleEvidence  `json:"policy"`
}

type policyBundleEvidence struct {
	Version string        `json:"version"`
	Rules   []policy.Rule `json:"rules"`
}

type policyInputsArtifact struct {
	SchemaVersion       string                `json:"schema_version"`
	PolicySource        string                `json:"policy_source"`
	Profile             string                `json:"profile,omitempty"`
	BundlePath          string                `json:"bundle_path,omitempty"`
	EffectivePolicyHash string                `json:"effective_policy_hash"`
	BundleSources       []string              `json:"bundle_sources,omitempty"`
	Inputs              []policy.BundleSource `json:"inputs,omitempty"`
}

type decisionRecord struct {
	SchemaVersion     string   `json:"schema_version"`
	Timestamp         string   `json:"timestamp"`
	ActionID          string   `json:"action_id"`
	TraceID           string   `json:"trace_id"`
	Tool              string   `json:"tool,omitempty"`
	ActionType        string   `json:"action_type"`
	Resource          string   `json:"resource"`
	ActionFingerprint string   `json:"action_fingerprint"`
	Decision          string   `json:"decision"`
	ReasonCode        string   `json:"reason_code"`
	MatchedRuleIDs    []string `json:"matched_rule_ids"`
	PolicyBundleHash  string   `json:"policy_bundle_hash"`
	ResultCode        string   `json:"result_code"`
}

type replayArtifact struct {
	SchemaVersion        string                `json:"schema_version"`
	GeneratedAt          string                `json:"generated_at"`
	JobArtifact          string                `json:"job_artifact"`
	PolicyArtifact       string                `json:"policy_artifact"`
	PolicyInputsArtifact string                `json:"policy_inputs_artifact"`
	AuditArtifact        string                `json:"audit_artifact"`
	DecisionsArtifact    string                `json:"decisions_artifact"`
	ChangedFilesArtifact string                `json:"changed_files_artifact"`
	ResultArtifact       string                `json:"job_result_artifact"`
	ManifestArtifact     string                `json:"manifest_artifact"`
	PolicyBundleHash     string                `json:"policy_bundle_hash"`
	PolicyInputs         []policy.BundleSource `json:"policy_inputs,omitempty"`
	AuditEventCount      int                   `json:"audit_event_count"`
	DecisionCount        int                   `json:"decision_count"`
	ChangedFileCount     int                   `json:"changed_file_count"`
	ExitReason           string                `json:"exit_reason"`
	ExitCode             int                   `json:"exit_code"`
	ObservedActions      []string              `json:"observed_actions,omitempty"`
	DeniedActions        []string              `json:"denied_actions,omitempty"`
	MissingEvidence      []string              `json:"missing_evidence,omitempty"`
}

type artifactManifest struct {
	SchemaVersion string                  `json:"schema_version"`
	GeneratedAt   string                  `json:"generated_at"`
	Files         []artifactManifestEntry `json:"files"`
}

type artifactManifestEntry struct {
	Path        string `json:"path"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type,omitempty"`
}

type replayReport struct {
	SchemaVersion    string   `json:"schema_version"`
	ArtifactDir      string   `json:"artifact_dir"`
	Valid            bool     `json:"valid"`
	Errors           []string `json:"errors,omitempty"`
	ManifestFiles    int      `json:"manifest_files"`
	AuditEvents      int      `json:"audit_events"`
	Decisions        int      `json:"decisions"`
	PolicyBundleHash string   `json:"policy_bundle_hash,omitempty"`
	ExitReason       string   `json:"exit_reason,omitempty"`
	ExitCode         int      `json:"exit_code"`
}

func newPolicyArtifact(selection loadedPolicy) policyArtifact {
	return policyArtifact{
		SchemaVersion:       replaySchemaVersion,
		PolicySource:        selection.Source,
		Profile:             selection.ProfileName,
		BundlePath:          selection.BundlePath,
		EffectivePolicyHash: selection.Bundle.Hash,
		BundleSources:       policy.BundleSourceLabels(selection.Bundle),
		Inputs:              append([]policy.BundleSource{}, selection.Bundle.SourceBundles...),
		Policy: policyBundleEvidence{
			Version: selection.Bundle.Version,
			Rules:   append([]policy.Rule{}, selection.Bundle.Rules...),
		},
	}
}

func newPolicyInputsArtifact(selection loadedPolicy) policyInputsArtifact {
	return policyInputsArtifact{
		SchemaVersion:       replaySchemaVersion,
		PolicySource:        selection.Source,
		Profile:             selection.ProfileName,
		BundlePath:          selection.BundlePath,
		EffectivePolicyHash: selection.Bundle.Hash,
		BundleSources:       policy.BundleSourceLabels(selection.Bundle),
		Inputs:              append([]policy.BundleSource{}, selection.Bundle.SourceBundles...),
	}
}

func writeDecisionStream(path string, events []audit.Event) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	enc := json.NewEncoder(file)
	redactor := redact.DefaultRedactor()
	for _, event := range events {
		record := decisionRecordFromAudit(event)
		safeRecord, err := redactor.RedactJSONValue(record)
		if err != nil {
			return err
		}
		if err := enc.Encode(safeRecord); err != nil {
			return err
		}
	}
	return nil
}

func decisionRecordFromAudit(event audit.Event) decisionRecord {
	return decisionRecord{
		SchemaVersion:     replaySchemaVersion,
		Timestamp:         event.Timestamp,
		ActionID:          event.ActionID,
		TraceID:           event.TraceID,
		Tool:              event.Tool,
		ActionType:        event.ActionType,
		Resource:          event.Resource,
		ActionFingerprint: event.ActionFingerprint,
		Decision:          event.Decision,
		ReasonCode:        event.ReasonCode,
		MatchedRuleIDs:    append([]string{}, event.MatchedRuleIDs...),
		PolicyBundleHash:  event.PolicyBundleHash,
		ResultCode:        event.ResultCode,
	}
}

func newReplayArtifact(output jobRunOutput, changed jobkit.ChangedFilesSummary, events []audit.Event, result jobkit.Result) replayArtifact {
	return replayArtifact{
		SchemaVersion:        replaySchemaVersion,
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		JobArtifact:          relativeArtifactPath(output.ArtifactDir, output.Artifacts.Job),
		PolicyArtifact:       relativeArtifactPath(output.ArtifactDir, output.Artifacts.Policy),
		PolicyInputsArtifact: relativeArtifactPath(output.ArtifactDir, output.Artifacts.PolicyInputs),
		AuditArtifact:        relativeArtifactPath(output.ArtifactDir, output.Artifacts.Audit),
		DecisionsArtifact:    relativeArtifactPath(output.ArtifactDir, output.Artifacts.Decisions),
		ChangedFilesArtifact: relativeArtifactPath(output.ArtifactDir, output.Artifacts.ChangedFiles),
		ResultArtifact:       relativeArtifactPath(output.ArtifactDir, output.Artifacts.Result),
		ManifestArtifact:     relativeArtifactPath(output.ArtifactDir, output.Artifacts.Manifest),
		PolicyBundleHash:     output.PolicyBundleHash,
		PolicyInputs:         append([]policy.BundleSource{}, output.PolicyBundleInputs...),
		AuditEventCount:      len(events),
		DecisionCount:        len(events),
		ChangedFileCount:     len(changed.Changed),
		ExitReason:           result.ExitReason,
		ExitCode:             result.ExitCode,
		ObservedActions:      append([]string{}, result.ObservedActions...),
		DeniedActions:        append([]string{}, result.DeniedActions...),
		MissingEvidence:      append([]string{}, result.MissingEvidence...),
	}
}

func writeSummaryArtifact(path string, output jobRunOutput, result jobkit.Result, events []audit.Event) error {
	text := buildJobSummaryText(output, result, events)
	sanitized, _ := sanitizeReturnPathText(text, "job.summary")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sanitized), 0o600)
}

func buildJobSummaryText(output jobRunOutput, result jobkit.Result, events []audit.Event) string {
	var b strings.Builder
	fmt.Fprintln(&b, "ProdClaw job summary")
	fmt.Fprintf(&b, "Agent: %s\n", output.Agent)
	fmt.Fprintf(&b, "Mode: %s\n", output.Mode)
	fmt.Fprintf(&b, "Policy: %s %s\n", output.PolicySource, output.PolicyBundleHash)
	fmt.Fprintf(&b, "Artifacts: %s\n", output.ArtifactDir)
	fmt.Fprintf(&b, "Exit: %s (%d)\n", result.ExitReason, result.ExitCode)
	fmt.Fprintf(&b, "Allowed actions: %s\n", formatCounts(actionCounts(events, true)))
	fmt.Fprintf(&b, "Denied actions: %s\n", formatCounts(actionCounts(events, false)))
	fmt.Fprintf(&b, "Budget usage: wall_clock_ms=%d tool_calls=%d process_exec_calls=%d network_calls=%d returned_bytes=%d artifact_bytes=%d\n",
		result.Budgets.Usage.WallClockMS,
		result.Budgets.Usage.ToolCalls,
		result.Budgets.Usage.ExecCalls,
		result.Budgets.Usage.NetworkCalls,
		result.Budgets.Usage.ReturnedBytes,
		result.Budgets.Usage.ArtifactBytes,
	)
	fmt.Fprintf(&b, "Budget exceeded: %s\n", formatList(result.Budgets.Exceeded))
	fmt.Fprintf(&b, "Changed files: %s\n", formatChangedFiles(result.ChangedFiles))
	fmt.Fprintf(&b, "Missing expected actions: %s\n", formatList(result.MissingExpectedActions))
	fmt.Fprintf(&b, "Missing mutation evidence: %s\n", formatList(result.MissingMutationEvidence))
	fmt.Fprintf(&b, "Missing evidence: %s\n", formatList(result.MissingEvidence))
	fmt.Fprintf(&b, "Replay: prodclaw replay --artifact-dir %s\n", output.ArtifactDir)
	return b.String()
}

func writeArtifactManifest(root, manifestPath string) error {
	manifest, err := buildArtifactManifest(root, filepath.Base(manifestPath))
	if err != nil {
		return err
	}
	return writeJSONFile(manifestPath, manifest)
}

func buildArtifactManifest(root, excludedBase string) (artifactManifest, error) {
	var entries []artifactManifestEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Base(path) == excludedBase {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries = append(entries, artifactManifestEntry{
			Path:        filepath.ToSlash(rel),
			SizeBytes:   info.Size(),
			SHA256:      sum,
			ContentType: artifactContentType(path),
		})
		return nil
	})
	if err != nil {
		return artifactManifest{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return artifactManifest{
		SchemaVersion: replaySchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Files:         entries,
	}, nil
}

func verifyReplayArtifacts(artifactDir string) replayReport {
	artifactDir = strings.TrimSpace(artifactDir)
	report := replayReport{SchemaVersion: replaySchemaVersion, ArtifactDir: artifactDir}
	addErr := func(format string, args ...any) {
		report.Errors = append(report.Errors, fmt.Sprintf(format, args...))
	}
	if artifactDir == "" {
		addErr("--artifact-dir is required")
		report.Valid = false
		return report
	}
	if abs, err := filepath.Abs(artifactDir); err == nil {
		artifactDir = abs
		report.ArtifactDir = abs
	}

	var manifest artifactManifest
	if err := readJSONArtifact(filepath.Join(artifactDir, "artifact-manifest.json"), &manifest); err != nil {
		addErr("read artifact-manifest.json: %v", err)
	} else {
		report.ManifestFiles = len(manifest.Files)
		for _, err := range verifyManifest(artifactDir, manifest) {
			addErr("%v", err)
		}
	}

	var job jobRunOutput
	if err := readJSONArtifact(filepath.Join(artifactDir, "job.json"), &job); err != nil {
		addErr("read job.json: %v", err)
	}
	var policyEvidence policyArtifact
	if err := readJSONArtifact(filepath.Join(artifactDir, "policy.json"), &policyEvidence); err != nil {
		addErr("read policy.json: %v", err)
	}
	var policyInputs policyInputsArtifact
	if err := readJSONArtifact(filepath.Join(artifactDir, "policy-inputs.json"), &policyInputs); err != nil {
		addErr("read policy-inputs.json: %v", err)
	}
	var replay replayArtifact
	if err := readJSONArtifact(filepath.Join(artifactDir, "replay.json"), &replay); err != nil {
		addErr("read replay.json: %v", err)
	}
	var launch agentkit.LaunchPlan
	if err := readJSONArtifact(filepath.Join(artifactDir, "agent-launch.json"), &launch); err != nil {
		addErr("read agent-launch.json: %v", err)
	}
	var changed jobkit.ChangedFilesSummary
	if err := readJSONArtifact(filepath.Join(artifactDir, "changed-files.json"), &changed); err != nil {
		addErr("read changed-files.json: %v", err)
	}
	var result jobkit.Result
	if err := readJSONArtifact(filepath.Join(artifactDir, "job-result.json"), &result); err != nil {
		addErr("read job-result.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifactDir, "summary.txt")); err != nil {
		addErr("read summary.txt: %v", err)
	}

	events, err := jobkit.ReadAuditEvents(filepath.Join(artifactDir, "audit.jsonl"))
	if err != nil {
		addErr("read audit.jsonl: %v", err)
	}
	decisions, err := readDecisionRecords(filepath.Join(artifactDir, "decisions.jsonl"))
	if err != nil {
		addErr("read decisions.jsonl: %v", err)
	}
	report.AuditEvents = len(events)
	report.Decisions = len(decisions)
	report.PolicyBundleHash = firstNonEmptyString(job.PolicyBundleHash, policyEvidence.EffectivePolicyHash, replay.PolicyBundleHash)
	report.ExitReason = result.ExitReason
	report.ExitCode = result.ExitCode

	if job.PolicyBundleHash != "" && policyEvidence.EffectivePolicyHash != "" && job.PolicyBundleHash != policyEvidence.EffectivePolicyHash {
		addErr("policy hash mismatch: job.json=%s policy.json=%s", job.PolicyBundleHash, policyEvidence.EffectivePolicyHash)
	}
	if policyInputs.EffectivePolicyHash != "" && policyEvidence.EffectivePolicyHash != "" && policyInputs.EffectivePolicyHash != policyEvidence.EffectivePolicyHash {
		addErr("policy hash mismatch: policy-inputs.json=%s policy.json=%s", policyInputs.EffectivePolicyHash, policyEvidence.EffectivePolicyHash)
	}
	if replay.PolicyBundleHash != "" && job.PolicyBundleHash != "" && replay.PolicyBundleHash != job.PolicyBundleHash {
		addErr("policy hash mismatch: replay.json=%s job.json=%s", replay.PolicyBundleHash, job.PolicyBundleHash)
	}
	for _, event := range events {
		if job.PolicyBundleHash != "" && event.PolicyBundleHash != "" && event.PolicyBundleHash != job.PolicyBundleHash {
			addErr("audit event %s policy hash %s does not match job policy hash %s", event.ActionID, event.PolicyBundleHash, job.PolicyBundleHash)
		}
	}
	if replay.SchemaVersion != "" && replay.AuditEventCount != len(events) {
		addErr("replay audit count %d does not match audit.jsonl count %d", replay.AuditEventCount, len(events))
	}
	if replay.SchemaVersion != "" && replay.DecisionCount != len(decisions) {
		addErr("replay decision count %d does not match decisions.jsonl count %d", replay.DecisionCount, len(decisions))
	}
	for _, err := range compareAuditAndDecisions(events, decisions) {
		addErr("%v", err)
	}
	if result.ExitCode == jobkit.ExitSuccess && job.Mode == "run" && len(result.ObservedActions) == 0 {
		addErr("successful run has no observed governed action evidence")
	}

	report.Valid = len(report.Errors) == 0
	return report
}

func verifyManifest(root string, manifest artifactManifest) []error {
	if len(manifest.Files) == 0 {
		return []error{errors.New("artifact manifest has no files")}
	}
	var errs []error
	for _, entry := range manifest.Files {
		if strings.TrimSpace(entry.Path) == "" {
			errs = append(errs, errors.New("artifact manifest contains an empty path"))
			continue
		}
		cleanRel := filepath.Clean(filepath.FromSlash(entry.Path))
		if filepath.IsAbs(entry.Path) || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
			errs = append(errs, fmt.Errorf("artifact manifest path is unsafe: %s", entry.Path))
			continue
		}
		path := filepath.Join(root, cleanRel)
		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("manifest file %s missing: %w", entry.Path, err))
			continue
		}
		if info.Size() != entry.SizeBytes {
			errs = append(errs, fmt.Errorf("manifest file %s size mismatch", entry.Path))
		}
		sum, err := fileSHA256(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("manifest file %s hash failed: %w", entry.Path, err))
			continue
		}
		if sum != entry.SHA256 {
			errs = append(errs, fmt.Errorf("manifest file %s sha256 mismatch", entry.Path))
		}
	}
	return errs
}

func compareAuditAndDecisions(events []audit.Event, decisions []decisionRecord) []error {
	var errs []error
	if len(events) != len(decisions) {
		errs = append(errs, fmt.Errorf("audit event count %d does not match decision count %d", len(events), len(decisions)))
	}
	index := map[string]decisionRecord{}
	for _, decision := range decisions {
		index[decision.ActionID] = decision
	}
	for _, event := range events {
		decision, ok := index[event.ActionID]
		if !ok {
			errs = append(errs, fmt.Errorf("audit event %s has no decision record", event.ActionID))
			continue
		}
		if decision.ActionFingerprint != event.ActionFingerprint ||
			decision.Decision != event.Decision ||
			decision.ReasonCode != event.ReasonCode ||
			decision.PolicyBundleHash != event.PolicyBundleHash ||
			decision.ResultCode != event.ResultCode {
			errs = append(errs, fmt.Errorf("decision record for action %s does not match audit event", event.ActionID))
		}
	}
	return errs
}

func readDecisionRecords(path string) ([]decisionRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var records []decisionRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record decisionRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("decode decision record: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func readJSONArtifact(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func relativeArtifactPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func artifactContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".jsonl":
		return "application/jsonl"
	case ".txt", ".md":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

func actionCounts(events []audit.Event, allowed bool) map[string]int {
	counts := map[string]int{}
	for _, event := range events {
		if allowed {
			if event.Decision == "ALLOW" {
				counts[event.ActionType]++
			}
			continue
		}
		if event.Decision == "DENY" {
			counts[event.ActionType]++
		}
	}
	return counts
}

func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func formatList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	out := append([]string{}, values...)
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func formatChangedFiles(files []jobkit.ChangedFile) string {
	if len(files) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(files))
	for _, file := range files {
		parts = append(parts, strings.TrimSpace(file.Status)+" "+file.Path)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
