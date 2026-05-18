package job

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
)

const MaxTaskBytes = 64 * 1024

const (
	ExitSuccess                 = 0
	ExitPolicyDenied            = 10
	ExitAgentFailure            = 20
	ExitInvalidConfig           = 30
	ExitRuntimeGuaranteeFailure = 40
	ExitInternalError           = 50
	ExitBudgetExhausted         = 60
)

const (
	ReasonSuccess                 = "success"
	ReasonDryRun                  = "dry_run"
	ReasonNoLaunch                = "no_launch"
	ReasonPolicyDenied            = "policy_denied"
	ReasonAgentFailure            = "agent_failure"
	ReasonInvalidConfig           = "invalid_config"
	ReasonRuntimeGuaranteeFailure = "runtime_guarantee_failure"
	ReasonInternalError           = "internal_error"
	ReasonBudgetExhausted         = "budget_exhausted"
)

type BudgetLimits struct {
	WallClockMS   int64 `json:"wall_clock_ms,omitempty"`
	ToolCalls     int   `json:"tool_calls,omitempty"`
	ExecCalls     int   `json:"process_exec_calls,omitempty"`
	NetworkCalls  int   `json:"network_calls,omitempty"`
	ReturnedBytes int64 `json:"returned_bytes,omitempty"`
	ArtifactBytes int64 `json:"artifact_bytes,omitempty"`
}

type BudgetUsage struct {
	WallClockMS   int64 `json:"wall_clock_ms"`
	ToolCalls     int   `json:"tool_calls"`
	ExecCalls     int   `json:"process_exec_calls"`
	NetworkCalls  int   `json:"network_calls"`
	ReturnedBytes int64 `json:"returned_bytes"`
	ArtifactBytes int64 `json:"artifact_bytes"`
}

type BudgetSummary struct {
	Limits   BudgetLimits `json:"limits"`
	Usage    BudgetUsage  `json:"usage"`
	Exceeded []string     `json:"exceeded,omitempty"`
}

type ChangedFile struct {
	Status string `json:"status"`
	Path   string `json:"path"`
}

type ChangedFilesSummary struct {
	Available bool          `json:"available"`
	Error     string        `json:"error,omitempty"`
	Before    []ChangedFile `json:"before,omitempty"`
	After     []ChangedFile `json:"after,omitempty"`
	Changed   []ChangedFile `json:"changed,omitempty"`
}

type EvaluationInput struct {
	Mode                 string
	ExpectedActions      []string
	AuditEvents          []audit.Event
	ChangedFiles         ChangedFilesSummary
	AgentExitErr         error
	AgentMessage         string
	AgentMessageExpected bool
	StartTime            time.Time
	EndTime              time.Time
	BudgetLimits         BudgetLimits
}

type Result struct {
	ExitReason              string        `json:"exit_reason"`
	ExitCode                int           `json:"exit_code"`
	ExpectedActions         []string      `json:"expected_actions,omitempty"`
	ObservedActions         []string      `json:"observed_actions,omitempty"`
	DeniedActions           []string      `json:"denied_actions,omitempty"`
	MissingExpectedActions  []string      `json:"missing_expected_actions,omitempty"`
	ChangedFiles            []ChangedFile `json:"changed_files,omitempty"`
	MissingMutationEvidence []string      `json:"missing_mutation_evidence,omitempty"`
	Budgets                 BudgetSummary `json:"budgets"`
	AgentFailureMarkers     []string      `json:"agent_failure_markers,omitempty"`
}

func ReadTaskFile(workspace, raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("--task is required")
	}
	path := raw
	if !filepath.IsAbs(path) {
		path = filepath.Join(workspace, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve task path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("read task file: %w", err)
	}
	if info.IsDir() {
		return "", "", fmt.Errorf("task path is a directory: %s", abs)
	}
	if info.Size() > MaxTaskBytes {
		return "", "", fmt.Errorf("task file exceeds %d bytes: %s", MaxTaskBytes, abs)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", "", fmt.Errorf("read task file: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", "", fmt.Errorf("task file is empty: %s", abs)
	}
	if !utf8.Valid(data) {
		return "", "", fmt.Errorf("task file must be valid UTF-8: %s", abs)
	}
	return abs, string(data), nil
}

func GitStatus(workspace string) ChangedFilesSummary {
	cmd := exec.Command("git", "-C", workspace, "status", "--porcelain=v1")
	out, err := cmd.Output()
	if err != nil {
		return ChangedFilesSummary{Available: false, Error: err.Error()}
	}
	return ChangedFilesSummary{Available: true, After: parsePorcelain(out)}
}

func DiffChangedFiles(before, after ChangedFilesSummary) ChangedFilesSummary {
	changed := ChangedFilesSummary{Available: before.Available && after.Available, Before: before.After, After: after.After}
	switch {
	case !before.Available:
		changed.Error = before.Error
	case !after.Available:
		changed.Error = after.Error
	default:
		changed.Changed = diffChangedFiles(before.After, after.After)
	}
	return changed
}

func ReadAuditEvents(path string) ([]audit.Event, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var events []audit.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event audit.Event
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func Evaluate(input EvaluationInput) Result {
	expected := sortedUnique(input.ExpectedActions)
	observed := observedSuccessfulActions(input.AuditEvents)
	denied := deniedActions(input.AuditEvents)
	missing := missingActions(expected, observed)
	missingMutations := missingMutationEvidence(input.ChangedFiles.Changed, input.AuditEvents)
	budgets := budgetSummary(input)
	markers := AgentFailureMarkers(input.AgentMessage)

	result := Result{
		ExpectedActions:         expected,
		ObservedActions:         observed,
		DeniedActions:           denied,
		MissingExpectedActions:  missing,
		ChangedFiles:            append([]ChangedFile{}, input.ChangedFiles.Changed...),
		MissingMutationEvidence: missingMutations,
		Budgets:                 budgets,
		AgentFailureMarkers:     markers,
	}

	switch input.Mode {
	case ReasonDryRun:
		result.ExitReason = ReasonDryRun
		result.ExitCode = ExitSuccess
		return result
	case ReasonNoLaunch:
		result.ExitReason = ReasonNoLaunch
		result.ExitCode = ExitSuccess
		return result
	}

	if len(budgets.Exceeded) > 0 {
		result.ExitReason = ReasonBudgetExhausted
		result.ExitCode = ExitBudgetExhausted
		return result
	}
	if len(denied) > 0 || deniedRequiredAction(expected, input.AuditEvents) {
		result.ExitReason = ReasonPolicyDenied
		result.ExitCode = ExitPolicyDenied
		return result
	}
	if input.AgentExitErr != nil ||
		(input.AgentMessageExpected && strings.TrimSpace(input.AgentMessage) == "") ||
		len(markers) > 0 ||
		len(missing) > 0 ||
		len(missingMutations) > 0 {
		result.ExitReason = ReasonAgentFailure
		result.ExitCode = ExitAgentFailure
		return result
	}
	result.ExitReason = ReasonSuccess
	result.ExitCode = ExitSuccess
	return result
}

func AgentFailureMarkers(text string) []string {
	normalized := strings.ToLower(strings.TrimSpace(text))
	normalized = strings.NewReplacer("’", "'", "‘", "'", "“", `"`, "”", `"`).Replace(normalized)
	if normalized == "" {
		return nil
	}
	candidates := []string{
		"user cancelled mcp tool call",
		"user canceled mcp tool call",
		"mcp tool call was cancelled",
		"mcp tool call was canceled",
		"prodclaw `read_file` call was cancelled",
		"prodclaw `read_file` call was canceled",
		"i can't proceed",
		"i cannot proceed",
		"required prodclaw mcp",
		"required prodclaw tool",
		"allow the prodclaw mcp",
		"allow the prodclaw tool",
		"mcp tools unavailable",
		"no mcp tools available",
		"switch the sandbox",
	}
	var markers []string
	for _, marker := range candidates {
		if strings.Contains(normalized, marker) {
			markers = append(markers, marker)
		}
	}
	return markers
}

func parsePorcelain(data []byte) []ChangedFile {
	trimmed := strings.TrimRight(string(data), "\r\n")
	if trimmed == "" {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	out := make([]ChangedFile, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if len(line) < 4 {
			continue
		}
		out = append(out, ChangedFile{Status: strings.TrimSpace(line[:2]), Path: strings.TrimSpace(line[3:])})
	}
	return out
}

func diffChangedFiles(before, after []ChangedFile) []ChangedFile {
	beforeSet := map[string]string{}
	for _, file := range before {
		beforeSet[file.Path] = file.Status
	}
	out := make([]ChangedFile, 0, len(after))
	for _, file := range after {
		if beforeSet[file.Path] != file.Status {
			out = append(out, file)
		}
	}
	return out
}

func observedSuccessfulActions(events []audit.Event) []string {
	set := map[string]struct{}{}
	for _, event := range events {
		if event.Decision == "ALLOW" && event.ResultCode == executor.ResultSuccess {
			set[event.ActionType] = struct{}{}
		}
	}
	return sortedKeys(set)
}

func deniedActions(events []audit.Event) []string {
	set := map[string]struct{}{}
	for _, event := range events {
		if event.Decision == "DENY" || event.ResultCode == executor.ResultDeniedPolicy {
			set[event.ActionType] = struct{}{}
		}
	}
	return sortedKeys(set)
}

func missingActions(expected, observed []string) []string {
	observedSet := map[string]struct{}{}
	for _, actionType := range observed {
		observedSet[actionType] = struct{}{}
	}
	var missing []string
	for _, actionType := range expected {
		if _, ok := observedSet[actionType]; !ok {
			missing = append(missing, actionType)
		}
	}
	return missing
}

func deniedRequiredAction(expected []string, events []audit.Event) bool {
	if len(expected) == 0 {
		return false
	}
	expectedSet := map[string]struct{}{}
	for _, actionType := range expected {
		expectedSet[actionType] = struct{}{}
	}
	for _, event := range events {
		if _, ok := expectedSet[event.ActionType]; !ok {
			continue
		}
		if event.Decision == "DENY" || event.ResultCode == executor.ResultDeniedPolicy {
			return true
		}
	}
	return false
}

func missingMutationEvidence(changed []ChangedFile, events []audit.Event) []string {
	if len(changed) == 0 {
		return nil
	}
	patchObserved := false
	writes := map[string]struct{}{}
	for _, event := range events {
		if event.Decision != "ALLOW" || event.ResultCode != executor.ResultSuccess {
			continue
		}
		switch event.ActionType {
		case "repo.apply_patch":
			patchObserved = true
		case "fs.write":
			writes[resourcePath(event.Resource)] = struct{}{}
		}
	}
	if patchObserved {
		return nil
	}
	var missing []string
	for _, file := range changed {
		if _, ok := writes[normalizeChangedPath(file.Path)]; !ok {
			missing = append(missing, file.Path)
		}
	}
	sort.Strings(missing)
	return missing
}

func resourcePath(resource string) string {
	return normalizeChangedPath(strings.TrimPrefix(resource, "file://workspace/"))
}

func normalizeChangedPath(path string) string {
	return strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(path)), "./")
}

func budgetSummary(input EvaluationInput) BudgetSummary {
	usage := BudgetUsage{
		WallClockMS: input.EndTime.Sub(input.StartTime).Milliseconds(),
		ToolCalls:   len(input.AuditEvents),
	}
	for _, event := range input.AuditEvents {
		switch event.ActionType {
		case "process.exec":
			usage.ExecCalls++
		case "net.http_request":
			usage.NetworkCalls++
		}
		usage.ReturnedBytes += int64(event.ReturnedBytes)
		usage.ArtifactBytes += int64(event.ArtifactBytes)
	}
	summary := BudgetSummary{Limits: input.BudgetLimits, Usage: usage}
	if input.BudgetLimits.WallClockMS > 0 && usage.WallClockMS > input.BudgetLimits.WallClockMS {
		summary.Exceeded = append(summary.Exceeded, "wall_clock_ms")
	}
	if input.BudgetLimits.ToolCalls > 0 && usage.ToolCalls > input.BudgetLimits.ToolCalls {
		summary.Exceeded = append(summary.Exceeded, "tool_calls")
	}
	if input.BudgetLimits.ExecCalls > 0 && usage.ExecCalls > input.BudgetLimits.ExecCalls {
		summary.Exceeded = append(summary.Exceeded, "process_exec_calls")
	}
	if input.BudgetLimits.NetworkCalls > 0 && usage.NetworkCalls > input.BudgetLimits.NetworkCalls {
		summary.Exceeded = append(summary.Exceeded, "network_calls")
	}
	if input.BudgetLimits.ReturnedBytes > 0 && usage.ReturnedBytes > input.BudgetLimits.ReturnedBytes {
		summary.Exceeded = append(summary.Exceeded, "returned_bytes")
	}
	if input.BudgetLimits.ArtifactBytes > 0 && usage.ArtifactBytes > input.BudgetLimits.ArtifactBytes {
		summary.Exceeded = append(summary.Exceeded, "artifact_bytes")
	}
	return summary
}

func sortedUnique(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
