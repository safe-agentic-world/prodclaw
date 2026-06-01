package job

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
)

func TestReadTaskFileValidation(t *testing.T) {
	workspace := t.TempDir()
	empty := filepath.Join(workspace, "empty.md")
	large := filepath.Join(workspace, "large.md")
	invalid := filepath.Join(workspace, "invalid.md")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatalf("write empty task: %v", err)
	}
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), MaxTaskBytes+1), 0o600); err != nil {
		t.Fatalf("write large task: %v", err)
	}
	if err := os.WriteFile(invalid, []byte{0xff, 0xfe}, 0o600); err != nil {
		t.Fatalf("write invalid task: %v", err)
	}
	tests := []struct {
		name string
		task string
		want string
	}{
		{name: "missing", task: "", want: "--task is required"},
		{name: "empty", task: empty, want: "task file is empty"},
		{name: "large", task: large, want: "task file exceeds"},
		{name: "invalid", task: invalid, want: "valid UTF-8"},
		{name: "directory", task: workspace, want: "task path is a directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ReadTaskFile(workspace, tc.task)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestParsePorcelainPreservesLeadingStatusSpacing(t *testing.T) {
	files := parsePorcelain([]byte(" M README.md\n"))
	if len(files) != 1 {
		t.Fatalf("expected one changed file, got %+v", files)
	}
	if files[0].Status != "M" || files[0].Path != "README.md" {
		t.Fatalf("unexpected parsed file: %+v", files[0])
	}
}

func TestEvaluatePolicyDenialAndExpectedActionGate(t *testing.T) {
	now := time.Now()
	result := Evaluate(EvaluationInput{
		ExpectedActions: []string{"process.exec"},
		AuditEvents: []audit.Event{
			{ActionType: "process.exec", Decision: "DENY", ResultCode: executor.ResultDeniedPolicy},
		},
		StartTime: now,
		EndTime:   now,
	})
	if result.ExitCode != ExitPolicyDenied || result.ExitReason != ReasonPolicyDenied {
		t.Fatalf("unexpected denial result: %+v", result)
	}

	missing := Evaluate(EvaluationInput{
		ExpectedActions: []string{"process.exec"},
		StartTime:       now,
		EndTime:         now,
	})
	if missing.ExitCode != ExitAgentFailure || len(missing.MissingExpectedActions) != 1 {
		t.Fatalf("expected missing-action failure, got %+v", missing)
	}
}

func TestEvaluateMutationGate(t *testing.T) {
	now := time.Now()
	result := Evaluate(EvaluationInput{
		ChangedFiles: ChangedFilesSummary{
			Changed: []ChangedFile{{Status: "M", Path: "README.md"}},
		},
		StartTime: now,
		EndTime:   now,
	})
	if result.ExitCode != ExitAgentFailure || len(result.MissingMutationEvidence) != 1 {
		t.Fatalf("expected mutation evidence failure, got %+v", result)
	}

	allowed := Evaluate(EvaluationInput{
		ChangedFiles: ChangedFilesSummary{
			Changed: []ChangedFile{{Status: "M", Path: "README.md"}},
		},
		AuditEvents: []audit.Event{
			{ActionType: "fs.write", Resource: "file://workspace/README.md", Decision: "ALLOW", ResultCode: executor.ResultSuccess},
		},
		StartTime: now,
		EndTime:   now,
	})
	if allowed.ExitCode != ExitSuccess {
		t.Fatalf("expected mutation evidence success, got %+v", allowed)
	}
}

func TestEvaluateAgentMessageOnlyIsMissingEvidence(t *testing.T) {
	now := time.Now()
	result := Evaluate(EvaluationInput{
		AgentMessage:         "Completed.",
		AgentMessageExpected: true,
		StartTime:            now,
		EndTime:              now,
	})
	if result.ExitCode != ExitAgentFailure || len(result.MissingEvidence) != 1 || result.MissingEvidence[0] != "governed_action_audit" {
		t.Fatalf("expected missing governed-action evidence, got %+v", result)
	}
}

func TestEvaluateBudgets(t *testing.T) {
	start := time.Now()
	result := Evaluate(EvaluationInput{
		AuditEvents: []audit.Event{
			{ActionType: "process.exec", Decision: "ALLOW", ResultCode: executor.ResultSuccess, ReturnedBytes: 20},
			{ActionType: "artifact.write", Decision: "ALLOW", ResultCode: executor.ResultSuccess, ArtifactBytes: 40},
		},
		StartTime: start,
		EndTime:   start.Add(2 * time.Second),
		BudgetLimits: BudgetLimits{
			WallClockMS:   1000,
			ToolCalls:     1,
			ExecCalls:     0,
			ReturnedBytes: 10,
			ArtifactBytes: 10,
		},
	})
	if result.ExitCode != ExitBudgetExhausted || len(result.Budgets.Exceeded) != 4 {
		t.Fatalf("unexpected budget result: %+v", result)
	}
}

func TestEvaluateAgentFailureMarkers(t *testing.T) {
	now := time.Now()
	result := Evaluate(EvaluationInput{
		AgentMessageExpected: true,
		AgentMessage:         "I can't proceed because the required ProdClaw MCP tool call was canceled.",
		StartTime:            now,
		EndTime:              now,
	})
	if result.ExitCode != ExitAgentFailure || len(result.AgentFailureMarkers) == 0 {
		t.Fatalf("expected agent failure markers, got %+v", result)
	}
}
