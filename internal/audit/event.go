package audit

import (
	"encoding/json"

	"github.com/safe-agentic-world/prodclaw/internal/doctor"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
	"github.com/safe-agentic-world/prodclaw/internal/schema"
)

const SchemaVersionV1 = "v1"

type Event struct {
	SchemaVersion      string                             `json:"schema_version"`
	Timestamp          string                             `json:"timestamp"`
	ActionID           string                             `json:"action_id"`
	TraceID            string                             `json:"trace_id"`
	Tool               string                             `json:"tool,omitempty"`
	ActionType         string                             `json:"action_type"`
	Resource           string                             `json:"resource"`
	ParamsHash         string                             `json:"params_hash"`
	Principal          string                             `json:"principal"`
	Agent              string                             `json:"agent"`
	Environment        string                             `json:"environment"`
	CIIdentity         identity.CIIdentity                `json:"ci_identity,omitempty"`
	CredentialExposure identity.CredentialExposureSummary `json:"credential_exposure,omitempty"`
	AssuranceLevel     string                             `json:"assurance_level,omitempty"`
	MediationCoverage  []doctor.Coverage                  `json:"mediation_coverage,omitempty"`
	ActionFingerprint  string                             `json:"action_fingerprint"`
	Decision           string                             `json:"decision"`
	ReasonCode         string                             `json:"reason_code"`
	MatchedRuleIDs     []string                           `json:"matched_rule_ids"`
	PolicyBundleHash   string                             `json:"policy_bundle_hash"`
	ResultCode         string                             `json:"result_code"`
	Retryable          bool                               `json:"retryable"`
	RedactionSummary   executor.RedactionSummary          `json:"redaction_summary"`
	ReturnedBytes      int                                `json:"returned_bytes,omitempty"`
	ArtifactBytes      int                                `json:"artifact_bytes,omitempty"`
	ExecCondition      string                             `json:"exec_condition,omitempty"`
	HTTPStatusCode     int                                `json:"http_status_code,omitempty"`
	HTTPFinalResource  string                             `json:"http_final_resource,omitempty"`
	HTTPRedirectHops   int                                `json:"http_redirect_hops,omitempty"`
}

func ValidateEventSchema(event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return schema.Validate(eventSchema(), data)
}

func RedactEvent(event Event, redactor *redact.Redactor) Event {
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	event.Tool = redactor.RedactText(event.Tool)
	event.ActionType = redactor.RedactText(event.ActionType)
	event.Resource = redactor.RedactText(event.Resource)
	event.Principal = redactor.RedactText(event.Principal)
	event.Agent = redactor.RedactText(event.Agent)
	event.Environment = redactor.RedactText(event.Environment)
	event.CIIdentity = redactCIIdentity(event.CIIdentity, redactor)
	event.CredentialExposure = redactCredentialExposure(event.CredentialExposure, redactor)
	event.AssuranceLevel = redactor.RedactText(event.AssuranceLevel)
	for idx, coverage := range event.MediationCoverage {
		event.MediationCoverage[idx].Surface = redactor.RedactText(coverage.Surface)
		event.MediationCoverage[idx].Level = redactor.RedactText(coverage.Level)
		event.MediationCoverage[idx].Evidence = redactor.RedactText(coverage.Evidence)
	}
	event.ReasonCode = redactor.RedactText(event.ReasonCode)
	event.ExecCondition = redactor.RedactText(event.ExecCondition)
	event.HTTPFinalResource = redactor.RedactText(event.HTTPFinalResource)
	for idx, ruleID := range event.MatchedRuleIDs {
		event.MatchedRuleIDs[idx] = redactor.RedactText(ruleID)
	}
	return event
}

func redactCIIdentity(ci identity.CIIdentity, redactor *redact.Redactor) identity.CIIdentity {
	ci.Provider = redactor.RedactText(ci.Provider)
	ci.Repo = redactor.RedactText(ci.Repo)
	ci.Project = redactor.RedactText(ci.Project)
	ci.Ref = redactor.RedactText(ci.Ref)
	ci.Branch = redactor.RedactText(ci.Branch)
	ci.CommitSHA = redactor.RedactText(ci.CommitSHA)
	ci.RunID = redactor.RedactText(ci.RunID)
	ci.PipelineID = redactor.RedactText(ci.PipelineID)
	ci.WorkflowRunID = redactor.RedactText(ci.WorkflowRunID)
	ci.JobID = redactor.RedactText(ci.JobID)
	ci.Actor = redactor.RedactText(ci.Actor)
	ci.EventType = redactor.RedactText(ci.EventType)
	ci.WorkspaceRoot = redactor.RedactText(ci.WorkspaceRoot)
	return ci
}

func redactCredentialExposure(summary identity.CredentialExposureSummary, redactor *redact.Redactor) identity.CredentialExposureSummary {
	for idx, key := range summary.AgentEnvKeys {
		summary.AgentEnvKeys[idx] = redactor.RedactText(key)
	}
	for idx, key := range summary.ExecutorOnlyKeys {
		summary.ExecutorOnlyKeys[idx] = redactor.RedactText(key)
	}
	for idx, key := range summary.ScrubbedKeys {
		summary.ScrubbedKeys[idx] = redactor.RedactText(key)
	}
	if len(summary.CredentialScopes) > 0 {
		redacted := make(map[string]bool, len(summary.CredentialScopes))
		for key, value := range summary.CredentialScopes {
			redacted[redactor.RedactText(key)] = value
		}
		summary.CredentialScopes = redacted
	}
	return summary
}
