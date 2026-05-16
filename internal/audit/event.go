package audit

import (
	"encoding/json"

	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
	"github.com/safe-agentic-world/prodclaw/internal/schema"
)

const SchemaVersionV1 = "v1"

type Event struct {
	SchemaVersion     string                    `json:"schema_version"`
	Timestamp         string                    `json:"timestamp"`
	ActionID          string                    `json:"action_id"`
	TraceID           string                    `json:"trace_id"`
	Tool              string                    `json:"tool,omitempty"`
	ActionType        string                    `json:"action_type"`
	Resource          string                    `json:"resource"`
	ParamsHash        string                    `json:"params_hash"`
	Principal         string                    `json:"principal"`
	Agent             string                    `json:"agent"`
	Environment       string                    `json:"environment"`
	ActionFingerprint string                    `json:"action_fingerprint"`
	Decision          string                    `json:"decision"`
	ReasonCode        string                    `json:"reason_code"`
	MatchedRuleIDs    []string                  `json:"matched_rule_ids"`
	PolicyBundleHash  string                    `json:"policy_bundle_hash"`
	ResultCode        string                    `json:"result_code"`
	Retryable         bool                      `json:"retryable"`
	RedactionSummary  executor.RedactionSummary `json:"redaction_summary"`
	ExecCondition     string                    `json:"exec_condition,omitempty"`
	HTTPStatusCode    int                       `json:"http_status_code,omitempty"`
	HTTPFinalResource string                    `json:"http_final_resource,omitempty"`
	HTTPRedirectHops  int                       `json:"http_redirect_hops,omitempty"`
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
	event.ReasonCode = redactor.RedactText(event.ReasonCode)
	event.ExecCondition = redactor.RedactText(event.ExecCondition)
	event.HTTPFinalResource = redactor.RedactText(event.HTTPFinalResource)
	for idx, ruleID := range event.MatchedRuleIDs {
		event.MatchedRuleIDs[idx] = redactor.RedactText(ruleID)
	}
	return event
}
