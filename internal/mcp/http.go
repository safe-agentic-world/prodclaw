package mcp

import (
	"encoding/json"
	"errors"

	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
)

type httpRequestInput struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	OutputMaxBytes int               `json:"output_max_bytes"`
	OutputMaxLines int               `json:"output_max_lines"`
}

func normalizedHTTPParams(raw []byte) (normalize.HTTPParams, error) {
	var params normalize.HTTPParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return normalize.HTTPParams{}, err
	}
	return params, nil
}

func redirectPolicyFromObligations(obligations map[string]any) executor.RedirectPolicy {
	policy := executor.RedirectPolicy{
		AllowHosts: networkAllowlistHosts(obligations),
	}
	if enabled, ok := obligations["http_redirects"].(bool); ok {
		policy.Enabled = enabled
	}
	if limit, ok := intObligation(obligations["http_redirect_hop_limit"]); ok {
		policy.HopLimit = limit
	}
	return policy
}

func networkAllowlistHosts(obligations map[string]any) []string {
	raw, ok := obligations["net_allowlist"]
	if !ok {
		return nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	hosts := make([]string, 0, len(values))
	for _, value := range values {
		host, ok := value.(string)
		if ok {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func intObligation(raw any) (int, bool) {
	switch typed := raw.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		if typed != float64(int(typed)) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func validateHTTPInput(input httpRequestInput) error {
	if input.OutputMaxBytes < 0 || input.OutputMaxLines < 0 {
		return errors.New("output caps must be >= 0")
	}
	return nil
}
