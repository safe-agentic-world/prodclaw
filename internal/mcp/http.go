package mcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
)

type httpRequestInput struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Headers          map[string]string `json:"headers"`
	Body             string            `json:"body"`
	CredentialEnvKey string            `json:"credential_env_key"`
	CredentialHeader string            `json:"credential_header"`
	OutputMaxBytes   int               `json:"output_max_bytes"`
	OutputMaxLines   int               `json:"output_max_lines"`
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
	if strings.TrimSpace(input.CredentialEnvKey) != "" && !identity.SensitiveEnvKey(input.CredentialEnvKey) {
		return errors.New("credential_env_key must name a sensitive executor-only credential")
	}
	if strings.ContainsAny(input.CredentialHeader, "\r\n") {
		return errors.New("credential_header contains invalid characters")
	}
	return nil
}

func materializeHTTPCredential(input httpRequestInput, lookup identity.LookupEnv) (string, string, error) {
	key := strings.TrimSpace(input.CredentialEnvKey)
	if key == "" {
		return "", "", nil
	}
	if lookup == nil {
		lookup = identity.LookupEnv(func(key string) (string, bool) { return "", false })
	}
	value, ok := lookup(key)
	if !ok {
		return "", "", errors.New("executor credential is not available")
	}
	header := http.CanonicalHeaderKey(strings.TrimSpace(input.CredentialHeader))
	if header == "" {
		header = defaultCredentialHeader(key)
	}
	if strings.EqualFold(header, "Authorization") && strings.EqualFold(key, "GITHUB_TOKEN") {
		return header, "Bearer " + value, nil
	}
	return header, value, nil
}

func credentialScopeForEnvKey(key string) string {
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "":
		return ""
	case "GITHUB_TOKEN":
		return "github_token"
	case "GITLAB_TOKEN", "CI_JOB_TOKEN":
		return "gitlab_token"
	case "OPENAI_API_KEY":
		return "openai_api"
	case "ANTHROPIC_API_KEY":
		return "anthropic_api"
	case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN":
		return "aws"
	case "GOOGLE_APPLICATION_CREDENTIALS":
		return "gcp"
	case "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID":
		return "azure"
	case "SSH_AUTH_SOCK":
		return "ssh_agent"
	default:
		return "credential"
	}
}

func defaultCredentialHeader(key string) string {
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "GITLAB_TOKEN":
		return "Private-Token"
	case "CI_JOB_TOKEN":
		return "Job-Token"
	default:
		return "Authorization"
	}
}
