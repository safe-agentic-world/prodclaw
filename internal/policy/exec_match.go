package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/normalize"
)

type execParams struct {
	Argv             []string `json:"argv"`
	CWD              string   `json:"cwd"`
	EnvAllowlistKeys []string `json:"env_allowlist_keys"`
	StdinMode        string   `json:"stdin_mode"`
	ShellMode        bool     `json:"shell_mode"`
	OutputMaxBytes   int      `json:"output_max_bytes"`
	OutputMaxLines   int      `json:"output_max_lines"`
}

func matchExec(rule Rule, action normalize.NormalizedAction) bool {
	if rule.ExecMatch == nil {
		return true
	}
	if action.ActionType != "process.exec" {
		return false
	}
	params, ok := decodeExecParams(action.Params)
	if !ok || len(params.Argv) == 0 {
		return false
	}
	for _, pattern := range rule.ExecMatch.ArgvPatterns {
		if matchArgvPattern(pattern, params.Argv) {
			return true
		}
	}
	return false
}

func decodeExecParams(raw []byte) (execParams, bool) {
	var params execParams
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil {
		return execParams{}, false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return execParams{}, false
	}
	if len(params.Argv) == 0 {
		return execParams{}, false
	}
	if params.StdinMode == "" {
		params.StdinMode = "none"
	}
	return params, true
}

func matchArgvPattern(pattern, argv []string) bool {
	return matchArgvSegments(pattern, argv)
}

func matchArgvSegments(pattern, argv []string) bool {
	if len(pattern) == 0 {
		return len(argv) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(argv); i++ {
			if matchArgvSegments(pattern[1:], argv[i:]) {
				return true
			}
		}
		return false
	}
	if len(argv) == 0 {
		return false
	}
	if !matchArgvToken(pattern[0], argv[0]) {
		return false
	}
	return matchArgvSegments(pattern[1:], argv[1:])
}

func matchArgvToken(pattern, token string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == token
	}
	return matchArgvWildcard(pattern, token)
}

func matchArgvWildcard(pattern, value string) bool {
	pIdx := 0
	vIdx := 0
	starIdx := -1
	matchIdx := 0
	for vIdx < len(value) {
		if pIdx < len(pattern) && (pattern[pIdx] == value[vIdx] || pattern[pIdx] == '?') {
			pIdx++
			vIdx++
			continue
		}
		if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = vIdx
			pIdx++
			continue
		}
		if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			vIdx = matchIdx
			continue
		}
		return false
	}
	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == len(pattern)
}

func classifyExecPreflight(params execParams) (string, string) {
	if !params.ShellMode && hasShellMetacharacters(params.Argv) {
		return "deny_by_exec_shell_metacharacters", "shell_metacharacter_risk"
	}
	if hasSensitiveEnvKey(params.EnvAllowlistKeys) {
		return "deny_by_exec_env_secret", "env_secret_injection"
	}
	return "", ""
}

func hasShellMetacharacters(argv []string) bool {
	for _, token := range argv {
		if strings.ContainsAny(token, ";|&<>`") || strings.Contains(token, "$(") || strings.ContainsAny(token, "\r\n") {
			return true
		}
	}
	return false
}

func hasSensitiveEnvKey(keys []string) bool {
	for _, key := range keys {
		lower := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "credential") ||
			strings.Contains(lower, "auth") ||
			strings.HasSuffix(lower, "_key") {
			return true
		}
	}
	return false
}
