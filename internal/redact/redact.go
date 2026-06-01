package redact

import (
	"encoding/json"
	"errors"
	"regexp"
)

type Redactor struct {
	patterns []*regexp.Regexp
}

func DefaultRedactor() *Redactor {
	return &Redactor{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)proxy-authorization:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)authorization:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)set-cookie:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)cookie:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)x-api-key:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)x-auth-token:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]{12,}=*`),
			regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9\+\/=]{12,}`),
			regexp.MustCompile(`(?i)\bsk-[A-Za-z0-9_-]{8,}\b`),
			regexp.MustCompile(`\bghp_[A-Za-z0-9_]{8,}\b`),
			regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}\b`),
			regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{8,}\b`),
			regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{8,}\b`),
			regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}\b`),
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
			regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*-----END [A-Z ]+-----`),
		},
	}
}

func NewRedactor(customPatterns []string) (*Redactor, error) {
	redactor := DefaultRedactor()
	for _, pattern := range customPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.New("invalid redaction pattern")
		}
		redactor.patterns = append(redactor.patterns, re)
	}
	return redactor, nil
}

func (r *Redactor) RedactText(text string) string {
	if r == nil {
		r = DefaultRedactor()
	}
	redacted := text
	for _, pattern := range r.patterns {
		redacted = pattern.ReplaceAllString(redacted, "[REDACTED]")
	}
	return redacted
}

func (r *Redactor) RedactBytes(payload []byte) []byte {
	return []byte(r.RedactText(string(payload)))
}

func (r *Redactor) RedactJSONValue(value any) (any, error) {
	if r == nil {
		r = DefaultRedactor()
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	return r.redactJSON(decoded), nil
}

func (r *Redactor) redactJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[r.RedactText(key)] = r.redactJSON(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for idx, value := range typed {
			out[idx] = r.redactJSON(value)
		}
		return out
	case string:
		return r.RedactText(typed)
	default:
		return value
	}
}
