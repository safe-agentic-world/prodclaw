package logging

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
)

var secretValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]+\b`),
	regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._-]+\b`),
}

type Logger struct {
	writer io.Writer
	now    func() time.Time
}

type event struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Event     string         `json:"event"`
	Fields    map[string]any `json:"fields,omitempty"`
}

func New(writer io.Writer) Logger {
	return Logger{
		writer: writer,
		now:    time.Now,
	}
}

func (l Logger) Info(name string, fields map[string]any) error {
	return l.write("info", name, fields)
}

func (l Logger) Error(name string, fields map[string]any) error {
	return l.write("error", name, fields)
}

func (l Logger) write(level, name string, fields map[string]any) error {
	redacted, _ := RedactFields(fields).(map[string]any)
	return json.NewEncoder(l.writer).Encode(event{
		Timestamp: l.now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Event:     name,
		Fields:    redacted,
	})
}

func RedactFields(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if sensitiveKey(key) {
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = RedactFields(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, RedactFields(item))
		}
		return out
	case string:
		out := typed
		for _, pattern := range secretValuePatterns {
			out = pattern.ReplaceAllString(out, "[REDACTED]")
		}
		return out
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "authorization") ||
		strings.HasSuffix(lower, "_key")
}
