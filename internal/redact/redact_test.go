package redact

import (
	"strings"
	"testing"
)

func TestDefaultRedactorCoversKnownSecretCorpus(t *testing.T) {
	redactor := DefaultRedactor()
	cases := []string{
		"Authorization: Bearer super-secret-token\n",
		"Cookie: session=abc123\n",
		"sk-proj-verysecretvalue",
		"AKIA1234567890ABCDEF",
		"ghp_m13githubtokensecret1234567890",
		"glpat-m13gitlabtokensecret",
		"eyJhbGciOiJIUzI1NiJ9.eyJwcm9kY2xhdyI6InRlc3QifQ.m13signature",
		"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
	}
	for _, input := range cases {
		output := redactor.RedactText(input)
		if output == input {
			t.Fatalf("expected redaction for %q", input)
		}
		for _, leaked := range []string{"super-secret-token", "session=abc123", "sk-proj-verysecretvalue", "AKIA", "PRIVATE KEY"} {
			if strings.Contains(output, leaked) {
				t.Fatalf("expected %q to be redacted in %q", leaked, output)
			}
		}
	}
}

func TestRedactJSONValuePreservesJSONShape(t *testing.T) {
	value := map[string]any{
		"token":  "ghp_m13githubtokensecret1234567890",
		"nested": []any{"Authorization: Bearer m13AuthorizationToken123456"},
	}
	redacted, err := DefaultRedactor().RedactJSONValue(value)
	if err != nil {
		t.Fatalf("redact json: %v", err)
	}
	payload := redacted.(map[string]any)
	if payload["token"] != "[REDACTED]" {
		t.Fatalf("expected token redaction, got %+v", payload)
	}
	nested := payload["nested"].([]any)
	if nested[0] != "[REDACTED]" {
		t.Fatalf("expected nested redaction, got %+v", payload)
	}
}
