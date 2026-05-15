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
