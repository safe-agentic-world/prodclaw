package normalize

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/safe-agentic-world/prodclaw/internal/action"
)

func TestNormalizeFileTraversalRejected(t *testing.T) {
	_, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/dir/../secret.txt",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestNormalizeRejectsSymlinkEscapeLikeTraversal(t *testing.T) {
	_, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/link/../outside",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err == nil {
		t.Fatal("expected symlink escape rejection")
	}
}

func TestNormalizeEquivalentURIs(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace//a/b",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if result.Resource != "file://workspace/a/b" {
		t.Fatalf("expected normalized resource, got %s", result.Resource)
	}
}

func TestNormalizeURLHostLowercase(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "net.http_request",
		Resource:      "url://Example.COM:80/path",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if result.Resource != "url://example.com/path" {
		t.Fatalf("expected normalized url, got %s", result.Resource)
	}
}

func TestNormalizeRepoLowercase(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "repo.apply_patch",
		Resource:      "repo://Org/Service",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if result.Resource != "repo://org/service" {
		t.Fatalf("expected normalized repo, got %s", result.Resource)
	}
}

func TestNormalizeCustomResource(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "payments.refund",
		Resource:      "Payment://Shop.Example.Com/orders/ORD-1001",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize custom resource: %v", err)
	}
	if result.Resource != "payment://shop.example.com/orders/ORD-1001" {
		t.Fatalf("expected normalized custom resource, got %s", result.Resource)
	}
}

func TestNormalizeCustomResourceRejectsQuery(t *testing.T) {
	_, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "payments.refund",
		Resource:      "payment://shop.example.com/orders/ORD-1001?x=1",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err == nil {
		t.Fatal("expected custom resource query rejection")
	}
}

func TestNormalizeArtifactResource(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "artifact.write",
		Resource:      "artifact://job/reports/summary.txt",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize artifact resource: %v", err)
	}
	if result.Resource != "artifact://job/reports/summary.txt" {
		t.Fatalf("expected normalized artifact resource, got %s", result.Resource)
	}
}

func TestMatchPatternDeterministic(t *testing.T) {
	ok, err := MatchPattern("foo/*/bar", "foo/a/bar")
	if err != nil {
		t.Fatalf("match error: %v", err)
	}
	if !ok {
		t.Fatal("expected match")
	}
	_, err = MatchPattern("foo\\*\\bar", "foo\\a\\bar")
	if err == nil {
		t.Fatal("expected backslash error")
	}
}

func TestNormalizationIsPure(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "normalize.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if path == "os" || path == "path/filepath" {
			t.Fatalf("normalize imports forbidden package %s", path)
		}
	}
}

func TestFingerprintStableForEquivalentNormalizedActions(t *testing.T) {
	first, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act-a",
		ActionType:    "process.exec",
		Resource:      "file://workspace//",
		Params:        []byte(`{"cwd":"","argv":["git","status"],"env_allowlist_keys":[]}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "ci",
		TraceID:       "trace-a",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize first action: %v", err)
	}
	second, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act-b",
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params:        []byte(`{"env_allowlist_keys":[],"argv":["git","status"],"cwd":""}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "ci",
		TraceID:       "trace-b",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize second action: %v", err)
	}
	firstFingerprint, err := Fingerprint(first, "policy-hash")
	if err != nil {
		t.Fatalf("fingerprint first action: %v", err)
	}
	secondFingerprint, err := Fingerprint(second, "policy-hash")
	if err != nil {
		t.Fatalf("fingerprint second action: %v", err)
	}
	if firstFingerprint != secondFingerprint {
		t.Fatalf("expected equivalent normalized actions to match, got %s and %s", firstFingerprint, secondFingerprint)
	}
	differentPolicyFingerprint, err := Fingerprint(second, "different-policy-hash")
	if err != nil {
		t.Fatalf("fingerprint different policy: %v", err)
	}
	if firstFingerprint == differentPolicyFingerprint {
		t.Fatal("expected policy hash to affect fingerprint")
	}
}

func TestFingerprintGoldenVector(t *testing.T) {
	normalized, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act-1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/docs/readme.md",
		Params:        []byte(`{"resource":"docs/readme.md"}`),
		Principal:     "system",
		Agent:         "prodclaw",
		Environment:   "ci",
		TraceID:       "trace-1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize action: %v", err)
	}
	got, err := Fingerprint(normalized, "bundle-hash")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	const expected = "23d4e5f5bd4fe252d424aa836a9d0b1d95768af1262f2b128fdc602c1386717a"
	if got != expected {
		t.Fatalf("expected fingerprint %s, got %s", expected, got)
	}
}
