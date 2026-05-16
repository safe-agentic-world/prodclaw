package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
)

var defaultProfileNames = []string{"ci-standard", "ci-strict"}

func TestDefaultPolicyProfileDecisions(t *testing.T) {
	tests := []struct {
		name       string
		profile    string
		actionType string
		resource   string
		params     map[string]any
		want       string
	}{
		{name: "ci strict denies dotenv", profile: "ci-strict", actionType: "fs.read", resource: "file://workspace/.env", params: map[string]any{"resource": ".env"}, want: DecisionDeny},
		{name: "ci strict allows git status", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "status"), want: DecisionAllow},
		{name: "ci strict denies git push", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "push", "origin", "main"), want: DecisionDeny},
		{name: "ci strict denies terraform destroy", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "destroy"), want: DecisionDeny},
		{name: "ci strict allows go test", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("go", "test", "./..."), want: DecisionAllow},
		{name: "ci strict denies go env", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("go", "env"), want: DecisionDeny},
		{name: "ci strict allows terraform plan", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "plan"), want: DecisionAllow},
		{name: "ci strict allows kubectl get", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "get", "pods"), want: DecisionAllow},
		{name: "ci strict denies kubectl delete", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "delete", "pod", "x"), want: DecisionDeny},
		{name: "ci strict allows structured publish", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("prodclaw", "publish-artifact", "dist/app.tgz"), want: DecisionAllow},
		{name: "ci strict allows artifact writes", profile: "ci-strict", actionType: "artifact.write", resource: "artifact://job/summary.txt", params: map[string]any{"path": "summary.txt"}, want: DecisionAllow},
		{name: "ci strict denies unknown egress by default", profile: "ci-strict", actionType: "net.http_request", resource: "url://unknown.example.com/api", params: httpParamsForTest("GET", nil), want: DecisionDeny},
		{name: "ci strict denies lowercase auth header after normalization", profile: "ci-strict", actionType: "net.http_request", resource: "url://github.com/api", params: httpParamsForTest("GET", map[string]string{"authorization": "Bearer secret"}), want: DecisionDeny},
		{name: "ci strict denies lowercase cookie header after normalization", profile: "ci-strict", actionType: "net.http_request", resource: "url://github.com/api", params: httpParamsForTest("GET", map[string]string{"cookie": "session=secret"}), want: DecisionDeny},
		{name: "ci standard denies dotenv", profile: "ci-standard", actionType: "fs.read", resource: "file://workspace/.env", params: map[string]any{"resource": ".env"}, want: DecisionDeny},
		{name: "ci standard allows git status", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "status"), want: DecisionAllow},
		{name: "ci standard denies main branch push", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "push", "origin", "main"), want: DecisionDeny},
		{name: "ci standard denies terraform destroy", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "destroy"), want: DecisionDeny},
		{name: "ci standard denies go env", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("go", "env"), want: DecisionDeny},
		{name: "ci standard allows terraform plan", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "plan"), want: DecisionAllow},
		{name: "ci standard allows kubectl get", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "get", "pods"), want: DecisionAllow},
		{name: "ci standard denies kubectl delete", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "delete", "pod", "x"), want: DecisionDeny},
		{name: "ci standard denies unknown egress by default", profile: "ci-standard", actionType: "net.http_request", resource: "url://unknown.example.com/api", params: httpParamsForTest("GET", nil), want: DecisionDeny},
		{name: "ci standard denies lowercase auth header after normalization", profile: "ci-standard", actionType: "net.http_request", resource: "url://github.com/api", params: httpParamsForTest("GET", map[string]string{"authorization": "Bearer secret"}), want: DecisionDeny},
		{name: "ci standard denies lowercase cookie header after normalization", profile: "ci-standard", actionType: "net.http_request", resource: "url://github.com/api", params: httpParamsForTest("GET", map[string]string{"cookie": "session=secret"}), want: DecisionDeny},
		{name: "ci standard allows feature branch push", profile: "ci-standard", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "push", "origin", "HEAD:refs/heads/ai-dev-agent/ACDK-1"), want: DecisionAllow},
		{name: "ci standard allows artifact writes", profile: "ci-standard", actionType: "artifact.write", resource: "artifact://job/summary.txt", params: map[string]any{"path": "summary.txt"}, want: DecisionAllow},
		{name: "ci standard allows merge request create", profile: "ci-standard", actionType: "net.http_request", resource: "url://gitlab.com/api/v4/projects/123/merge_requests", params: httpParamsForTest("POST", map[string]string{"PRIVATE-TOKEN": "redacted"}), want: DecisionAllow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := loadDefaultProfileBundle(t, tc.profile)
			decision := evaluateProfileDecision(t, bundle, tc.actionType, tc.resource, tc.params)
			if decision.Decision != tc.want {
				t.Fatalf("decision = %s (%s via %v), want %s", decision.Decision, decision.ReasonCode, decision.MatchedRuleIDs, tc.want)
			}
		})
	}
}

func TestDefaultProfilesContainOnlyAllowOrDenyDecisions(t *testing.T) {
	for _, name := range defaultProfileNames {
		t.Run(name, func(t *testing.T) {
			bundle := loadDefaultProfileBundle(t, name)
			for _, rule := range bundle.Rules {
				if rule.Decision != DecisionAllow && rule.Decision != DecisionDeny {
					t.Fatalf("profile %s rule %s uses unsupported decision %s", name, rule.ID, rule.Decision)
				}
			}
		})
	}
}

func loadDefaultProfileBundle(t *testing.T, name string) Bundle {
	t.Helper()
	bundle, err := LoadBundle(repoPath(filepath.Join("profiles", name+".yaml")))
	if err != nil {
		t.Fatalf("load %s profile: %v", name, err)
	}
	return bundle
}

func evaluateProfileDecision(t *testing.T, bundle Bundle, actionType, resource string, params map[string]any) Decision {
	t.Helper()
	paramBytes, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "profile_test",
		ActionType:    actionType,
		Resource:      resource,
		Params:        paramBytes,
		TraceID:       "profile_test",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "prodclaw", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	normalized, err := normalize.Action(act)
	if err != nil {
		t.Fatalf("normalize action: %v", err)
	}
	return NewEngine(bundle).Evaluate(normalized)
}

func execParamsForTest(argv ...string) map[string]any {
	return map[string]any{
		"argv":               argv,
		"cwd":                "",
		"env_allowlist_keys": []string{},
		"stdin_mode":         "none",
		"shell_mode":         false,
		"output_max_bytes":   0,
		"output_max_lines":   0,
	}
}

func httpParamsForTest(method string, headers map[string]string) map[string]any {
	if headers == nil {
		headers = map[string]string{}
	}
	return map[string]any{
		"method":  method,
		"body":    "",
		"headers": headers,
	}
}

func readRepoFileBytes(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(repoPath(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return data
}

func repoPath(rel string) string {
	return filepath.Join("..", "..", rel)
}
