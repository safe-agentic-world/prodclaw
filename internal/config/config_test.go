package config

import "testing"

func TestLoadUsesFileThenEnvironment(t *testing.T) {
	values, err := Decode([]byte(`{"profile":"ci-strict","workspace":"repo","agent":"claude","task":"task.md","policy_inputs":{"baseline":{"path":"base.yaml"}}}`))
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	values.applyEnv(func(key string) (string, bool) {
		switch key {
		case "PRODCLAW_PROFILE":
			return "ci-standard", true
		case "PRODCLAW_AGENT":
			return "codex", true
		case "PRODCLAW_CONTROLLED_CI":
			return "true", true
		case "PRODCLAW_POLICY_REPOSITORY":
			return "repo.yaml", true
		case "PRODCLAW_POLICY_REPOSITORY_SHA256":
			return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true
		default:
			return "", false
		}
	})
	if values.Profile != "ci-standard" || values.Agent != "codex" {
		t.Fatalf("expected environment overrides, got %+v", values)
	}
	if values.Workspace != "repo" || values.TaskPath != "task.md" {
		t.Fatalf("expected file values retained, got %+v", values)
	}
	if !values.ControlledCI {
		t.Fatalf("expected controlled CI override, got %+v", values)
	}
	if values.PolicyInputs.Baseline.Path != "base.yaml" || values.PolicyInputs.Repository.Path != "repo.yaml" || values.PolicyInputs.Repository.SHA256 == "" {
		t.Fatalf("expected layered policy inputs, got %+v", values.PolicyInputs)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	if _, err := Decode([]byte(`{"profile":"ci-strict","unknown":true}`)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestPolicyInputsOrdered(t *testing.T) {
	inputs := PolicyInputs{
		Baseline:     PolicyInput{Path: "base.yaml"},
		Organization: PolicyInput{Path: "org.yaml"},
		Repository:   PolicyInput{Path: "repo.yaml"},
		Environment:  PolicyInput{Path: "env.yaml"},
		Job:          PolicyInput{Path: "job.yaml"},
	}
	ordered := inputs.Ordered()
	want := []string{"baseline", "organization", "repository", "environment", "job"}
	if len(ordered) != len(want) {
		t.Fatalf("ordered input count = %d, want %d", len(ordered), len(want))
	}
	for idx, role := range want {
		if ordered[idx].Role != role {
			t.Fatalf("ordered[%d].Role = %q, want %q", idx, ordered[idx].Role, role)
		}
	}
}
