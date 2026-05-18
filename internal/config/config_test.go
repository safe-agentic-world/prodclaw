package config

import "testing"

func TestLoadUsesFileThenEnvironment(t *testing.T) {
	values, err := Decode([]byte(`{"profile":"ci-strict","workspace":"repo","agent":"claude","task":"task.md"}`))
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
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	if _, err := Decode([]byte(`{"profile":"ci-strict","unknown":true}`)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}
