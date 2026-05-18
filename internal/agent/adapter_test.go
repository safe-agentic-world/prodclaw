package agent

import (
	"strings"
	"testing"
)

func TestCodexLaunchPlanUsesConfigOverrides(t *testing.T) {
	builder, err := Lookup("codex")
	if err != nil {
		t.Fatalf("lookup codex: %v", err)
	}
	config, err := BuildMCPConfig("prodclaw", []string{"mcp", "--profile", "ci-strict"})
	if err != nil {
		t.Fatalf("build mcp config: %v", err)
	}
	plan, err := builder.Build(BuildInput{
		Workspace:     "/workspace",
		TaskPrompt:    "fix it",
		MCPConfigPath: "/workspace/.prodclaw/agent/codex.mcp.json",
		MCPConfig:     config,
	})
	if err != nil {
		t.Fatalf("build codex plan: %v", err)
	}
	if plan.MCPWiringMethod != MCPWiringCodexConfigOverride || !plan.MCPAttachmentVerified {
		t.Fatalf("unexpected codex wiring metadata: %+v", plan)
	}
	got := strings.Join(plan.Argv, "\x00")
	for _, want := range []string{
		`mcp_servers.prodclaw.command="prodclaw"`,
		`mcp_servers.prodclaw.args=["mcp","--profile","ci-strict"]`,
		`mcp_servers.prodclaw.default_tools_approval_mode="approve"`,
		"exec\x00fix it",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("codex argv missing %q: %+v", want, plan.Argv)
		}
	}
	if plan.MCPConfig.MCPServers["prodclaw"].Command != "prodclaw" || len(plan.MCPConfig.MCPServers) != 1 {
		t.Fatalf("unexpected codex mcp config: %+v", plan.MCPConfig)
	}
}

func TestClaudeLaunchPlanUsesMCPConfigFlag(t *testing.T) {
	builder, err := Lookup("claude")
	if err != nil {
		t.Fatalf("lookup claude: %v", err)
	}
	config, err := BuildMCPConfig("prodclaw", []string{"mcp", "--profile", "ci-strict"})
	if err != nil {
		t.Fatalf("build mcp config: %v", err)
	}
	plan, err := builder.Build(BuildInput{
		Workspace:     "/workspace",
		TaskPrompt:    "fix it",
		MCPConfigPath: "/workspace/.prodclaw/agent/claude.mcp.json",
		MCPConfig:     config,
	})
	if err != nil {
		t.Fatalf("build claude plan: %v", err)
	}
	if plan.MCPWiringMethod != MCPWiringConfigFlag || !plan.MCPAttachmentVerified {
		t.Fatalf("unexpected claude wiring metadata: %+v", plan)
	}
	if got := strings.Join(plan.Argv, "\x00"); got != "--mcp-config\x00/workspace/.prodclaw/agent/claude.mcp.json\x00-p\x00fix it" {
		t.Fatalf("unexpected claude argv: %+v", plan.Argv)
	}
}

func TestGeneratedMCPConfigRejectsExtraServers(t *testing.T) {
	builder, err := Lookup("codex")
	if err != nil {
		t.Fatalf("lookup codex: %v", err)
	}
	_, err = builder.Build(BuildInput{
		Workspace:     "/workspace",
		TaskPrompt:    "fix it",
		MCPConfigPath: "/workspace/.prodclaw/agent/codex.mcp.json",
		MCPConfig: MCPClientConfig{MCPServers: map[string]MCPServer{
			"prodclaw": {Command: "prodclaw"},
			"raw-fs":   {Command: "filesystem"},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "only the prodclaw server") {
		t.Fatalf("expected extra server rejection, got %v", err)
	}
}

func TestAdapterCapabilitiesExposeUniformContract(t *testing.T) {
	codex, _ := Lookup("codex")
	claude, _ := Lookup("claude")
	for _, builder := range []Builder{codex, claude} {
		caps := builder.Capabilities()
		if caps.MCPWiringMethod == "" || caps.MCPAttachmentVerification == "" || caps.FinalOutputCapture == "" || caps.VersionDiscovery == "" {
			t.Fatalf("incomplete capabilities for %s: %+v", builder.Name(), caps)
		}
		if caps.RequiresGlobalConfigMutation || !caps.NativeBypassPossible {
			t.Fatalf("unexpected capability flags for %s: %+v", builder.Name(), caps)
		}
	}
}
