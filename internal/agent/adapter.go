package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	AgentCodex  = "codex"
	AgentClaude = "claude"

	MCPWiringCodexConfigOverride = "codex_config_override"
	MCPWiringConfigFlag          = "mcp_config_flag"

	AttachmentVerificationLaunchArgv = "launch_argv_verified"
)

type Capabilities struct {
	MCPWiringMethod              string   `json:"mcp_wiring_method"`
	MCPAttachmentVerification    string   `json:"mcp_attachment_verification"`
	FinalOutputCapture           string   `json:"final_output_capture"`
	VersionDiscovery             string   `json:"version_discovery"`
	RequiresGlobalConfigMutation bool     `json:"requires_global_config_mutation"`
	NativeBypassPossible         bool     `json:"native_bypass_possible"`
	UnsupportedFeatures          []string `json:"unsupported_features,omitempty"`
}

type MCPClientConfig struct {
	MCPServers map[string]MCPServer `json:"mcpServers"`
}

type MCPServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type LaunchPlan struct {
	SchemaVersion             string          `json:"schema_version"`
	Agent                     string          `json:"agent"`
	Executable                string          `json:"executable"`
	Workspace                 string          `json:"workspace"`
	Argv                      []string        `json:"argv"`
	Env                       []string        `json:"env,omitempty"`
	MCPConfigPath             string          `json:"mcp_config_path"`
	MCPConfig                 MCPClientConfig `json:"mcp_config"`
	MCPWiringMethod           string          `json:"mcp_wiring_method"`
	MCPAttachmentVerified     bool            `json:"mcp_attachment_verified"`
	MCPAttachmentVerification string          `json:"mcp_attachment_verification"`
	Warnings                  []string        `json:"warnings,omitempty"`
	UnsupportedFeatures       []string        `json:"unsupported_features,omitempty"`
}

type BuildInput struct {
	Workspace        string
	TaskPrompt       string
	MCPConfigPath    string
	MCPConfig        MCPClientConfig
	FinalMessagePath string
}

type Builder interface {
	Name() string
	Capabilities() Capabilities
	Build(BuildInput) (LaunchPlan, error)
}

func Lookup(name string) (Builder, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case AgentCodex:
		return codexBuilder{}, nil
	case AgentClaude:
		return claudeBuilder{}, nil
	default:
		return nil, fmt.Errorf("unsupported agent %q", name)
	}
}

func BuildMCPConfig(command string, args []string) (MCPClientConfig, error) {
	if strings.TrimSpace(command) == "" {
		return MCPClientConfig{}, errors.New("mcp command is required")
	}
	return MCPClientConfig{
		MCPServers: map[string]MCPServer{
			"prodclaw": {
				Command: command,
				Args:    append([]string{}, args...),
			},
		},
	}, nil
}

func MarshalMCPConfig(config MCPClientConfig) ([]byte, error) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DiscoverVersion(builder Builder) string {
	if builder == nil || builder.Capabilities().VersionDiscovery != "version_flag" {
		return ""
	}
	out, err := exec.Command(builder.Name(), "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	line := bytes.TrimSpace(out)
	if len(line) == 0 {
		return ""
	}
	if idx := bytes.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	return string(bytes.TrimSpace(line))
}

type codexBuilder struct{}

func (codexBuilder) Name() string { return AgentCodex }

func (codexBuilder) Capabilities() Capabilities {
	return Capabilities{
		MCPWiringMethod:              MCPWiringCodexConfigOverride,
		MCPAttachmentVerification:    AttachmentVerificationLaunchArgv,
		FinalOutputCapture:           "exec_output_file",
		VersionDiscovery:             "version_flag",
		RequiresGlobalConfigMutation: false,
		NativeBypassPossible:         true,
		UnsupportedFeatures: []string{
			"native_tool_exclusion",
		},
	}
}

func (b codexBuilder) Build(input BuildInput) (LaunchPlan, error) {
	base, server, err := basePlan(b, input)
	if err != nil {
		return LaunchPlan{}, err
	}
	base.Argv = []string{
		"-c", "mcp_servers.prodclaw.command=" + tomlString(server.Command),
		"-c", "mcp_servers.prodclaw.args=" + tomlStringArray(server.Args),
		"-c", `mcp_servers.prodclaw.default_tools_approval_mode="approve"`,
		"-C", input.Workspace,
		"--ask-for-approval", "never",
		"--sandbox", "read-only",
		"exec",
	}
	if strings.TrimSpace(input.FinalMessagePath) != "" {
		base.Argv = append(base.Argv, "-o", input.FinalMessagePath)
	}
	base.Argv = append(base.Argv, input.TaskPrompt)
	base.MCPAttachmentVerified = verifyCodexPlan(base.Argv, server)
	return base, nil
}

type claudeBuilder struct{}

func (claudeBuilder) Name() string { return AgentClaude }

func (claudeBuilder) Capabilities() Capabilities {
	return Capabilities{
		MCPWiringMethod:              MCPWiringConfigFlag,
		MCPAttachmentVerification:    AttachmentVerificationLaunchArgv,
		FinalOutputCapture:           "stdout",
		VersionDiscovery:             "version_flag",
		RequiresGlobalConfigMutation: false,
		NativeBypassPossible:         true,
		UnsupportedFeatures: []string{
			"native_tool_exclusion",
		},
	}
}

func (b claudeBuilder) Build(input BuildInput) (LaunchPlan, error) {
	base, _, err := basePlan(b, input)
	if err != nil {
		return LaunchPlan{}, err
	}
	base.Argv = []string{
		"--strict-mcp-config",
		"--mcp-config", input.MCPConfigPath,
		"--tools", "",
		"--permission-mode", "dontAsk",
		"--print", input.TaskPrompt,
	}
	base.MCPAttachmentVerified = len(base.Argv) >= 3 &&
		base.Argv[1] == "--mcp-config" &&
		base.Argv[2] == input.MCPConfigPath
	return base, nil
}

func basePlan(builder Builder, input BuildInput) (LaunchPlan, MCPServer, error) {
	if strings.TrimSpace(input.Workspace) == "" {
		return LaunchPlan{}, MCPServer{}, errors.New("workspace is required")
	}
	if strings.TrimSpace(input.MCPConfigPath) == "" {
		return LaunchPlan{}, MCPServer{}, errors.New("mcp config path is required")
	}
	server, ok := input.MCPConfig.MCPServers["prodclaw"]
	if !ok {
		return LaunchPlan{}, MCPServer{}, errors.New("generated mcp config missing prodclaw server")
	}
	if len(input.MCPConfig.MCPServers) != 1 {
		return LaunchPlan{}, MCPServer{}, errors.New("generated mcp config must contain only the prodclaw server")
	}
	capabilities := builder.Capabilities()
	return LaunchPlan{
		SchemaVersion:             "v1",
		Agent:                     builder.Name(),
		Executable:                builder.Name(),
		Workspace:                 input.Workspace,
		MCPConfigPath:             input.MCPConfigPath,
		MCPConfig:                 input.MCPConfig,
		MCPWiringMethod:           capabilities.MCPWiringMethod,
		MCPAttachmentVerification: capabilities.MCPAttachmentVerification,
		Warnings: []string{
			"Native agent tools may remain available beside ProdClaw MCP; this launch plan proves MCP attachment, not exclusive mediation.",
		},
		UnsupportedFeatures: append([]string{}, capabilities.UnsupportedFeatures...),
	}, server, nil
}

func verifyCodexPlan(argv []string, server MCPServer) bool {
	wantCommand := "mcp_servers.prodclaw.command=" + tomlString(server.Command)
	wantArgs := "mcp_servers.prodclaw.args=" + tomlStringArray(server.Args)
	for idx := 0; idx+1 < len(argv); idx++ {
		if argv[idx] == "-c" && argv[idx+1] == wantCommand {
			for inner := idx + 2; inner+1 < len(argv); inner++ {
				if argv[inner] == "-c" && argv[inner+1] == wantArgs {
					return true
				}
			}
		}
	}
	return false
}

func tomlString(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(quoted)
}

func tomlStringArray(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, tomlString(value))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
