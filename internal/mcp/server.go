package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/canonicaljson"
	"github.com/safe-agentic-world/prodclaw/internal/doctor"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

type Server struct {
	bundle            policy.Bundle
	workspace         string
	artifactDir       string
	workspaceReal     string
	artifactDirReal   string
	auditPath         string
	id                identity.VerifiedIdentity
	assuranceLevel    string
	mediationCoverage []doctor.Coverage
	httpRunner        *executor.HTTPRunner
	redactor          *redact.Redactor
	forwardTool       ToolForwarder
	commandExec       func(context.Context, string, commandRequest) commandResult
}

func (s *Server) AdvertisedToolNames() []string {
	definitions := s.toolDefinitions()
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		if name, ok := definition["name"].(string); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

type Options struct {
	Bundle      policy.Bundle
	Workspace   string
	ArtifactDir string
	AuditPath   string
	Identity    identity.VerifiedIdentity
	Redactor    *redact.Redactor
	ForwardTool ToolForwarder
}

type ToolForwarder func(context.Context, string, string, json.RawMessage) (any, error)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Input     json.RawMessage `json:"input"`
}

type commandResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
}

type commandRequest struct {
	Argv             []string `json:"argv"`
	CWD              string   `json:"cwd"`
	EnvAllowlistKeys []string `json:"env_allowlist_keys"`
	StdinMode        string   `json:"stdin_mode"`
	ShellMode        bool     `json:"shell_mode"`
	OutputMaxBytes   int      `json:"output_max_bytes"`
	OutputMaxLines   int      `json:"output_max_lines"`
}

type toolSpec struct {
	Friendly    string
	Canonical   string
	ActionType  string
	Description string
	Properties  map[string]any
	Required    []string
	ReadOnly    bool
}

type authorizedAction struct {
	tool        string
	actionType  string
	normalized  normalize.NormalizedAction
	decision    policy.Decision
	explanation policy.ExplainDetails
	fingerprint string
}

func NewServer(opts Options) (*Server, error) {
	workspace := strings.TrimSpace(opts.Workspace)
	if workspace == "" {
		workspace = "."
	}
	absWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	realWorkspace := realBasePath(absWorkspace)
	id := opts.Identity
	if id.Principal == "" {
		id.Principal = "system"
	}
	if id.Agent == "" {
		id.Agent = "prodclaw"
	}
	if id.Environment == "" {
		id.Environment = "ci"
	}
	if id.CI.WorkspaceRoot == "" {
		id.CI.WorkspaceRoot = absWorkspace
	}
	if len(id.CredentialExposure.AgentEnvKeys) == 0 && len(id.CredentialExposure.ExecutorOnlyKeys) == 0 && len(id.CredentialExposure.ScrubbedKeys) == 0 && len(id.CredentialExposure.CredentialScopes) == 0 {
		id.CredentialExposure = identity.CredentialExposure(os.LookupEnv, nil)
	}
	artifactDir := strings.TrimSpace(opts.ArtifactDir)
	if artifactDir == "" {
		artifactDir = filepath.Join(absWorkspace, ".prodclaw", "artifacts")
	}
	absArtifactDir, err := filepath.Abs(artifactDir)
	if err != nil {
		return nil, err
	}
	realArtifactDir := realBasePath(absArtifactDir)
	redactor := opts.Redactor
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	assuranceLevel, mediationCoverage := doctor.AssuranceFromEnv(os.LookupEnv)
	return &Server{
		bundle:            opts.Bundle,
		workspace:         absWorkspace,
		artifactDir:       absArtifactDir,
		workspaceReal:     realWorkspace,
		artifactDirReal:   realArtifactDir,
		auditPath:         opts.AuditPath,
		id:                id,
		assuranceLevel:    assuranceLevel,
		mediationCoverage: mediationCoverage,
		redactor:          redactor,
		forwardTool:       opts.ForwardTool,
		httpRunner:        executor.NewHTTPRunner(nil),
		commandExec:       runCommand,
	}, nil
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	writer := bufio.NewWriter(out)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		first, err := reader.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var payload []byte
		framed := false
		if first[0] == 'C' || first[0] == 'c' {
			payload, err = readFramedPayload(reader)
			framed = true
		} else {
			payload, err = readJSONLine(reader)
		}
		if err != nil {
			return err
		}
		var req rpcRequest
		if err := json.Unmarshal(bytes.TrimSpace(payload), &req); err != nil {
			continue
		}
		if len(req.ID) == 0 {
			_ = s.handleNotification(req)
			continue
		}
		resp := s.handleRequest(ctx, req)
		if framed {
			err = writeFramedPayload(writer, resp)
		} else {
			err = writeJSONLine(writer, resp)
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) handleNotification(req rpcRequest) error {
	return nil
}

func (s *Server) handleRequest(ctx context.Context, req rpcRequest) rpcResponse {
	id := decodeID(req.ID)
	result, err := s.dispatch(ctx, req)
	if err != nil {
		return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32000, Message: s.redactor.RedactText(err.Error())}}
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *Server) dispatch(ctx context.Context, req rpcRequest) (any, error) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "prodclaw",
				"version": "dev",
			},
		}, nil
	case "tools/list":
		return map[string]any{"tools": s.toolDefinitions(), "capabilities": s.capabilitySummary()}, nil
	case "tools/call":
		name, args, err := parseToolCallParams(req.Params)
		if err != nil {
			return s.toolErrorResult(err), nil
		}
		result, err := s.callTool(ctx, name, args)
		if err != nil {
			return s.toolErrorResult(err), nil
		}
		return result, nil
	case "ping":
		return map[string]any{}, nil
	default:
		return nil, fmt.Errorf("unsupported method %q", req.Method)
	}
}

func decodeID(raw json.RawMessage) any {
	var id any
	if err := json.Unmarshal(raw, &id); err != nil {
		return string(raw)
	}
	return id
}

func parseToolCallParams(raw json.RawMessage) (string, json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil, errors.New("invalid tools/call params")
	}
	var params toolCallParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return "", nil, fmt.Errorf("invalid tools/call params: %w", err)
	}
	name := strings.TrimSpace(params.Name)
	if name == "" {
		return "", nil, errors.New("invalid tools/call params: name is required")
	}
	if len(bytes.TrimSpace(params.Arguments)) > 0 {
		return name, params.Arguments, nil
	}
	if len(bytes.TrimSpace(params.Input)) > 0 {
		return name, params.Input, nil
	}
	return name, json.RawMessage(`{}`), nil
}

func readJSONLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(bytes.TrimSpace(line)) == 0 {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return readJSONLine(reader)
	}
	return line, nil
}

func readFramedPayload(reader *bufio.Reader) ([]byte, error) {
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid framed header")
		}
		headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	lengthRaw := headers["content-length"]
	if lengthRaw == "" {
		return nil, errors.New("missing content-length")
	}
	n, err := strconv.Atoi(lengthRaw)
	if err != nil || n < 0 || n > 4*1024*1024 {
		return nil, errors.New("invalid content-length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeFramedPayload(writer *bufio.Writer, payload rpcResponse) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(data)); err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Flush()
}

func writeJSONLine(writer *bufio.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}
	return writer.Flush()
}

func baseToolSpecs() []toolSpec {
	return []toolSpec{
		{
			Friendly:    "capabilities",
			Canonical:   "ProdClaw.capabilities",
			Description: "Return the policy-derived capability contract for this MCP session.",
			Properties:  map[string]any{},
			ReadOnly:    true,
		},
		{
			Friendly:    "read_file",
			Canonical:   "ProdClaw.read_file",
			ActionType:  "fs.read",
			Description: "Read a workspace file through ProdClaw policy.",
			Properties: map[string]any{
				"path": map[string]any{"type": "string"},
			},
			Required: []string{"path"},
			ReadOnly: true,
		},
		{
			Friendly:    "write_file",
			Canonical:   "ProdClaw.write_file",
			ActionType:  "fs.write",
			Description: "Write a workspace file through ProdClaw policy.",
			Properties: map[string]any{
				"path":    map[string]any{"type": "string"},
				"content": map[string]any{"type": "string"},
			},
			Required: []string{"path", "content"},
		},
		{
			Friendly:    "apply_patch",
			Canonical:   "ProdClaw.apply_patch",
			ActionType:  "repo.apply_patch",
			Description: "Apply a unified diff patch through ProdClaw policy.",
			Properties: map[string]any{
				"patch": map[string]any{"type": "string"},
			},
			Required: []string{"patch"},
		},
		{
			Friendly:    "run_command",
			Canonical:   "ProdClaw.run_command",
			ActionType:  "process.exec",
			Description: "Run a command through ProdClaw process.exec policy.",
			Properties: map[string]any{
				"argv":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"cwd":                map[string]any{"type": "string"},
				"env_allowlist_keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"stdin_mode":         map[string]any{"type": "string"},
				"shell_mode":         map[string]any{"type": "boolean"},
				"output_max_bytes":   map[string]any{"type": "integer"},
				"output_max_lines":   map[string]any{"type": "integer"},
			},
			Required: []string{"argv"},
		},
		{
			Friendly:    "http_request",
			Canonical:   "ProdClaw.http_request",
			ActionType:  "net.http_request",
			Description: "Send an HTTP request through ProdClaw net.http_request policy.",
			Properties: map[string]any{
				"url":                map[string]any{"type": "string"},
				"method":             map[string]any{"type": "string"},
				"headers":            map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
				"body":               map[string]any{"type": "string"},
				"credential_env_key": map[string]any{"type": "string"},
				"credential_header":  map[string]any{"type": "string"},
				"output_max_bytes":   map[string]any{"type": "integer"},
				"output_max_lines":   map[string]any{"type": "integer"},
			},
			Required: []string{"url"},
		},
		{
			Friendly:    "call_tool",
			Canonical:   "ProdClaw.call_tool",
			ActionType:  "mcp.call",
			Description: "Forward an upstream tool call through ProdClaw mcp.call policy.",
			Properties: map[string]any{
				"server":    map[string]any{"type": "string"},
				"tool":      map[string]any{"type": "string"},
				"arguments": map[string]any{"type": "object"},
			},
			Required: []string{"server", "tool"},
		},
		{
			Friendly:    "write_artifact",
			Canonical:   "ProdClaw.write_artifact",
			ActionType:  "artifact.write",
			Description: "Write a job artifact through ProdClaw artifact.write policy.",
			Properties: map[string]any{
				"path":    map[string]any{"type": "string"},
				"content": map[string]any{"type": "string"},
			},
			Required: []string{"path", "content"},
		},
	}
}

func (s *Server) toolDefinitions() []map[string]any {
	specs := baseToolSpecs()
	tools := make([]map[string]any, 0, len(specs)*2)
	for _, spec := range specs {
		tools = append(tools, s.toolDefinition(spec, spec.Friendly))
		tools = append(tools, s.toolDefinition(spec, spec.Canonical))
	}
	return tools
}

func (s *Server) toolDefinition(spec toolSpec, name string) map[string]any {
	entry := tool(name, spec.Description, spec.Properties, spec.Required)
	entry["annotations"] = map[string]any{
		"readOnlyHint":    spec.ReadOnly,
		"destructiveHint": !spec.ReadOnly,
	}
	entry["_meta"] = map[string]any{
		"prodclaw": map[string]any{
			"canonical_name":       spec.Canonical,
			"friendly_name":        spec.Friendly,
			"aliases":              []string{spec.Friendly, spec.Canonical},
			"action_type":          spec.ActionType,
			"capability":           s.capabilityForActionType(spec.ActionType),
			"identity":             s.capabilityIdentity(),
			"runtime":              s.capabilityRuntime(),
			"adapter_capabilities": s.adapterCapabilities(),
		},
	}
	return entry
}

func tool(name, description string, properties map[string]any, required []string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"name":        name,
		"description": description,
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           properties,
			"required":             required,
			"additionalProperties": false,
		},
	}
}

func (s *Server) capabilitySummary() map[string]any {
	specs := baseToolSpecs()
	advertised := make([]string, 0, len(specs)*2)
	enabled := make([]string, 0, len(specs))
	unavailable := make([]string, 0, len(specs))
	toolStates := make(map[string]any, len(specs))
	for _, spec := range specs {
		advertised = append(advertised, spec.Friendly, spec.Canonical)
		capability := s.capabilityForActionType(spec.ActionType)
		state, _ := capability["state"].(string)
		if state == "allow" {
			enabled = append(enabled, spec.Canonical)
		} else {
			unavailable = append(unavailable, spec.Canonical)
		}
		toolStates[spec.Canonical] = map[string]any{
			"canonical_name": spec.Canonical,
			"friendly_name":  spec.Friendly,
			"action_type":    spec.ActionType,
			"capability":     capability,
		}
	}
	sort.Strings(advertised)
	sort.Strings(enabled)
	sort.Strings(unavailable)
	return map[string]any{
		"contract_version":       "prodclaw.mcp.capabilities.v1",
		"advisory_only":          true,
		"authorization_notice":   "Advisory only. ProdClaw evaluates every action live against policy and runtime controls.",
		"policy_bundle_hash":     s.bundle.Hash,
		"tool_advertisement":     "static_supported_tools_with_policy_capability_metadata",
		"advertised_tools":       advertised,
		"enabled_tools":          enabled,
		"unavailable_tools":      unavailable,
		"tool_states":            toolStates,
		"identity":               s.capabilityIdentity(),
		"runtime":                s.capabilityRuntime(),
		"adapter_capabilities":   s.adapterCapabilities(),
		"principal_scope_source": "verified_runtime_identity",
	}
}

func (s *Server) capabilityForActionType(actionType string) map[string]any {
	if strings.TrimSpace(actionType) == "" {
		return map[string]any{
			"state":                "allow",
			"advisory":             true,
			"immediately_callable": true,
			"resource_classes":     []string{},
			"host_classes":         []string{},
			"exec_classes":         []string{},
		}
	}
	capability := policy.NewEngine(s.bundle).CapabilityForActionType(actionType, s.id.Principal, s.id.Agent, s.id.Environment)
	return map[string]any{
		"state":                capability.State(),
		"advisory":             true,
		"immediately_callable": capability.Allow,
		"resource_classes":     append([]string{}, capability.ResourceClasses...),
		"host_classes":         append([]string{}, capability.HostClasses...),
		"exec_classes":         append([]string{}, capability.ExecClasses...),
	}
}

func (s *Server) capabilityIdentity() map[string]any {
	return map[string]any{
		"principal":   s.id.Principal,
		"agent":       s.id.Agent,
		"environment": s.id.Environment,
		"ci": map[string]any{
			"provider":   s.id.CI.Provider,
			"project":    s.id.CI.Project,
			"repo":       s.id.CI.Repo,
			"ref":        s.id.CI.Ref,
			"branch":     s.id.CI.Branch,
			"commit_sha": s.id.CI.CommitSHA,
			"run_id":     s.id.CI.RunID,
			"job_id":     s.id.CI.JobID,
			"actor":      s.id.CI.Actor,
			"event_type": s.id.CI.EventType,
		},
	}
}

func (s *Server) capabilityRuntime() map[string]any {
	return map[string]any{
		"environment":         s.id.Environment,
		"ci_provider":         s.id.CI.Provider,
		"policy_bundle_hash":  s.bundle.Hash,
		"workspace_confined":  true,
		"artifact_confined":   true,
		"credential_boundary": "executor_only",
	}
}

func (s *Server) adapterCapabilities() map[string]any {
	return map[string]any{
		"stdio":                   true,
		"content_length_framing":  true,
		"json_line_framing":       true,
		"tool_call_arguments_key": true,
		"tool_call_input_key":     true,
		"structured_tool_errors":  true,
	}
}

func normalizeToolName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	for _, spec := range baseToolSpecs() {
		if name == spec.Friendly || name == spec.Canonical {
			return spec.Friendly, true
		}
	}
	return name, false
}

func (s *Server) toolErrorResult(err error) map[string]any {
	message := "invalid tool request"
	if err != nil {
		message = err.Error()
	}
	message = s.redactor.RedactText(message)
	return map[string]any{
		"content":     []map[string]string{{"type": "text", "text": message}},
		"isError":     true,
		"result_code": executor.ResultInvalidRequest,
	}
}

func unsupportedContentPlaceholder(kind, reason string) map[string]any {
	if strings.TrimSpace(kind) == "" {
		kind = "unknown"
	}
	if strings.TrimSpace(reason) == "" {
		reason = "unsupported"
	}
	return map[string]any{
		"type": "text",
		"text": "[ProdClaw unsupported MCP content block: kind=" + kind + " reason=" + reason + "]",
		"_meta": map[string]any{
			"prodclaw_unsupported_content_block": true,
			"blocked_kind":                       kind,
			"reason":                             reason,
		},
	}
}

func normalizeForwardedMCPResult(value any) any {
	root, ok := cloneJSONMap(value)
	if !ok {
		return value
	}
	rawContent, ok := root["content"]
	if !ok {
		return root
	}
	content, ok := rawContent.([]any)
	if !ok {
		root["content"] = []any{unsupportedContentPlaceholder("unknown", "content is not an array")}
		root["unsupported_content_blocks"] = []map[string]any{{"kind": "unknown", "reason": "content is not an array"}}
		return root
	}
	normalized := make([]any, 0, len(content))
	unsupported := make([]map[string]any, 0)
	for _, item := range content {
		block, ok := item.(map[string]any)
		if !ok {
			normalized = append(normalized, unsupportedContentPlaceholder("unknown", "content block is not an object"))
			unsupported = append(unsupported, map[string]any{"kind": "unknown", "reason": "content block is not an object"})
			continue
		}
		kind, _ := block["type"].(string)
		if kind == "text" {
			if _, ok := block["text"].(string); ok {
				normalized = append(normalized, block)
				continue
			}
			normalized = append(normalized, unsupportedContentPlaceholder("text", "text field is missing or not a string"))
			unsupported = append(unsupported, map[string]any{"kind": "text", "reason": "text field is missing or not a string"})
			continue
		}
		normalized = append(normalized, unsupportedContentPlaceholder(kind, "non-text MCP content is not forwarded to CI agents"))
		unsupported = append(unsupported, map[string]any{"kind": firstNonEmptyString(kind, "unknown"), "reason": "non-text MCP content is not forwarded to CI agents"})
	}
	root["content"] = normalized
	if len(unsupported) > 0 {
		root["unsupported_content_blocks"] = unsupported
	}
	return root
}

func cloneJSONMap(value any) (map[string]any, bool) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, false
	}
	return root, true
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func validateJSONObject(raw json.RawMessage, field string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("%s must be a JSON object", field)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var object map[string]json.RawMessage
	if err := dec.Decode(&object); err != nil {
		return fmt.Errorf("%s must be a valid JSON object: %w", field, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("%s must contain one JSON object", field)
	}
	return nil
}

func (s *Server) callTool(ctx context.Context, name string, args json.RawMessage) (any, error) {
	name, ok := normalizeToolName(name)
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", s.redactor.RedactText(name))
	}
	switch name {
	case "capabilities":
		data, err := json.MarshalIndent(s.capabilitySummary(), "", "  ")
		if err != nil {
			return nil, err
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": s.redactor.RedactText(string(data))}}, "isError": false, "result_code": executor.ResultSuccess}, nil
	case "read_file":
		return s.readFile(ctx, args)
	case "write_file":
		return s.writeFile(ctx, args)
	case "apply_patch":
		return s.applyPatch(ctx, args)
	case "run_command":
		return s.runCommand(ctx, args)
	case "http_request":
		return s.httpRequest(ctx, args)
	case "call_tool":
		return s.callToolForward(ctx, args)
	case "write_artifact":
		return s.writeArtifact(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool %q", s.redactor.RedactText(name))
	}
}

func (s *Server) readFile(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Path string `json:"path"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	abs, rel, err := s.workspacePath(input.Path)
	if err != nil {
		return nil, err
	}
	auth, err := s.authorize("read_file", "fs.read", fileResource(rel), map[string]any{"resource": rel})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	return s.textResult(auth, string(data), executor.ResultSuccess, false, false, 0, 0), nil
}

func (s *Server) writeFile(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	abs, rel, err := s.workspacePath(input.Path)
	if err != nil {
		return nil, err
	}
	auth, err := s.authorize("write_file", "fs.write", fileResource(rel), map[string]any{"resource": rel, "bytes": len(input.Content)})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := os.WriteFile(abs, []byte(input.Content), 0o644); err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	return s.textResult(auth, "ALLOW fs.write wrote "+rel, executor.ResultSuccess, false, false, 0, 0), nil
}

func (s *Server) applyPatch(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Patch string `json:"patch"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(input.Patch))
	auth, err := s.authorize("apply_patch", "repo.apply_patch", "repo://local/workspace", map[string]any{"patch_sha256": hex.EncodeToString(sum[:])})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	cmd := exec.CommandContext(execCtx, "git", "apply", "--whitespace=nowarn", "-")
	cmd.Dir = s.workspace
	cmd.Stdin = strings.NewReader(input.Patch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return s.failureResult(auth, fmt.Errorf("git apply failed: %w: %s", err, string(out))), nil
	}
	return s.textResult(auth, "ALLOW repo.apply_patch applied patch", executor.ResultSuccess, false, false, 0, 0), nil
}

func (s *Server) runCommand(ctx context.Context, args json.RawMessage) (any, error) {
	var input commandRequest
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	if len(input.Argv) == 0 {
		return nil, errors.New("argv is required")
	}
	cwd := s.workspace
	policyCWD := ""
	if strings.TrimSpace(input.CWD) != "" {
		abs, rel, err := s.workspacePath(input.CWD)
		if err != nil {
			return nil, err
		}
		cwd = abs
		policyCWD = rel
	}
	if input.StdinMode == "" {
		input.StdinMode = "none"
	}
	if input.StdinMode != "none" && input.StdinMode != "empty" {
		return nil, errors.New("stdin_mode must be none or empty")
	}
	if input.OutputMaxBytes < 0 || input.OutputMaxLines < 0 {
		return nil, errors.New("output caps must be >= 0")
	}
	auth, err := s.authorize("run_command", "process.exec", "file://workspace/", map[string]any{
		"argv":               input.Argv,
		"cwd":                policyCWD,
		"env_allowlist_keys": input.EnvAllowlistKeys,
		"stdin_mode":         input.StdinMode,
		"shell_mode":         input.ShellMode,
		"output_max_bytes":   input.OutputMaxBytes,
		"output_max_lines":   input.OutputMaxLines,
	})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	input.CWD = cwd
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	result := s.commandExec(execCtx, s.workspace, input)
	if err := execCtx.Err(); err != nil {
		return s.failureJSONResult(auth, result, err, input.OutputMaxBytes, input.OutputMaxLines), nil
	}
	if result.Error != "" {
		return s.jsonResult(auth, result, executor.ResultExecutionFailed, false, true, input.OutputMaxBytes, input.OutputMaxLines), nil
	}
	return s.jsonResult(auth, result, executor.ResultSuccess, false, false, input.OutputMaxBytes, input.OutputMaxLines), nil
}

func (s *Server) httpRequest(ctx context.Context, args json.RawMessage) (any, error) {
	var input httpRequestInput
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	if err := validateHTTPInput(input); err != nil {
		return nil, err
	}
	resource, actualURL, err := normalize.NormalizeHTTPRequestTarget(input.URL)
	if err != nil {
		return nil, err
	}
	auth, err := s.authorize("http_request", "net.http_request", resource, map[string]any{
		"method":             input.Method,
		"headers":            input.Headers,
		"body":               input.Body,
		"credential_env_key": input.CredentialEnvKey,
		"credential_header":  input.CredentialHeader,
		"credential_scope":   credentialScopeForEnvKey(input.CredentialEnvKey),
		"output_max_bytes":   input.OutputMaxBytes,
		"output_max_lines":   input.OutputMaxLines,
	})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	params, err := normalizedHTTPParams(auth.normalized.Params)
	if err != nil {
		return nil, err
	}
	if header, value, err := materializeHTTPCredential(input, os.LookupEnv); err != nil {
		return s.failureResult(auth, err), nil
	} else if header != "" {
		if params.Headers == nil {
			params.Headers = map[string]string{}
		}
		params.Headers[header] = value
	}
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	result, err := s.httpRunner.DoWithPolicy(
		execCtx,
		actualURL,
		executor.HTTPParams{Method: params.Method, Body: params.Body, Header: params.Headers},
		redirectPolicyFromObligations(auth.decision.Obligations),
		executor.HTTPRequestLimit(auth.decision.Obligations),
		executor.HTTPResponseLimit(auth.decision.Obligations, params.OutputMaxBytes),
	)
	if err != nil {
		return s.failureResult(auth, err), nil
	}
	return s.jsonResultWithOutcome(
		auth,
		map[string]any{"status": result.StatusCode, "body": result.Body},
		executor.Outcome{
			ResultCode:        executor.ResultSuccess,
			HTTPStatusCode:    result.StatusCode,
			HTTPFinalResource: result.FinalResource,
			HTTPRedirectHops:  result.RedirectHops,
		},
		false,
		params.OutputMaxBytes,
		params.OutputMaxLines,
	), nil
}

func (s *Server) callToolForward(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Server    string          `json:"server"`
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Server) == "" || strings.TrimSpace(input.Tool) == "" {
		return nil, errors.New("server and tool are required")
	}
	if len(bytes.TrimSpace(input.Arguments)) == 0 {
		input.Arguments = json.RawMessage(`{}`)
	}
	if err := validateJSONObject(input.Arguments, "arguments"); err != nil {
		return nil, err
	}
	canonicalArgs, err := canonicaljson.Canonicalize(input.Arguments)
	if err != nil {
		return nil, fmt.Errorf("canonicalize tool arguments: %w", err)
	}
	var argumentValue any
	if err := json.Unmarshal(canonicalArgs, &argumentValue); err != nil {
		return nil, fmt.Errorf("decode tool arguments: %w", err)
	}
	auth, err := s.authorize("call_tool", "mcp.call", "mcp://"+input.Server+"/"+input.Tool, map[string]any{
		"upstream_server":     input.Server,
		"upstream_tool":       input.Tool,
		"tool_arguments":      argumentValue,
		"tool_arguments_hash": canonicaljson.HashSHA256(canonicalArgs),
	})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	if s.forwardTool == nil {
		return s.unsupportedResult(auth, "mcp forwarding is not configured"), nil
	}
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	result, err := s.forwardTool(execCtx, input.Server, input.Tool, canonicalArgs)
	if err != nil {
		return s.failureResult(auth, err), nil
	}
	return s.jsonResult(auth, normalizeForwardedMCPResult(result), executor.ResultSuccess, false, false, 0, 0), nil
}

func (s *Server) writeArtifact(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	abs, rel, err := s.artifactPath(input.Path)
	if err != nil {
		return nil, err
	}
	auth, err := s.authorize("write_artifact", "artifact.write", artifactResource(rel), map[string]any{"path": rel, "bytes": len(input.Content)})
	if err != nil {
		return nil, err
	}
	if auth.decision.Decision != policy.DecisionAllow {
		return s.deniedResult(auth), nil
	}
	execCtx, cancel := executor.WithTimeout(ctx, auth.decision.Obligations)
	defer cancel()
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return s.failureResult(auth, err), nil
	}
	sanitizedContent, summary := executor.SanitizeOutputForLocation(s.redactor, input.Content, auth.decision.Obligations, 0, 0, "artifact.write")
	outcome := executor.Outcome{
		ResultCode:       executor.ResultSuccess,
		RedactionSummary: summary,
		ArtifactBytes:    len([]byte(sanitizedContent)),
	}
	if summary.Denied {
		outcome.ResultCode = executor.ResultReturnPathDenied
		outcome.ArtifactBytes = 0
		return s.textResultWithOutcome(auth, "DENY artifact.write return-path scanner findings blocked content", outcome, true, 0, 0), nil
	}
	if err := os.WriteFile(abs, []byte(sanitizedContent), 0o600); err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	return s.textResultWithOutcome(auth, "ALLOW artifact.write wrote "+rel, outcome, false, 0, 0), nil
}

func decodeArgs(args json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid tool arguments: trailing data")
	}
	return nil
}

func (s *Server) authorize(tool, actionType, resource string, params map[string]any) (authorizedAction, error) {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return authorizedAction{}, err
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      fmt.Sprintf("%s-%d", tool, time.Now().UnixNano()),
		ActionType:    actionType,
		Resource:      resource,
		Params:        paramBytes,
		TraceID:       "prodclaw-mcp",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, s.id)
	if err != nil {
		return authorizedAction{}, err
	}
	normalized, err := normalize.Action(act)
	if err != nil {
		return authorizedAction{}, err
	}
	explanation := policy.NewEngine(s.bundle).Explain(normalized)
	decision := explanation.Decision
	fingerprint, err := normalize.Fingerprint(normalized, decision.PolicyBundleHash)
	if err != nil {
		return authorizedAction{}, err
	}
	return authorizedAction{
		tool:        tool,
		actionType:  actionType,
		normalized:  normalized,
		decision:    decision,
		explanation: explanation,
		fingerprint: fingerprint,
	}, nil
}

func (s *Server) recordAudit(auth authorizedAction, outcome executor.Outcome) {
	_ = s.audit(audit.Event{
		SchemaVersion:      audit.SchemaVersionV1,
		Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
		ActionID:           auth.normalized.ActionID,
		TraceID:            auth.normalized.TraceID,
		Tool:               auth.tool,
		ActionType:         auth.actionType,
		Resource:           auth.normalized.Resource,
		ParamsHash:         auth.normalized.ParamsHash,
		Principal:          auth.normalized.Principal,
		Agent:              auth.normalized.Agent,
		Environment:        auth.normalized.Environment,
		CIIdentity:         s.id.CI,
		CredentialExposure: s.id.CredentialExposure,
		AssuranceLevel:     s.assuranceLevel,
		MediationCoverage:  s.mediationCoverage,
		ActionFingerprint:  auth.fingerprint,
		Decision:           auth.decision.Decision,
		ReasonCode:         auth.decision.ReasonCode,
		MatchedRuleIDs:     auth.decision.MatchedRuleIDs,
		PolicyBundleHash:   auth.decision.PolicyBundleHash,
		ResultCode:         outcome.ResultCode,
		Retryable:          outcome.Retryable,
		RedactionSummary:   outcome.RedactionSummary,
		ReturnedBytes:      outcome.ReturnedBytes,
		ArtifactBytes:      outcome.ArtifactBytes,
		ExecCondition:      auth.explanation.ExecAuthorization.ConditionClass,
		HTTPStatusCode:     outcome.HTTPStatusCode,
		HTTPFinalResource:  outcome.HTTPFinalResource,
		HTTPRedirectHops:   outcome.HTTPRedirectHops,
	})
}

func (s *Server) audit(event audit.Event) error {
	if strings.TrimSpace(s.auditPath) == "" {
		return nil
	}
	event = audit.RedactEvent(event, s.redactor)
	if err := audit.ValidateEventSchema(event); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.auditPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	return enc.Encode(event)
}

func (s *Server) workspacePath(input string) (string, string, error) {
	cleanInput := filepath.Clean(strings.TrimSpace(input))
	if cleanInput == "." || cleanInput == string(filepath.Separator) {
		return s.workspace, "", nil
	}
	if filepath.IsAbs(cleanInput) {
		rel, err := filepath.Rel(s.workspace, cleanInput)
		if err != nil {
			return "", "", err
		}
		if rel == "." {
			return s.workspace, "", nil
		}
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", "", errors.New("path escapes workspace")
		}
		if err := ensureNoSymlinkEscape(s.workspace, s.workspaceReal, cleanInput, "path escapes workspace"); err != nil {
			return "", "", err
		}
		return cleanInput, filepath.ToSlash(rel), nil
	}
	abs := filepath.Join(s.workspace, cleanInput)
	rel, err := filepath.Rel(s.workspace, abs)
	if err != nil {
		return "", "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("path escapes workspace")
	}
	if err := ensureNoSymlinkEscape(s.workspace, s.workspaceReal, abs, "path escapes workspace"); err != nil {
		return "", "", err
	}
	return abs, filepath.ToSlash(rel), nil
}

func (s *Server) artifactPath(input string) (string, string, error) {
	cleanInput := filepath.Clean(strings.TrimSpace(input))
	if cleanInput == "." || cleanInput == string(filepath.Separator) {
		return "", "", errors.New("artifact path is required")
	}
	if filepath.IsAbs(cleanInput) {
		return "", "", errors.New("absolute artifact paths are not allowed")
	}
	abs := filepath.Join(s.artifactDir, cleanInput)
	rel, err := filepath.Rel(s.artifactDir, abs)
	if err != nil {
		return "", "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("artifact path escapes artifact dir")
	}
	if err := ensureNoSymlinkEscape(s.artifactDir, s.artifactDirReal, abs, "artifact path escapes artifact dir"); err != nil {
		return "", "", err
	}
	return abs, filepath.ToSlash(rel), nil
}

func realBasePath(abs string) string {
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(realPath)
}

func ensureNoSymlinkEscape(logicalBase, realBase, abs, escapeMessage string) error {
	if realPath, err := filepath.EvalSymlinks(abs); err == nil {
		return ensureWithinRealBase(realBase, realPath, escapeMessage)
	} else if !os.IsNotExist(err) {
		return err
	}

	parent := filepath.Dir(abs)
	for {
		if _, err := os.Lstat(parent); err == nil {
			rel, relErr := filepath.Rel(logicalBase, parent)
			if relErr != nil {
				return relErr
			}
			if rel == "." || (!filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				realParent, err := filepath.EvalSymlinks(parent)
				if err != nil {
					return err
				}
				return ensureWithinRealBase(realBase, realParent, escapeMessage)
			}
			return nil
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
}

func ensureWithinRealBase(realBase, realPath, escapeMessage string) error {
	rel, err := filepath.Rel(realBase, realPath)
	if err != nil {
		return err
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New(escapeMessage)
	}
	return nil
}

func fileResource(rel string) string {
	if rel == "" {
		return "file://workspace/"
	}
	return "file://workspace/" + rel
}

func artifactResource(rel string) string {
	return "artifact://job/" + rel
}

func runCommand(ctx context.Context, _ string, req commandRequest) commandResult {
	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Dir = req.CWD
	cmd.Env = commandEnvironment(req.EnvAllowlistKeys)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		result.Error = err.Error()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = 1
		}
		return result
	}
	return result
}

func commandEnvironment(allowlist []string) []string {
	return identity.AgentEnvironment(os.LookupEnv, allowlist)
}

func (s *Server) deniedResult(auth authorizedAction) map[string]any {
	return s.textResult(
		auth,
		fmt.Sprintf("DENY %s by %s matched=%v hash=%s", auth.decision.ReasonCode, auth.decision.Decision, auth.decision.MatchedRuleIDs, auth.decision.PolicyBundleHash),
		executor.ResultDeniedPolicy,
		false,
		true,
		0,
		0,
	)
}

func (s *Server) unsupportedResult(auth authorizedAction, message string) map[string]any {
	return s.textResult(auth, message, executor.ResultUnsupported, false, true, 0, 0)
}

func (s *Server) failureResult(auth authorizedAction, err error) map[string]any {
	code, retryable := executor.ClassifyError(err)
	return s.textResult(auth, err.Error(), code, retryable, true, 0, 0)
}

func (s *Server) failureJSONResult(auth authorizedAction, value any, err error, requestedMaxBytes, requestedMaxLines int) map[string]any {
	code, retryable := executor.ClassifyError(err)
	return s.jsonResult(auth, value, code, retryable, true, requestedMaxBytes, requestedMaxLines)
}

func (s *Server) textResult(auth authorizedAction, text, resultCode string, retryable, isError bool, requestedMaxBytes, requestedMaxLines int) map[string]any {
	return s.textResultWithOutcome(auth, text, executor.Outcome{ResultCode: resultCode, Retryable: retryable}, isError, requestedMaxBytes, requestedMaxLines)
}

func (s *Server) textResultWithOutcome(auth authorizedAction, text string, outcome executor.Outcome, isError bool, requestedMaxBytes, requestedMaxLines int) map[string]any {
	sanitized, summary := executor.SanitizeOutputForLocation(s.redactor, text, auth.decision.Obligations, requestedMaxBytes, requestedMaxLines, "mcp.response")
	outcome.RedactionSummary = executor.MergeRedactionSummaries(outcome.RedactionSummary, summary)
	if summary.Denied {
		outcome.ResultCode = executor.ResultReturnPathDenied
		outcome.Retryable = false
		isError = true
	}
	outcome.ReturnedBytes = len([]byte(sanitized))
	s.recordAudit(auth, outcome)
	result := map[string]any{
		"result_code": outcome.ResultCode,
		"retryable":   outcome.Retryable,
		"redaction":   outcome.RedactionSummary,
		"content":     []map[string]any{{"type": "text", "text": sanitized}},
		"isError":     isError,
	}
	return result
}

func (s *Server) jsonResult(auth authorizedAction, value any, resultCode string, retryable, isError bool, requestedMaxBytes, requestedMaxLines int) map[string]any {
	return s.jsonResultWithOutcome(auth, value, executor.Outcome{ResultCode: resultCode, Retryable: retryable}, isError, requestedMaxBytes, requestedMaxLines)
}

func (s *Server) jsonResultWithOutcome(auth authorizedAction, value any, outcome executor.Outcome, isError bool, requestedMaxBytes, requestedMaxLines int) map[string]any {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return s.textResultWithOutcome(auth, fmt.Sprintf("%+v", value), outcome, isError, requestedMaxBytes, requestedMaxLines)
	}
	return s.textResultWithOutcome(auth, string(data), outcome, isError, requestedMaxBytes, requestedMaxLines)
}
