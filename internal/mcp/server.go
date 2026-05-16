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
	"strings"
	"time"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	"github.com/safe-agentic-world/prodclaw/internal/audit"
	"github.com/safe-agentic-world/prodclaw/internal/canonicaljson"
	"github.com/safe-agentic-world/prodclaw/internal/executor"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/internal/redact"
)

type Server struct {
	bundle      policy.Bundle
	workspace   string
	artifactDir string
	auditPath   string
	id          identity.VerifiedIdentity
	httpRunner  *executor.HTTPRunner
	redactor    *redact.Redactor
	forwardTool ToolForwarder
	commandExec func(context.Context, string, commandRequest) commandResult
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
	artifactDir := strings.TrimSpace(opts.ArtifactDir)
	if artifactDir == "" {
		artifactDir = filepath.Join(absWorkspace, ".prodclaw", "artifacts")
	}
	absArtifactDir, err := filepath.Abs(artifactDir)
	if err != nil {
		return nil, err
	}
	redactor := opts.Redactor
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	return &Server{
		bundle:      opts.Bundle,
		workspace:   absWorkspace,
		artifactDir: absArtifactDir,
		auditPath:   opts.AuditPath,
		id:          id,
		redactor:    redactor,
		forwardTool: opts.ForwardTool,
		httpRunner:  executor.NewHTTPRunner(nil),
		commandExec: runCommand,
	}, nil
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		if len(req.ID) == 0 {
			_ = s.handleNotification(req)
			continue
		}
		resp := s.handleRequest(ctx, req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (s *Server) handleNotification(req rpcRequest) error {
	return nil
}

func (s *Server) handleRequest(ctx context.Context, req rpcRequest) rpcResponse {
	id := decodeID(req.ID)
	result, err := s.dispatch(ctx, req)
	if err != nil {
		return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32000, Message: err.Error()}}
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
		return map[string]any{"tools": toolDefinitions()}, nil
	case "tools/call":
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, fmt.Errorf("invalid tools/call params: %w", err)
		}
		return s.callTool(ctx, params.Name, params.Arguments)
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

func toolDefinitions() []map[string]any {
	return []map[string]any{
		tool("read_file", "Read a workspace file through ProdClaw policy.", map[string]any{
			"path": map[string]any{"type": "string"},
		}, []string{"path"}),
		tool("write_file", "Write a workspace file through ProdClaw policy.", map[string]any{
			"path":    map[string]any{"type": "string"},
			"content": map[string]any{"type": "string"},
		}, []string{"path", "content"}),
		tool("apply_patch", "Apply a unified diff patch through ProdClaw policy.", map[string]any{
			"patch": map[string]any{"type": "string"},
		}, []string{"patch"}),
		tool("run_command", "Run a command through ProdClaw process.exec policy.", map[string]any{
			"argv":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"cwd":                map[string]any{"type": "string"},
			"env_allowlist_keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"stdin_mode":         map[string]any{"type": "string"},
			"shell_mode":         map[string]any{"type": "boolean"},
			"output_max_bytes":   map[string]any{"type": "integer"},
			"output_max_lines":   map[string]any{"type": "integer"},
		}, []string{"argv"}),
		tool("http_request", "Send an HTTP request through ProdClaw net.http_request policy.", map[string]any{
			"url":              map[string]any{"type": "string"},
			"method":           map[string]any{"type": "string"},
			"headers":          map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"body":             map[string]any{"type": "string"},
			"output_max_bytes": map[string]any{"type": "integer"},
			"output_max_lines": map[string]any{"type": "integer"},
		}, []string{"url"}),
		tool("call_tool", "Forward an upstream tool call through ProdClaw mcp.call policy.", map[string]any{
			"server":    map[string]any{"type": "string"},
			"tool":      map[string]any{"type": "string"},
			"arguments": map[string]any{"type": "object"},
		}, []string{"server", "tool"}),
		tool("write_artifact", "Write a job artifact through ProdClaw artifact.write policy.", map[string]any{
			"path":    map[string]any{"type": "string"},
			"content": map[string]any{"type": "string"},
		}, []string{"path", "content"}),
	}
}

func tool(name, description string, properties map[string]any, required []string) map[string]any {
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

func (s *Server) callTool(ctx context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
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
		return nil, fmt.Errorf("unknown tool %q", name)
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
	if strings.TrimSpace(input.CWD) != "" {
		abs, _, err := s.workspacePath(input.CWD)
		if err != nil {
			return nil, err
		}
		cwd = abs
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
		"cwd":                input.CWD,
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
		"method":           input.Method,
		"headers":          input.Headers,
		"body":             input.Body,
		"output_max_bytes": input.OutputMaxBytes,
		"output_max_lines": input.OutputMaxLines,
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
	return s.jsonResult(auth, result, executor.ResultSuccess, false, false, 0, 0), nil
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
	if err := os.WriteFile(abs, []byte(input.Content), 0o600); err != nil {
		return s.failureResult(auth, err), nil
	}
	if err := execCtx.Err(); err != nil {
		return s.failureResult(auth, err), nil
	}
	return s.textResult(auth, "ALLOW artifact.write wrote "+rel, executor.ResultSuccess, false, false, 0, 0), nil
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
		SchemaVersion:     audit.SchemaVersionV1,
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		ActionID:          auth.normalized.ActionID,
		TraceID:           auth.normalized.TraceID,
		Tool:              auth.tool,
		ActionType:        auth.actionType,
		Resource:          auth.normalized.Resource,
		ParamsHash:        auth.normalized.ParamsHash,
		Principal:         auth.normalized.Principal,
		Agent:             auth.normalized.Agent,
		Environment:       auth.normalized.Environment,
		ActionFingerprint: auth.fingerprint,
		Decision:          auth.decision.Decision,
		ReasonCode:        auth.decision.ReasonCode,
		MatchedRuleIDs:    auth.decision.MatchedRuleIDs,
		PolicyBundleHash:  auth.decision.PolicyBundleHash,
		ResultCode:        outcome.ResultCode,
		Retryable:         outcome.Retryable,
		RedactionSummary:  outcome.RedactionSummary,
		ExecCondition:     auth.explanation.ExecAuthorization.ConditionClass,
		HTTPStatusCode:    outcome.HTTPStatusCode,
		HTTPFinalResource: outcome.HTTPFinalResource,
		HTTPRedirectHops:  outcome.HTTPRedirectHops,
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
		return "", "", errors.New("absolute paths are not allowed")
	}
	abs := filepath.Join(s.workspace, cleanInput)
	rel, err := filepath.Rel(s.workspace, abs)
	if err != nil {
		return "", "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("path escapes workspace")
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
	return abs, filepath.ToSlash(rel), nil
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
	keys := map[string]struct{}{}
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG"} {
		keys[key] = struct{}{}
	}
	for _, key := range allowlist {
		key = strings.TrimSpace(key)
		if key != "" {
			keys[key] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	env := make([]string, 0, len(ordered))
	for _, key := range ordered {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
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
	sanitized, summary := executor.SanitizeOutput(s.redactor, text, auth.decision.Obligations, requestedMaxBytes, requestedMaxLines)
	outcome.RedactionSummary = summary
	s.recordAudit(auth, outcome)
	result := map[string]any{
		"result_code": outcome.ResultCode,
		"retryable":   outcome.Retryable,
		"redaction":   summary,
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
