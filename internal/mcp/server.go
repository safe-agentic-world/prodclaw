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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/safe-agentic-world/prodclaw/internal/action"
	"github.com/safe-agentic-world/prodclaw/internal/identity"
	"github.com/safe-agentic-world/prodclaw/internal/normalize"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
)

type Server struct {
	bundle      policy.Bundle
	workspace   string
	auditPath   string
	id          identity.VerifiedIdentity
	httpClient  *http.Client
	commandExec func(context.Context, string, []string, string) commandResult
}

type Options struct {
	Bundle    policy.Bundle
	Workspace string
	AuditPath string
	Identity  identity.VerifiedIdentity
}

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

type auditEvent struct {
	Timestamp        string   `json:"timestamp"`
	Tool             string   `json:"tool"`
	ActionType       string   `json:"action_type"`
	Resource         string   `json:"resource"`
	Decision         string   `json:"decision"`
	ReasonCode       string   `json:"reason_code"`
	MatchedRuleIDs   []string `json:"matched_rule_ids"`
	PolicyBundleHash string   `json:"policy_bundle_hash"`
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
	return &Server{
		bundle:    opts.Bundle,
		workspace: absWorkspace,
		auditPath: opts.AuditPath,
		id:        id,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
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
			"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"cwd":  map[string]any{"type": "string"},
		}, []string{"argv"}),
		tool("http_request", "Send an HTTP request through ProdClaw net.http_request policy.", map[string]any{
			"url":     map[string]any{"type": "string"},
			"method":  map[string]any{"type": "string"},
			"headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"body":    map[string]any{"type": "string"},
		}, []string{"url"}),
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
		return s.readFile(args)
	case "write_file":
		return s.writeFile(args)
	case "apply_patch":
		return s.applyPatch(ctx, args)
	case "run_command":
		return s.runCommand(ctx, args)
	case "http_request":
		return s.httpRequest(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func (s *Server) readFile(args json.RawMessage) (any, error) {
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
	decision, err := s.authorize("read_file", "fs.read", fileResource(rel), map[string]any{"resource": rel})
	if err != nil {
		return nil, err
	}
	if decision.Decision != policy.DecisionAllow {
		return deniedResult(decision), nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return textResult(string(data)), nil
}

func (s *Server) writeFile(args json.RawMessage) (any, error) {
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
	decision, err := s.authorize("write_file", "fs.write", fileResource(rel), map[string]any{"resource": rel, "bytes": len(input.Content)})
	if err != nil {
		return nil, err
	}
	if decision.Decision != policy.DecisionAllow {
		return deniedResult(decision), nil
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(abs, []byte(input.Content), 0o644); err != nil {
		return nil, err
	}
	return textResult("ALLOW fs.write wrote " + rel), nil
}

func (s *Server) applyPatch(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Patch string `json:"patch"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(input.Patch))
	decision, err := s.authorize("apply_patch", "repo.apply_patch", "repo://local/workspace", map[string]any{"patch_sha256": hex.EncodeToString(sum[:])})
	if err != nil {
		return nil, err
	}
	if decision.Decision != policy.DecisionAllow {
		return deniedResult(decision), nil
	}
	cmd := exec.CommandContext(ctx, "git", "apply", "--whitespace=nowarn", "-")
	cmd.Dir = s.workspace
	cmd.Stdin = strings.NewReader(input.Patch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git apply failed: %w: %s", err, string(out))
	}
	return textResult("ALLOW repo.apply_patch applied patch"), nil
}

func (s *Server) runCommand(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		Argv []string `json:"argv"`
		CWD  string   `json:"cwd"`
	}
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
	decision, err := s.authorize("run_command", "process.exec", "file://workspace/", map[string]any{"argv": input.Argv, "cwd": input.CWD, "env_allowlist_keys": []string{}})
	if err != nil {
		return nil, err
	}
	if decision.Decision != policy.DecisionAllow {
		return deniedResult(decision), nil
	}
	result := s.commandExec(ctx, s.workspace, input.Argv, cwd)
	return jsonTextResult(result), nil
}

func (s *Server) httpRequest(ctx context.Context, args json.RawMessage) (any, error) {
	var input struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := decodeArgs(args, &input); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	resource := httpResource(input.URL)
	decision, err := s.authorize("http_request", "net.http_request", resource, map[string]any{"method": method, "headers": input.Headers})
	if err != nil {
		return nil, err
	}
	if decision.Decision != policy.DecisionAllow {
		return deniedResult(decision), nil
	}
	actualURL := input.URL
	if strings.HasPrefix(actualURL, "url://") {
		actualURL = "https://" + strings.TrimPrefix(actualURL, "url://")
	}
	req, err := http.NewRequestWithContext(ctx, method, actualURL, strings.NewReader(input.Body))
	if err != nil {
		return nil, err
	}
	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	return jsonTextResult(map[string]any{"status": resp.StatusCode, "body": string(body)}), nil
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

func (s *Server) authorize(tool, actionType, resource string, params map[string]any) (policy.Decision, error) {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return policy.Decision{}, err
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
		return policy.Decision{}, err
	}
	normalized, err := normalize.Action(act)
	if err != nil {
		return policy.Decision{}, err
	}
	decision := policy.NewEngine(s.bundle).Evaluate(normalized)
	_ = s.audit(auditEvent{
		Timestamp:        time.Now().UTC().Format(time.RFC3339Nano),
		Tool:             tool,
		ActionType:       actionType,
		Resource:         normalized.Resource,
		Decision:         decision.Decision,
		ReasonCode:       decision.ReasonCode,
		MatchedRuleIDs:   decision.MatchedRuleIDs,
		PolicyBundleHash: decision.PolicyBundleHash,
	})
	return decision, nil
}

func (s *Server) audit(event auditEvent) error {
	if strings.TrimSpace(s.auditPath) == "" {
		return nil
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

func fileResource(rel string) string {
	if rel == "" {
		return "file://workspace/"
	}
	return "file://workspace/" + rel
}

func httpResource(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "url://") {
		return raw
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	return "url://" + raw
}

func runCommand(ctx context.Context, workspace string, argv []string, cwd string) commandResult {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = cwd
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

func deniedResult(decision policy.Decision) map[string]any {
	return map[string]any{
		"isError": true,
		"content": []map[string]any{{
			"type": "text",
			"text": fmt.Sprintf("DENY %s by %s matched=%v hash=%s", decision.ReasonCode, decision.Decision, decision.MatchedRuleIDs, decision.PolicyBundleHash),
		}},
	}
}

func textResult(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

func jsonTextResult(value any) map[string]any {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return textResult(fmt.Sprintf("%+v", value))
	}
	return textResult(string(data))
}
