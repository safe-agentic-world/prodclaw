# ProdClaw

ProdClaw is a CI-first execution boundary for AI coding agents.

It is built for teams that want Codex or Claude Code to work on real repositories in CI without handing the agent unrestricted shell, network, file, or credential access.

## What It Does

- Runs coding agents from CI jobs.
- Routes file, patch, shell, HTTP, and tool actions through policy.
- Uses deterministic `ALLOW` or `DENY` decisions for the MVP.
- Writes audit artifacts that are independent of the agent vendor.
- Keeps local developer UX and operator approvals out of the MVP.

## Current State

This repository is the clean CI-focused product track. The original `nomos` repository remains the R&D repo.

The first implementation target is a small, shippable loop:

```text
CI pipeline -> prodclaw job run -> agent MCP tools -> policy -> executor -> audit artifacts
```

## Build

```bash
go build ./cmd/prodclaw
go test ./...
```

## CI-First CLI

ProdClaw commands are non-interactive by design. `job run` and `mcp` accept strict JSON config files, environment variables, and flags with precedence `file < environment < flags`, so CI jobs can define defaults once and override them explicitly when needed.

```bash
prodclaw job run --config ./prodclaw.json --dry-run
```

Structured operational logs are written to `stderr` as JSON and redact token-like fields before emission.

## Install

For the MVP, install from source with Go:

```bash
go install github.com/safe-agentic-world/prodclaw/cmd/prodclaw@latest
```

Versioned binaries are published from GitHub tags. Create a tag like `v0.1.0` to build Linux, macOS, and Windows artifacts with SHA256 checksums.

## Try Policy Checks

```bash
go run ./cmd/prodclaw policy check --profile ci-standard --action examples/actions/git-status.json
go run ./cmd/prodclaw policy explain --profile ci-standard --action examples/actions/git-status.json
```

`check` gives the compact decision for CI gates. `explain` adds matched rule details so a failed pipeline can show exactly which policy rule caused the result.

## Inspect Profiles

```bash
go run ./cmd/prodclaw profiles list
go run ./cmd/prodclaw profiles show ci-standard
```

Profile hashes are computed from the profile embedded in the running binary. ProdClaw does not require a checked-in hash pin file for policy edits.

Use `ci-strict` by default or replace it with a customer-owned bundle once the job needs explicit organization policy:

```bash
prodclaw job run --agent codex --task task.md --dry-run
prodclaw job run --agent codex --task task.md --policy-bundle ./policy/prodclaw.yaml --dry-run
```

See `docs/default-profiles.md` for the default-profile contract and the replacement path.

## Run As An MCP Boundary

```bash
prodclaw mcp --profile ci-standard --workspace . --audit artifacts/prodclaw/audit.jsonl
```

The MCP server exposes governed `read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`, `call_tool`, and `write_artifact` tools. Every tool call is converted into a ProdClaw action, evaluated against policy, and recorded in the audit log with the final execution result.

Network actions are deny-by-default. HTTP requests normalize method, host, path, port, and header names before policy evaluation; redirects are disabled unless policy opts in with an explicit `net_allowlist`, and response bodies are capped and redacted before they reach the agent.
