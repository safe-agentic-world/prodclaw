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
