# Configuration

ProdClaw is a CI-first CLI. It does not prompt for missing values.

`job run` and `mcp` load configuration with this precedence:

1. JSON config file from `--config`
2. Environment variables
3. Explicit flags

Supported JSON fields:

```json
{
  "policy_bundle": "./policy/prodclaw.yaml",
  "profile": "ci-strict",
  "workspace": ".",
  "audit": "artifacts/prodclaw/audit.jsonl",
  "principal": "system",
  "agent": "codex",
  "environment": "ci",
  "task": "task.md"
}
```

Supported environment variables:

- `PRODCLAW_POLICY_BUNDLE`
- `PRODCLAW_PROFILE`
- `PRODCLAW_WORKSPACE`
- `PRODCLAW_AUDIT`
- `PRODCLAW_PRINCIPAL`
- `PRODCLAW_AGENT`
- `PRODCLAW_ENVIRONMENT`
- `PRODCLAW_TASK`

Unknown config fields fail closed. Operational logs are JSON on `stderr` and redact token-like fields before emission.
