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
  "policy_inputs": {
    "baseline": {
      "path": "./policy/baseline.yaml",
      "sha256": "optional expected bundle hash"
    },
    "organization": {
      "path": "./policy/organization.yaml"
    },
    "repository": {
      "path": "./policy/repository.yaml"
    },
    "environment": {
      "path": "./policy/environment.yaml"
    },
    "job": {
      "path": "./policy/job.yaml"
    }
  },
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
- `PRODCLAW_POLICY_BASELINE`
- `PRODCLAW_POLICY_ORGANIZATION`
- `PRODCLAW_POLICY_REPOSITORY`
- `PRODCLAW_POLICY_ENVIRONMENT`
- `PRODCLAW_POLICY_JOB`
- `PRODCLAW_POLICY_BASELINE_SHA256`
- `PRODCLAW_POLICY_ORGANIZATION_SHA256`
- `PRODCLAW_POLICY_REPOSITORY_SHA256`
- `PRODCLAW_POLICY_ENVIRONMENT_SHA256`
- `PRODCLAW_POLICY_JOB_SHA256`
- `PRODCLAW_PROFILE`
- `PRODCLAW_WORKSPACE`
- `PRODCLAW_AUDIT`
- `PRODCLAW_PRINCIPAL`
- `PRODCLAW_AGENT`
- `PRODCLAW_ENVIRONMENT`
- `PRODCLAW_TASK`

Unknown config fields fail closed. Operational logs are JSON on `stderr` and redact token-like fields before emission.

Choose exactly one policy source:

- `profile` for a built-in embedded profile.
- `policy_bundle` for one customer-owned bundle.
- `policy_inputs` for explicit ordered layers. Layers are merged in fixed order: `baseline`, `organization`, `repository`, `environment`, `job`.

Layer hashes are optional but, when provided, must be valid SHA-256 values and must match the loaded source bundle. No built-in profile is silently added to a customer bundle or layered configuration.

Job-only runtime flags such as `--artifact-dir`, `--expect-action`, and budget limits are intentionally explicit CLI inputs rather than persisted config fields. They describe the current CI run, not the reusable policy source.
