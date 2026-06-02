# Job Runner

`prodclaw job run` is the main CI product surface. It prepares one isolated ProdClaw MCP config, launches a supported agent, and then evaluates the job from ProdClaw evidence rather than trusting the agent's final prose.

## Minimal Run

```bash
prodclaw job run \
  --agent codex \
  --profile ci-strict \
  --task-text 'First call ProdClaw run_command with argv ["git","status"], then say hi.'
```

Use `--dry-run` before adding agent credentials:

```bash
prodclaw job run \
  --agent claude \
  --profile ci-strict \
  --task-file task.md \
  --dry-run
```

Use exactly one task source:

- `--task-text <text>` for short inline tasks.
- `--task-file <path>` for checked-in or generated task files.
- `--task <path>` remains a legacy alias for `--task-file`.

`--workspace` defaults to the current directory. `--artifact-dir` defaults to `.prodclaw/job` inside the workspace.

## Policy Input

Choose exactly one policy source:

- `--profile <name>` for an embedded profile
- `--policy-bundle <path>` for one customer-owned bundle
- explicit layered policy flags for ordered customer bundles

Profile and bundle inputs are mutually exclusive. Invalid policy selection fails before launch.

## Deterministic Artifacts

Every prepared job writes:

- `job.json`
- `job-plan.json`
- `policy.json`
- `policy-inputs.json`
- `agent-launch.json`
- `mcp-config.json`
- `audit.jsonl`
- `decisions.jsonl`
- `changed-files.json`
- `job-result.json`
- `replay.json`
- `artifact-manifest.json`
- `summary.txt`
- `agent-artifacts/`

When an adapter supports final-output capture, ProdClaw also writes `agent-final-message.txt`.

`job-result.json` is the machine-readable verdict. It records expected actions, observed actions, denied actions, changed files, missing evidence, budget use, exit reason, and exit code.

`policy.json` and `policy-inputs.json` record the effective policy rules, policy source, source bundle hashes, and effective policy hash so a reviewer can reconstruct why a decision was made without rebuilding the repository.

`artifact-manifest.json` records file size and SHA-256 for each artifact. Verify a completed artifact directory offline with:

```bash
prodclaw replay --artifact-dir .prodclaw/job
```

Replay validates the manifest, policy identity, audit and decision consistency, replay counts, and that a successful real run has governed action evidence rather than only an agent final message.

## Failure Gates

Use `--expect-action <type>` when the job must prove that a governed action happened, for example:

```bash
prodclaw job run \
  --agent codex \
  --profile ci-standard \
  --task-file task.md \
  --expect-action process.exec \
  --expect-action fs.write
```

ProdClaw fails the job when:

- a policy denial appears in audit evidence
- an expected governed action is missing
- a changed workspace file lacks matching `fs.write` or `repo.apply_patch` evidence
- a configured budget is exhausted
- the agent reports canceled MCP calls, missing MCP tools, refusal, or other recognized failure text
- final-message capture is expected but missing

The runner uses one shared evaluator for Codex, Claude Code, and future adapters. Agent-specific code may change launch argv and output capture, but it must not change policy semantics, artifact layout, or success criteria.

## Budgets

Supported deterministic budget flags:

- `--max-wall-clock-ms`
- `--max-tool-calls`
- `--max-exec-calls`
- `--max-network-calls`
- `--max-returned-bytes`
- `--max-artifact-bytes`

Executor-level obligations still enforce per-tool timeouts and output caps. Job budgets add the aggregate CI verdict across the full run.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | success |
| `10` | policy denied one or more governed actions |
| `20` | agent failure or missing required evidence |
| `30` | invalid config or task input |
| `40` | runtime guarantee failure |
| `50` | internal ProdClaw error |
| `60` | job budget exhausted |

## Preflight

`--probe-tools` records the tools the generated ProdClaw MCP server advertises before launch. `--no-launch` materializes the same job artifacts and launch config without starting the agent.

The injected task preamble tells the selected agent to use only ProdClaw MCP tools for side effects and to stop on policy denial rather than bypassing the boundary.
