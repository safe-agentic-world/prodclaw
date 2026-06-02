# ProdClaw CI Tasks

## One-Liner

ProdClaw is a policy-enforced execution boundary for AI coding agents in CI.

It lets teams run agents such as Codex and Claude Code against real repositories while ProdClaw decides, records, and constrains every governed side effect according to customer policy.

## MVP Goal

The first MVP is:

```text
CI pipeline
  -> ProdClaw job run --agent codex|claude
  -> ProdClaw launches the agent with only ProdClaw-governed tools
  -> every governed file, command, network, and upstream tool action becomes a ProdClaw Action
  -> customer policy returns ALLOW or DENY
  -> ProdClaw executes allowed actions, blocks denied actions, and writes audit artifacts
```

ProdClaw should ship as:

- a CLI that can be installed in CI runners
- a raw CLI path that people can test quickly before adopting a controlled runtime
- default policy profiles for users who do not provide a custom policy
- later, an official Docker image that provides the controlled runtime path

## Why ProdClaw Is Separate From Nomos

ProdClaw exists because the CI product needs a smaller, sharper execution boundary than Nomos.

Nomos remains the R&D and broad control-plane repo. It has useful code, but it also carries local developer UX, approvals, operator UI, gateway features, and compatibility layers that made the CI story feel overbuilt.

ProdClaw must stay CI-first:

- no operator UI in MVP
- no human approval queue in MVP
- no broad MCP gateway compatibility matrix in MVP
- no local-laptop strong-enforcement claims
- no model routing or replacement for Codex or Claude Code
- no generic daemon or multi-tenant control plane in MVP

Every milestone should answer:

- Does this make CI agent execution more deterministic, enforceable, or auditable?
- Can this be tested non-interactively in GitHub Actions or GitLab CI?
- Is this smaller than copying the corresponding Nomos subsystem?

If the answer is no, it belongs in future backlog or Nomos R&D, not ProdClaw MVP.

## Nomos Reuse Rule

Use relevant Nomos code snippets when they reduce risk or preserve lessons already learned, but do not port whole subsystems by default.

Good candidates to reuse selectively:

- action normalization and strict schema validation patterns
- deterministic policy evaluation and explain output patterns
- Codex and Claude MCP wiring argv/config snippets
- MCP protocol handling details that avoid client compatibility mistakes
- audit JSONL shapes and redaction lessons
- bypass-test fixtures and CI smoke-test patterns

Do not copy into ProdClaw MVP unless a milestone explicitly requires it:

- operator UI
- approval store and approval workflow
- upstream MCP gateway/fanout
- long-lived daemon/server modes
- local launcher UX not needed by CI
- broad config compatibility layers
- profile hash-pin rituals that create policy-edit friction

When using Nomos code, document the exact reason in the PR or commit:

- what was reused
- why it fits ProdClaw's CI-first scope
- what was intentionally left behind to prevent scope creep

## Nomos Reference Guidance

Nomos is a reference repo for implementation patterns, not a roadmap that ProdClaw should copy wholesale.

For every milestone below, check `../nomos` for reusable code, tests, fixtures, and docs patterns before implementing. Reuse only the smallest CI-relevant pieces that preserve ProdClaw's uniform agent contract.

Useful reference areas include:

- action normalization and strict schema validation
- deterministic policy evaluation and explain output
- CI identity, runtime assurance, and bypass-test fixtures
- MCP protocol and client compatibility details
- Codex and Claude MCP wiring snippets
- audit JSONL, replay, and artifact evidence patterns
- redaction and no-leak test fixtures
- release provenance and verification workflow patterns

Do not port Nomos subsystems that would expand MVP scope:

- approvals and operator UI
- hot reload and long-lived gateway operations
- multi-tenant control plane behavior
- broad upstream MCP gateway transports
- SDK and wrapper adoption layers
- local laptop UX beyond clear best-effort warnings
- profile hash-pin rituals that slow policy edits

## Milestone Fit Check

| Milestone | Why It Belongs In ProdClaw |
| --- | --- |
| M1-M4 | They define the smallest CI product surface: CLI, action model, deterministic policy, and default CI profiles. |
| M5-M7 | They execute governed file, command, network, upstream-tool, and artifact actions. |
| M8-M10 | They bind CI identity/credentials, prove the MCP contract, and make policy sources inspectable. |
| M11-M13 | They wire agents uniformly, run jobs deterministically, and protect returned output/artifacts. |
| M14-M16 | They provide controlled runtime, guarantee proof, and replayable evidence for CI review. |
| M17-M20 | They make raw CLI adoption/release concrete and define the first MVP release bar. |
| M21 | It adds official Docker image distribution and a host-side Docker runtime launcher after the raw CLI path is easy to try. |

## Product Contract

ProdClaw does not constrain agent reasoning. ProdClaw governs execution authority.

Agents may:

- reason
- plan
- inspect allowed context
- propose patches
- request command execution
- request network access
- request upstream tool calls

ProdClaw controls, when the action routes through ProdClaw:

- filesystem reads and writes
- patch application
- process execution
- network requests
- upstream MCP or tool calls
- credential use by executors
- output caps, timeouts, and resource limits
- audit records and job artifacts

## Uniform Agent Contract

ProdClaw behavior must not vary by underlying agent.

Codex, Claude Code, OpenClaw, and future agents are adapter implementations behind the same ProdClaw job contract. The adapter may differ only in how it wires MCP, passes prompts, captures final output, and discovers client version/capabilities.

The following must remain uniform across agents:

- policy evaluation
- action schema and normalization
- tool names and tool semantics exposed through ProdClaw MCP
- audit event schema
- artifact layout
- exit codes
- job result semantics
- failure gates
- controlled-runtime checks
- profile and customer policy behavior

If an agent cannot support the uniform contract, ProdClaw must fail closed or mark that adapter capability as unsupported. ProdClaw must not add agent-specific policy exceptions, audit formats, or success criteria.

## Problems ProdClaw Must Solve

| Production problem | ProdClaw requirement |
| --- | --- |
| Agents can run native tools outside policy | CI/container runtime must route supported tools through ProdClaw and block or detect native bypass paths |
| Interactive approval prompts do not work in CI | MVP policy decisions are ALLOW or DENY only; no approval queue is required |
| Shell and CLI policies are brittle | `process.exec` policy must match normalized argv, working directory, environment, and command risk |
| Agents need credentials but must not hold secrets | Credentials are materialized only inside ProdClaw executors and never returned to the agent |
| Network egress is hard to control | Network actions must be allowlisted by policy and CI runtime must block direct egress where strong guarantees are claimed |
| MCP expands the attack surface | Upstream tools must be registered behind ProdClaw, surfaced by policy, and audited as governed actions |
| Audit formats differ across agents | ProdClaw emits a normalized audit stream independent of Codex, Claude Code, or future agents |
| Agent CLIs expose different flags and MCP wiring | ProdClaw adapters normalize those differences behind one job contract and one policy boundary |
| Local dev assumptions break CI | `ProdClaw job run` must work non-interactively with deterministic exit codes and artifacts; the official Docker path is a later controlled-runtime adoption step |
| Default setup is too hard | ProdClaw provides safe default CI profiles while supporting customer custom policies |

## Scope

### In Scope For MVP

- Codex and Claude Code CI execution through ProdClaw
- one uniform agent job contract across Codex, Claude Code, and future adapters
- CLI entrypoint: `ProdClaw job run`
- raw CLI entrypoint for CI
- customer policy bundles
- explicit policy layering for baseline, organization, repository, and job-specific policy inputs
- one or two built-in default CI profiles
- ALLOW or DENY decisions for every governed action
- deterministic policy evaluation
- verified CI identity and runtime context
- least-privilege credential materialization inside governed executors
- canonical action schema
- core actions:
  - `fs.read`
  - `fs.write`
  - `repo.apply_patch`
  - `process.exec`
  - `net.http_request`
  - `mcp.call`
  - `artifact.write`
- MCP server exposed to agents with natural tool names
- Codex launcher adapter
- Claude Code launcher adapter
- controlled-runtime checks for CI/container use
- audit JSONL and job metadata artifacts
- replayable decision evidence for CI review
- job budgets for tool calls, wall-clock time, output size, and network calls
- policy explain output for denied actions
- release checksums, SBOM, and provenance for raw CLI artifacts
- security regression tests for bypass attempts

### Out Of Scope For MVP

- operator UI
- human approval inbox or approval loop
- policy decision `REQUIRE_APPROVAL`
- replacing Codex or Claude Code with a model orchestration layer
- autonomous scheduling or daemon mode
- unmanaged laptop strong-enforcement claims
- broad support for every MCP client
- broad support for every upstream MCP server feature
- long-lived enterprise credentials in agent environments

### Future, Not MVP

- operator console
- human approvals
- multi-tenant gateway deployment
- signed remote policy distribution
- advanced workload identity integrations
- OpenClaw and additional agent adapters that implement the same uniform job contract
- full upstream MCP compatibility matrix

## Guarantee Levels

ProdClaw must be explicit about what it can and cannot enforce.

### Controlled CI Or Container Runtime

ProdClaw may claim strong enforcement only when all checks pass:

- agent is launched by `ProdClaw job run`
- agent receives ProdClaw-governed tools as the only supported side-effect path
- direct network egress is blocked except required platform endpoints and ProdClaw-controlled paths
- direct credential access is blocked
- workspace mutation is either routed through ProdClaw or the runtime can detect and fail unmediated mutation
- audit sink and artifact directory are writable
- policy bundle or default profile is loaded successfully

### Local Developer Runtime

Local runs are best-effort unless the user explicitly uses the controlled Docker runtime.

ProdClaw must warn when:

- native tools remain available beside ProdClaw tools
- direct egress is not known to be blocked
- credentials are present in the agent process environment
- workspace writes may occur outside ProdClaw

## Policy Model

The MVP has two policy outcomes:

- `ALLOW`
- `DENY`

Default behavior is deny.

Policy evaluation must be:

- deterministic
- side-effect free
- based on normalized action inputs
- based on verified identity and runtime environment
- independent of agent-supplied trust claims

Policy rules must support:

- action type matching
- resource pattern matching
- principal and agent identity matching
- environment matching, such as `ci`, `container`, `local`
- CI identity matching, such as repo, branch, commit, pipeline id, job id, actor, and event type
- normalized argv matching for `process.exec`
- HTTP method and host/path matching for `net.http_request`
- MCP server/tool matching for `mcp.call`
- credential scope matching for executor-only secret use
- job and per-tool budgets
- output caps
- timeouts
- sandbox profile selection
- redaction tags

## Default Profiles

ProdClaw should ship two built-in CI profiles.

### `ci-strict`

Purpose: safest default for CI.

Expected behavior:

- allow repository reads except well-known secret paths
- allow patch application only inside the workspace
- allow a small configured set of test/build commands
- deny unknown process execution
- deny direct deploy, push, destroy, delete, and credential commands
- deny unknown network egress
- deny reads of `.env`, SSH keys, cloud credentials, kubeconfig, and token files
- redact secrets from all outputs and artifacts
- no approvals

### `ci-standard`

Purpose: useful default for common CI agent jobs.

Expected behavior:

- include all `ci-strict` protections
- allow configured package manager commands
- allow network egress only to configured package registries and source hosts
- allow git status/diff/log style inspection
- deny git push unless customer policy explicitly allows it
- deny production infrastructure mutation unless customer policy explicitly allows it
- no approvals

If no customer policy is provided, `ProdClaw job run` should select `ci-strict` by default and print the selected profile and its hash.

## Action Schema

Every governed request becomes an Action.

Required fields:

- `schema_version`
- `action_id`
- `trace_id`
- `job_id`
- `action_type`
- `resource`
- `params`
- `principal`
- `agent`
- `environment`
- `workspace`
- `context`

Rules:

- reject unknown top-level fields
- validate size limits before policy evaluation
- canonicalize resources before policy evaluation
- compute `params_hash` from canonical JSON
- compute `action_fingerprint` from normalized action inputs
- include policy bundle identity in decisions and audit records

## Audit And Artifacts

Every job must write deterministic artifacts.

Required artifacts:

- `job.json`
- `policy.json`
- `audit.jsonl`
- `decisions.jsonl`
- `agent-launch.json`
- `changed-files.json`
- `job-result.json`
- `policy-inputs.json`
- `replay.json`
- `summary.txt`

Every action audit event must include:

- action id
- trace id
- job id
- action type
- normalized resource
- normalized parameters or redacted parameter hash
- principal
- agent
- environment
- policy bundle hash
- matched rule ids
- decision
- result code
- retryable flag
- redaction summary
- timestamp

Secrets must never be stored raw in artifacts.

## Exit Codes

`ProdClaw job run` must use deterministic exit codes.

| Code | Meaning |
| --- | --- |
| `0` | job completed successfully |
| `10` | policy denied one or more required actions |
| `20` | agent failed |
| `30` | invalid policy or config |
| `40` | runtime guarantee check failed |
| `50` | internal ProdClaw error |
| `60` | job budget exhausted |

## Milestones

## M0 - Consolidated Product Foundation

Goal: make this file the single current roadmap for the CI agent-runner MVP.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] Remove obsolete approval-loop and operator-UI MVP scope from roadmap language.
- [x] Keep future ideas in a separate future backlog section only.
- [x] Define the MVP around Codex and Claude Code in CI.
- [x] Define ALLOW/DENY-only policy semantics for MVP.
- [x] Define default profiles and customer policy behavior.
- [x] Define controlled-runtime versus local-runtime guarantees.
- [x] Keep this roadmap explicit that ProdClaw is separate from Nomos to avoid rebuilding Nomos under a new name.
- [x] Add and maintain the Nomos reuse rule for narrow snippets only.

Acceptance:

- [x] A new contributor can read `TASKS.md` and understand the MVP without reading historical milestones.
- [x] The roadmap directly maps to the production pain points listed above.
- [x] No MVP milestone depends on operator UI or approval workflow.
- [x] Every milestone can explain why it belongs in ProdClaw rather than Nomos R&D.

## M1 - Project Skeleton And CLI Surface

Goal: establish the executable product shape.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] `cmd/prodclaw` CLI entrypoint.
- [x] `prodclaw version`.
- [x] `prodclaw policy check`.
- [x] `prodclaw policy explain`.
- [x] `prodclaw mcp`.
- [x] `ProdClaw job run`.
- [x] config loading from file, flags, and environment.
- [x] fail-closed startup when policy/profile cannot be loaded.
- [x] structured logging with redaction applied.

Acceptance:

- [x] CLI builds from source.
- [x] CLI runs in a clean CI environment.
- [x] Missing policy/profile fails closed with a clear error unless default profile selection is explicitly enabled.
- [x] All commands have non-interactive behavior suitable for CI.
- [x] CLI help and docs repeatedly state the CI-first scope and avoid Nomos control-plane language.

## M2 - Canonical Action Model

Goal: make every governed side effect representable, stable, and auditable.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] JSON schema for Action v1.
- [x] JSON schema for Decision v1.
- [x] JSON schema for AuditEvent v1.
- [x] canonical JSON encoding and hashing.
- [x] resource URI normalization for files, repos, URLs, and MCP tools.
- [x] action fingerprint generation.
- [x] request size limits.
- [x] strict unknown-field rejection.

Acceptance:

- [x] Equivalent resources normalize to the same canonical form.
- [x] Traversal and invalid URI attempts are rejected before policy evaluation.
- [x] Same normalized action plus same identity plus same policy produces the same fingerprint on every OS.
- [x] Golden test vectors cover canonical JSON and hashing.

## M3 - Deterministic Policy Engine

Goal: customer policy decides every governed action.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] YAML policy bundle format.
- [x] JSON policy bundle format.
- [x] default-deny behavior.
- [x] ALLOW/DENY-only decision model for MVP.
- [x] deterministic rule precedence with deny winning.
- [x] stable rule ids.
- [x] policy bundle hash.
- [x] `prodclaw policy check --bundle <path> --action <path>`.
- [x] `prodclaw policy explain --bundle <path> --action <path>`.
- [x] explain output showing matched rules and denial reason.

Acceptance:

- [x] Same input produces same decision and explanation.
- [x] Invalid policy bundles fail closed.
- [x] Deny rules override allow rules.
- [x] Explain output is useful enough for a CI log.

## M4 - Default CI Profiles

Goal: let users try ProdClaw without writing policy on day one.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] built-in `ci-standard` profile.
- [x] built-in `ci-strict` profile.
- [x] profile list command.
- [x] profile show command.
- [x] runtime profile hash output from the embedded profile.
- [x] tests proving profile decisions for representative allow and deny actions.
- [x] docs explaining how to replace default profiles with customer policy.

Acceptance:

- [x] `ProdClaw job run` can use `ci-strict` without an external policy file.
- [x] default profiles deny secret paths.
- [x] default profiles deny unknown network egress.
- [x] default profiles deny destructive infrastructure commands.
- [x] default profiles do not contain approval-required decisions.
- [x] no checked-in profile hash pin file or manual hash-update ritual.

## M5 - Core Executors

Goal: execute allowed actions without giving authority to the agent.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] minimal `fs.read` executor through MCP.
- [x] minimal `fs.write` executor through MCP.
- [x] minimal `repo.apply_patch` executor through MCP.
- [x] minimal `process.exec` executor through MCP.
- [x] minimal `net.http_request` executor through MCP.
- [x] `mcp.call` executor or forwarding path.
- [x] `artifact.write` executor.
- [x] output caps for every executor.
- [x] timeout support for every executor.
- [x] redaction before returning output to the agent.
- [x] redaction before writing audit artifacts.

Acceptance:

- [x] Allowed actions execute and return capped output.
- [x] Denied `process.exec` actions do not execute.
- [x] Executor errors map to canonical result codes.
- [x] Secret corpus tests prove outputs and artifacts do not leak known secret patterns.

## M6 - Generic Exec Governance

Goal: make command execution policy practical for real CI jobs without tool-specific adapters.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] normalized command model with argv, cwd, environment allowlist, stdin mode, shell mode, and output caps.
- [x] policy matching on exact argv.
- [x] policy matching on argv prefixes.
- [x] policy matching on subcommands and flags.
- [x] policy denial for shell metacharacter risk when shell mode is not allowed.
- [x] policy denial for environment variable secret injection.
- [x] stable audit evidence for exec decisions.
- [x] built-in risk classes for commands such as push, deploy, destroy, delete, credential read, and package install.

Acceptance:

- [x] `git status` can be allowed while `git push origin main` is denied before execution.
- [x] `go test ./...` can be allowed while arbitrary `go env` secret exfiltration patterns are denied by policy.
- [x] `terraform plan` can be allowed while `terraform apply` and `terraform destroy` are denied by default profiles.
- [x] `kubectl get` can be allowed while `kubectl delete` is denied by default profiles.
- [x] Explain output identifies the exec condition that caused allow or deny.

## M7 - Network Governance

Goal: make agent network access explicit, allowlisted, and auditable.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] normalized HTTP request action.
- [x] method, host, path, and port matching.
- [x] deny-by-default network policy.
- [x] optional profile registry allowlists for common package hosts.
- [x] redirect policy with deterministic handling.
- [x] request and response size caps.
- [x] response redaction.
- [x] audit evidence for denied and allowed network calls.

Acceptance:

- [x] Unknown hosts are denied by default.
- [x] Allowed hosts are matched after URL normalization.
- [x] Redirects cannot escape policy allowlists.
- [x] Authorization headers and cookies are never returned raw to the agent or audit artifacts.

## M8 - CI Identity And Credential Boundary

Goal: bind every job and action to verified CI/runtime identity while keeping credentials out of the agent process.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] verified CI identity model for GitHub Actions and GitLab CI.
- [x] normalized identity fields for repo/project, branch/ref, commit SHA, pipeline/workflow id, job id, actor, event type, and workspace root.
- [x] agent identity derived from the selected adapter, never from agent-supplied text.
- [x] environment classification derived from runtime evidence: `ci`, `container`, or `local`.
- [x] fail-closed startup when required CI identity fields are missing in controlled CI mode.
- [x] agent environment allowlist with default secret scrubbing.
- [x] executor-only credential materialization for platform tokens and upstream service tokens.
- [x] audit metadata showing credential exposure summary without raw secret values.
- [x] policy matching over verified CI identity fields and credential scopes.

Acceptance:

- [x] A GitHub Actions job and GitLab CI job produce stable normalized identity records.
- [x] Agent prompts or tool arguments cannot override principal, agent, environment, branch, or job identity.
- [x] `GITHUB_TOKEN`, `GITLAB_TOKEN`, cloud credentials, SSH keys, and OpenAI/Anthropic keys are not exposed to governed tool results or audit artifacts.
- [x] A policy can deny `git push` to protected branches using verified ref/branch context.
- [x] A missing or ambiguous identity in controlled CI mode exits with invalid-config or runtime-guarantee failure, not best-effort success.

## M9 - MCP Contract And Capability Surface

Goal: make the governed tool path reliable for real CI agents before adding more launch complexity.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] stdio MCP server.
- [x] friendly tool aliases for `read_file`, `write_file`, `apply_patch`, `run_command`, and `http_request`.
- [x] `call_tool` alias for governed upstream tool calls.
- [x] canonical `ProdClaw.*` tool names for compatibility.
- [x] policy-aware `tools/list`.
- [x] machine-readable capability summary derived from policy, identity, runtime, and adapter capability.
- [x] principal-scoped capability visibility derived from verified CI identity, not agent-supplied identity.
- [x] no human text on MCP stdout.
- [x] readiness and errors on stderr only.
- [x] redaction for all MCP responses.
- [x] accept both MCP `arguments` and `input` tool-call payload shapes.
- [x] return structured `tools/call` results with `isError` instead of protocol-level failure for policy denials and invalid tool input.
- [x] support Content-Length framed stdio responses used by real MCP clients.
- [x] fixture-based contract tests for Codex MCP `tools/list` and `tools/call` request shapes.
- [x] fixture-based contract tests for Claude Code MCP `tools/list` and `tools/call` request shapes.
- [x] tests that tool advertisement is based on action capability, not brittle sample-resource probes.
- [x] schema validation for `mcp.call` upstream tool arguments before forwarding.
- [x] explicit unsupported-content-block behavior: preserve governed text blocks, and return structured errors/placeholders for unsupported non-text blocks rather than silently dropping them.

Acceptance:

- [x] Codex can list and call ProdClaw tools in the GitLab customer test job.
- [x] Claude Code can list and call ProdClaw tools.
- [x] Tool calls produce canonical actions and audit events.
- [x] Denied tool calls return structured denial without executing the action.
- [x] Contract tests run without OpenAI or Anthropic credentials.
- [x] A regression in Codex-compatible or Claude-compatible MCP request parsing fails CI.
- [x] Tool visibility cannot hide `run_command` or `http_request` only because a synthetic probe used a sample argv or host not allowed by policy.
- [x] Capability output is advisory but accurate; enforcement remains the policy engine.
- [x] Unsupported MCP content cannot disappear silently from the agent-facing response or audit trail.

## M10 - Policy Source, Composition, And Profile Provenance

Goal: make built-in profiles, customer policies, and effective policy state inspectable before they are used by the agent launch path.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] canonical built-in profiles live in one source directory.
- [x] embedded profiles are generated from canonical profiles for single-binary installs.
- [x] drift test verifies embedded profile bytes match canonical profile bytes.
- [x] `prodclaw profiles list` prints name, source, hash, and short summary for built-in profiles.
- [x] `prodclaw profiles show <name>` prints the embedded profile content or metadata.
- [x] `prodclaw profiles verify` validates embedded profiles and canonical source when available.
- [x] explicit ordered policy inputs for baseline, organization, repository, environment, and job-specific policy layers.
- [x] deterministic merge with deny-wins semantics and a stable effective policy identity.
- [x] fail-closed validation for missing bundles, duplicate rule ids, unknown fields, ambiguous merge config, and invalid hashes.
- [x] policy explain output shows matched rule source bundle and effective policy identity.
- [x] job metadata records selected profile name, policy inputs, source hashes, effective policy hash, and whether policy was built-in or customer-supplied.

Acceptance:

- [x] Installed `prodclaw` can answer "which ci-standard profile is in this binary?" without a source checkout.
- [x] Editing a built-in profile requires updating only the canonical profile and regenerated embed output, not a separate manual hash file.
- [x] CI fails if canonical and embedded built-in profiles drift.
- [x] Single customer policy remains the simplest path and does not inherit hidden default rules.
- [x] Multiple explicit policy layers produce a deterministic effective policy identity.
- [x] Missing or invalid policy layers fail closed before agent launch.

## M11 - Agent Adapters And Dry Run

Goal: generate truthful, inspectable agent launch plans behind one uniform ProdClaw contract before real job execution.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] shared launch-plan builder interface for supported agents.
- [x] shared adapter capability model covering MCP wiring method, final-output capture, version discovery, and unsupported features.
- [x] shared generated launch-plan schema used by every adapter.
- [x] Codex launch-plan builder.
- [x] Codex MCP configuration generation.
- [x] Claude Code launch-plan builder.
- [x] Claude Code MCP configuration generation.
- [x] dry-run output showing exact agent argv/config without requiring agent credentials.
- [x] runtime verification that the ProdClaw MCP config is attached where possible.
- [x] warning when native bypass paths may remain available.
- [x] job metadata recording agent version when available.
- [x] launch metadata recording the MCP wiring method truthfully.
- [x] generated config does not require mutation of user-global config unless explicitly requested.
- [x] generated config does not silently coexist with raw upstream tools for the same governed capabilities.
- [x] no adapter-specific policy behavior, audit schema, artifact layout, exit-code mapping, or success criteria.

Acceptance:

- [x] `prodclaw job run --agent codex --profile ci-strict --task-file <file> --dry-run` works without Codex credentials.
- [x] `prodclaw job run --agent claude --profile ci-strict --task-file <file> --dry-run` works without Anthropic credentials.
- [x] real Codex launch receives ProdClaw MCP configuration.
- [x] real Claude Code launch receives ProdClaw MCP configuration.
- [x] GitLab customer test wires Codex to ProdClaw MCP via Codex config overrides.
- [x] dry-run artifacts are deterministic except for explicit temp paths.
- [x] launch metadata never claims stronger mediation than the adapter can mechanically verify.
- [x] Codex and Claude dry-run outputs have the same ProdClaw job metadata fields, with differences limited to adapter argv/config details.
- [x] Unsupported adapter capabilities fail closed or are explicitly marked unsupported without changing the ProdClaw policy contract.

## M12 - Job Runner, Budgets, And CI Failure Gates

Goal: provide one main CI product surface and fail deterministically when any supported agent does not actually operate through ProdClaw.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] `prodclaw job run`.
- [x] `--agent codex|claude`.
- [x] `--task-file <path>`.
- [x] `--task-text <text>`.
- [x] legacy `--task <path>` alias for `--task-file`.
- [x] `--workspace <path>`.
- [x] `--policy-bundle <path>`.
- [x] `--profile <name>`.
- [x] `--artifact-dir <path>`.
- [x] `--dry-run`.
- [x] `--no-launch`.
- [x] mutually exclusive policy/profile validation.
- [x] task file and inline task text size limits.
- [x] deterministic exit codes.
- [x] changed-file summary.
- [x] agent final-message capture when the selected agent supports it.
- [x] job budgets for wall-clock time, MCP tool calls, `process.exec` calls, network calls, bytes returned, and artifact bytes.
- [x] per-tool timeouts and output caps enforced by executors.
- [x] adapter-injected CI contract telling the agent to use only ProdClaw MCP tools for file writes, patching, shell/git commands, HTTP, upstream tools, and artifacts.
- [x] preflight check that the generated agent launch plan contains only the intended ProdClaw MCP server for governed capabilities.
- [x] optional preflight probe that lists ProdClaw MCP tools before handing off to the agent when the client supports it non-interactively.
- [x] post-run audit gate requiring at least one expected governed action for jobs that declare expected actions.
- [x] post-run changed-file gate that maps changed workspace files to `fs.write` or `repo.apply_patch` audit events.
- [x] post-run denied-action gate that exits `10` when policy denial blocked a required action.
- [x] post-run budget gate that exits `60` when deterministic limits are exhausted.
- [x] post-run agent-failure gate that exits `20` for missing MCP tools, canceled MCP calls, agent refusal, invalid agent flags, or native-tool-only completion.
- [x] machine-readable `job-result.json` with exit reason, expected actions, observed actions, denied actions, changed files, budgets, and missing evidence.
- [x] shared job result evaluator used for Codex, Claude Code, and future adapters.

Acceptance:

- [x] CI can run a dry-run job without agent credentials.
- [x] CI can run a real job when the selected agent and credentials are present.
- [x] Policy denials produce exit code `10`.
- [x] Invalid config produces exit code `30`.
- [x] Runtime guarantee failure produces exit code `40`.
- [x] Budget exhaustion produces exit code `60`.
- [x] All required artifacts are written.
- [x] Any supported-agent job where `run_command` is canceled or unavailable fails instead of reporting success.
- [x] A job where the agent writes only a final message and produces no governed action audit fails when expected actions are configured.
- [x] A job that changes `README.md` without a matching governed write or patch audit event fails the mutation gate.
- [x] A successful job has enough audit and `job-result.json` evidence for CI reviewers to see what ProdClaw allowed and denied.
- [x] The same policy bundle and same requested action produce the same ProdClaw decision and audit shape regardless of selected agent.

## M13 - Return-Path Safety And No-Leak Harness

Goal: govern what comes back to the agent and what gets written to CI artifacts before broad real-agent examples depend on those artifacts.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] deterministic redaction pass for every executor response before returning it to the agent.
- [x] deterministic redaction pass for every audit and artifact write.
- [x] redaction corpus for tokens, JWTs, PEM blocks, cloud keys, cookies, auth headers, and common CI secrets.
- [x] no-leak harness that scans agent output, logs, audit, decisions, artifacts, and summaries for raw corpus secrets.
- [x] small versioned scanner rule pack for obvious prompt-injection, credential-exfiltration, and hidden-control-character patterns.
- [x] policy obligation or profile setting for return-path handling: `allow`, `fence`, `strip`, or `deny`.
- [x] scanner findings recorded by rule id, severity, location kind, and digest; never raw matched content.
- [x] size and line caps applied before agent delivery and before artifact persistence.
- [x] tests proving scanner failure fails closed.

Acceptance:

- [x] A command output containing a bearer token is redacted before agent response and audit persistence.
- [x] A command output containing known instruction-override text is fenced, stripped, or denied according to policy.
- [x] Scanner findings do not leak the matched secret or prompt-injection text.
- [x] Same output and same scanner rule pack produce identical findings across platforms.
- [x] Return-path protections apply to `fs.read`, `process.exec`, `net.http_request`, `mcp.call`, and `artifact.write` paths.
- [x] The no-leak harness fails CI if any known secret corpus value appears in emitted job artifacts.

## M14 - Docker Runtime

Goal: provide the easiest path to stronger CI guarantees.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] official Dockerfile.
- [x] image entrypoint for `prodclaw job run`.
- [x] image variant or documented install path for Codex.
- [x] image variant or documented install path for Claude Code.
- [x] non-root runtime user where possible.
- [x] workspace mount contract.
- [x] artifact mount contract.
- [x] egress-blocking guidance for GitHub Actions and GitLab CI.
- [x] environment variable allowlist for agent processes.
- [x] doctor checks for container hardening.

Acceptance:

- [x] Docker image can run `prodclaw version`.
- [x] Docker image can run `prodclaw job run --dry-run`.
- [x] Docker image can run policy checks against mounted policy files.
- [x] Container docs show how to prevent direct credential and network bypass.
- [x] Strong-enforcement claims are only printed when doctor checks pass.

## M15 - Controlled Runtime Proof And Guarantees Matrix

Goal: prove that CI/container mode blocks common bypasses and communicate exact enforcement guarantees.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] `prodclaw doctor --mode ci`.
- [x] mediation coverage matrix for filesystem, process, network, credentials, repo publishing, upstream tools, and artifacts.
- [x] derived assurance level recorded in explain output, audit, and job metadata.
- [x] check for direct network egress controls.
- [x] check for credential exposure in agent environment.
- [x] check for writable workspace bypass risk.
- [x] check for raw upstream MCP servers beside ProdClaw.
- [x] normalization bypass corpus for file paths, repo refs, URLs, redirect hops, and platform-specific path forms.
- [x] bypass fixture suite for path traversal, symlink escape, direct shell/network, direct credential read, direct workspace mutation, redirect escape, and protected-branch push.
- [x] CI workflow that runs bypass fixtures.
- [x] documentation of residual risks by environment.

Acceptance:

- [x] Direct `curl` to a denied host fails in strong-mode fixture.
- [x] Direct read of secret fixture path fails or is detected as a runtime guarantee failure.
- [x] Direct workspace mutation outside ProdClaw fails or is detected as a runtime guarantee failure.
- [x] Raw upstream MCP server overlap is detected before launch.
- [x] Audit artifacts show denied governed bypass attempts.
- [x] ProdClaw never claims strong enforcement unless controlled-runtime checks and evidence support it.

## M16 - Audit Evidence, Replay, And Incident Review

Goal: make CI artifacts sufficient to reconstruct decisions and review what happened without relying on agent prose.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [x] `job.json`.
- [x] `policy.json`.
- [x] `policy-inputs.json`.
- [x] `audit.jsonl`.
- [x] `decisions.jsonl`.
- [x] `agent-launch.json`.
- [x] `changed-files.json`.
- [x] `job-result.json`.
- [x] `replay.json`.
- [x] optional hash chain or artifact manifest for detecting accidental artifact corruption.
- [x] `prodclaw replay --artifact-dir <path>` or equivalent offline verifier.
- [x] policy explain output with why-denied, matched rule source, safe remediation hint, and obligations summary.
- [x] CI-friendly summary that highlights allowed actions, denied actions, budget use, changed files, and missing evidence.

Acceptance:

- [x] A reviewer can determine which policy inputs produced a decision without rebuilding the repo.
- [x] Offline replay verifies decisions from artifacts and fails when policy identity or action evidence is missing.
- [x] Denied actions explain the safe policy gap without exposing secrets or sensitive policy internals.
- [x] The artifact manifest or hash chain detects accidental artifact corruption.
- [x] Job success never depends only on the agent final message.

## M17 - CI Examples And Smoke Workflows

Goal: make adoption concrete for GitHub Actions and GitLab CI after the core job path exists.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [ ] GitHub Actions example using CLI install.
- [ ] GitLab CI example using CLI install.
- [x] GitLab CI customer test installs ProdClaw from source and runs policy preflight.
- [ ] example task file.
- [ ] example customer policy.
- [ ] example explicit policy-layering config.
- [ ] example artifacts upload.
- [ ] example policy denial job.
- [ ] example budget-exhaustion job.
- [x] example policy preflight covers denied protected-branch push.
- [x] example live Codex task verifies governed command and file-write audit.

Acceptance:

- [ ] Examples run in CI without operator interaction.
- [ ] Examples do not require model credentials for dry-run.
- [ ] Examples clearly separate dry-run, policy check, and real-agent execution.
- [ ] Examples upload ProdClaw artifacts.
- [x] GitLab CI customer test uploads ProdClaw audit artifacts.

## M18 - Documentation, Threat Model, And Security Mapping

Goal: explain the product and its security claims without historical roadmap ambiguity.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [ ] README quickstart for CI.
- [ ] README quickstart explains why ProdClaw is not Nomos and what scope was intentionally removed.
- [ ] customer policy guide.
- [ ] policy layering guide.
- [ ] default profile reference.
- [ ] action schema reference.
- [ ] audit artifact and replay reference.
- [ ] Codex integration guide.
- [ ] Claude Code integration guide.
- [ ] controlled-runtime guarantee guide.
- [ ] threat model.
- [ ] credential handling guide.
- [ ] troubleshooting guide.
- [ ] OWASP Agentic Top 10 mapping or equivalent security-control mapping for CI buyers.

Acceptance:

- [ ] A new user can run the dry-run path in under 10 minutes.
- [ ] Docs do not claim strong enforcement for unmanaged laptops.
- [ ] Docs state that MVP has no approval loop.
- [ ] Docs explain how to replace default profiles with customer policy.
- [ ] Docs include a "Reuse From Nomos Carefully" note with examples of acceptable snippets and rejected subsystems.
- [ ] Docs clearly separate runtime enforcement claims from release-artifact provenance claims.

## M19 - Release Distribution And Supply-Chain Provenance

Goal: ship ProdClaw like CI security infrastructure, not a local demo binary.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [ ] reproducible release workflow for Linux, macOS, and Windows binaries where practical.
- [ ] checksums for release archives and binaries.
- [ ] signed release artifacts or documented verification mechanism.
- [ ] SBOM for release binaries.
- [ ] build provenance/attestation showing source revision and workflow identity.
- [ ] vulnerability scan in release workflow.
- [ ] documented `go install github.com/safe-agentic-world/prodclaw/cmd/prodclaw@latest` path.
- [ ] future package-manager handoff notes for Homebrew/Scoop repos without blocking MVP.

Acceptance:

- [ ] Users can verify official release artifacts with documented steps.
- [ ] Each official release publishes checksums, SBOM, and provenance/attestation artifacts.
- [ ] Release automation fails if trust artifacts are missing.
- [ ] Installation docs avoid asking users to clone source for normal CI use.

## M20 - MVP Release Gate

Goal: define the minimum bar for the first release.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Required release checks:

- [ ] unit tests pass.
- [ ] policy golden tests pass.
- [ ] canonicalization golden tests pass.
- [ ] normalization bypass corpus tests pass.
- [ ] identity and credential-boundary tests pass.
- [ ] redaction corpus and no-leak harness pass.
- [ ] bypass fixture tests pass.
- [ ] MCP client contract tests pass.
- [ ] policy composition and profile provenance checks pass.
- [ ] Codex dry-run test passes.
- [ ] Claude Code dry-run test passes.
- [ ] Codex/Claude adapter parity tests pass for job metadata, exit codes, artifact layout, and policy decisions.
- [ ] job-runner failure-gate and budget tests pass.
- [ ] return-path safety tests pass.
- [ ] audit replay tests pass.
- [ ] GitHub Actions example validates.
- [ ] GitLab CI example validates.
- [ ] GitLab CI Codex-through-ProdClaw-MCP example validates.
- [ ] release provenance workflow validates.
- [ ] docs quickstart is tested from a clean environment.

MVP is releasable when:

- [ ] a user can run Codex through ProdClaw in CI using `ci-strict`.
- [ ] a user can run Claude Code through ProdClaw in CI using `ci-strict`.
- [ ] Codex and Claude Code runs expose the same ProdClaw behavior except for agent-specific wiring details.
- [ ] customer policy can allow and deny representative file, exec, network, and MCP actions.
- [ ] CI identity and credential exposure are controlled and auditable.
- [ ] every governed action has an audit event.
- [ ] denied actions do not execute.
- [ ] artifacts are sufficient for CI review, replay, and incident analysis.
- [ ] a job that cannot prove ProdClaw-governed actions occurred fails rather than passing on agent text alone.
- [ ] official release artifacts have checksums, SBOM, and provenance.
- [ ] no operator UI or approval workflow is required.

## M21 - Official Docker Distribution And Runtime Launcher

Goal: provide the controlled Docker adoption path after the raw CLI release is easy to test.

Nomos reference: check `../nomos` for reusable code, tests, or docs patterns; copy only the minimum CI-relevant pieces.

Deliverables:

- [ ] official container image build.
- [ ] official Codex-capable image or documented Codex install variant.
- [ ] official Claude Code-capable image or documented Claude install variant.
- [ ] container image tags that map to release versions and source revisions.
- [ ] SBOM for container image.
- [ ] build provenance/attestation for container image.
- [ ] vulnerability scan for container image.
- [ ] documented container install path.
- [ ] Docker quickstart.
- [ ] GitHub Actions example using Docker.
- [ ] GitLab CI example using Docker.
- [ ] host CLI runtime flag such as `prodclaw job run --runtime docker`.
- [ ] host CLI image selection flag such as `--image ghcr.io/safe-agentic-world/prodclaw-codex:<version>`.
- [ ] automatic workspace and artifact mounts for the host-side Docker launcher.

Acceptance:

- [ ] Users can run raw `prodclaw job run` without Docker for quick testing.
- [ ] Users can opt into Docker with a short command, not a long manual `docker run` invocation.
- [ ] `prodclaw job run --runtime docker --agent codex --task-file <path>` launches the official image with correct mounts.
- [ ] Docker dry-run test passes.
- [ ] controlled-runtime proof workflow passes for the official image.
- [ ] Docker examples validate in GitHub Actions and GitLab CI.
- [ ] Container image provenance is documented separately from runtime enforcement guarantees.
- [ ] Docker remains an optional stronger-runtime path and does not block the raw CLI release.

## Future Backlog

These items are useful, but must not block the MVP above.

- [ ] human approval workflow.
- [ ] operator UI.
- [ ] durable approval store.
- [ ] multi-tenant gateway.
- [ ] OpenClaw adapter implementing the same uniform agent contract.
- [ ] additional agent adapters implementing the same uniform agent contract.
- [ ] upstream MCP compatibility hardening beyond MVP tool calls.
- [ ] broad reference MCP server matrix beyond Codex and Claude Code client contracts.
- [ ] policy hot reload for long-running daemon deployments.
- [ ] operator telemetry dashboards and enterprise console.
- [ ] signed policy/profile bundles.
- [ ] OCI policy distribution.
- [ ] SPIFFE/SPIRE workload identity.
- [ ] Kubernetes reference deployment.
- [ ] remote audit sink integrations.
- [ ] organization-wide policy pack marketplace.
