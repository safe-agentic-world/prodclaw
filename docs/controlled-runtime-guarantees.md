# Controlled Runtime Guarantees

ProdClaw claims strong enforcement only when runtime evidence supports it. Local runs and CI jobs without egress, credential, workspace, artifact, and raw-MCP evidence are reported as `partial` or `none`.

## Doctor Modes

Container mode checks the controlled image path:

```bash
prodclaw doctor --mode container --workspace /workspace --artifact-dir /artifacts
```

CI mode adds supported CI identity validation on top of the container checks:

```bash
prodclaw doctor --mode ci --workspace /workspace --artifact-dir /artifacts
```

`doctor --mode ci` requires complete GitHub Actions or GitLab CI identity fields. It still requires container evidence because unmanaged hosted CI shells cannot prove exclusive mediation by themselves.

## Required Strong-Mode Evidence

Set these only when the control is actually active in the same runtime that launches the agent:

- `PRODCLAW_CONTAINER=true`: controlled container image/runtime evidence.
- `PRODCLAW_EGRESS_BLOCKED=true`: direct network egress is blocked or forced through a controlled proxy/firewall.
- `PRODCLAW_WORKSPACE_MUTATION_PROTECTED=true`: direct workspace writes are blocked except through ProdClaw.
- `PRODCLAW_WORKSPACE_MUTATION_DETECT=true`: unmediated workspace mutation is detected and fails the job.
- `PRODCLAW_RAW_MCP_SERVERS` unset: no raw upstream MCP servers are available beside ProdClaw for governed capabilities.

ProdClaw `job run` records mutation-detection evidence because it compares changed workspace files with successful `fs.write` and `repo.apply_patch` audit events.

## Coverage Matrix

| Surface | Strong evidence |
| --- | --- |
| Filesystem | Workspace is mounted and unmediated mutation is blocked or detected. MCP file paths reject traversal and symlink escape. |
| Process | Agent runs inside a controlled non-root runtime and governed commands route through ProdClaw MCP policy. |
| Network | Direct egress is blocked or forced through controlled paths; governed HTTP requests are allowlisted and audited. |
| Credentials | Sensitive CI and cloud credential variables are executor-only and absent from the agent environment. |
| Repo publishing | `process.exec` policy denies protected-branch pushes unless customer policy explicitly allows them. |
| Upstream tools | Raw upstream MCP servers are not present beside ProdClaw for governed capabilities. |
| Artifacts | Artifact directory is writable for audit, decisions, job metadata, and summaries. |

The same derived assurance level is recorded in `prodclaw policy explain`, MCP audit events, and `job run` metadata.

## Residual Risks

Controlled Docker runtime:

- Strong only after doctor passes in the same container options used for the job.
- `--network none` is strongest for dry-runs and policy checks. Real-agent jobs need a firewall or proxy for required model endpoints.
- Kernel/container escapes and host runner compromise are outside the ProdClaw MVP boundary.

Supported CI with container:

- Strong only when `doctor --mode ci` passes and CI identity is complete.
- GitHub-hosted runners do not provide a general outbound deny switch; use self-hosted runners, container firewalls, or a controlled proxy for strong egress claims.
- GitLab self-hosted runners can enforce egress with Docker network controls, host firewalls, or outbound proxies.

Unmanaged CI shell or local laptop:

- Best effort only.
- Native tools, direct egress, raw local credentials, and direct workspace writes may remain available beside ProdClaw.
- ProdClaw must not claim strong enforcement in this environment.
