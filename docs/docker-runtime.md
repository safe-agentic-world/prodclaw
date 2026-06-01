# Docker Runtime

ProdClaw's Docker image is the recommended path for CI jobs that want stronger, inspectable runtime guarantees than a local laptop run.

The image still does not make strong enforcement claims by itself. Strong enforcement is claimed only when `prodclaw doctor --mode container` passes inside the same runtime that will launch the agent.

## Build The Image

```bash
docker build -t prodclaw:local .
```

The default image contains `prodclaw`, Git, Node.js, npm, CA certificates, and a non-root `prodclaw` user. It does not install Codex or Claude Code by default.

## Optional Agent Install Paths

Build a Codex image by installing the Codex npm package during the image build. Pin the version used by your CI job.

```bash
docker build -t prodclaw:codex \
  --build-arg INSTALL_CODEX=true \
  --build-arg CODEX_NPM_VERSION=latest \
  .
```

Build a Claude Code image the same way:

```bash
docker build -t prodclaw:claude \
  --build-arg INSTALL_CLAUDE=true \
  --build-arg CLAUDE_NPM_VERSION=latest \
  .
```

The package names are also configurable:

```bash
docker build -t prodclaw:agents \
  --build-arg INSTALL_CODEX=true \
  --build-arg CODEX_NPM_PACKAGE=@openai/codex \
  --build-arg CODEX_NPM_VERSION=latest \
  --build-arg INSTALL_CLAUDE=true \
  --build-arg CLAUDE_NPM_PACKAGE=@anthropic-ai/claude-code \
  --build-arg CLAUDE_NPM_VERSION=latest \
  .
```

## Entrypoint

The image entrypoint accepts normal ProdClaw commands:

```bash
docker run --rm prodclaw:local version
docker run --rm prodclaw:local profiles list
docker run --rm prodclaw:local doctor --mode container
```

When the first argument starts with `-`, the entrypoint defaults to `prodclaw job run` and injects the standard mounts:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$PWD/artifacts/prodclaw:/artifacts" \
  prodclaw:local \
  --agent codex \
  --task /workspace/task.md \
  --dry-run
```

The equivalent explicit command is:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$PWD/artifacts/prodclaw:/artifacts" \
  prodclaw:local \
  job run \
  --workspace /workspace \
  --artifact-dir /artifacts \
  --agent codex \
  --task /workspace/task.md \
  --dry-run
```

## Mount Contract

Workspace:

- Mount the checked-out repository at `/workspace`.
- The mounted directory must be readable by the container user.
- Jobs that apply patches or write files through ProdClaw need `/workspace` to be writable by the container user.

Artifacts:

- Mount a writable directory at `/artifacts`.
- Upload `/artifacts` from CI after the job.
- Do not mount `/artifacts` over `/workspace`; keep evidence separate from source mutations.

The image runs as UID/GID `10001` by default. If your CI platform mounts the workspace with a different owner, either make the mount writable by UID `10001` or run the container with a matching non-root user:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/workspace" \
  -v "$PWD/artifacts/prodclaw:/artifacts" \
  prodclaw:local \
  --agent codex --task /workspace/task.md --dry-run
```

## Policy Check Smoke Test

Mounted policy and action files work through the same image:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  prodclaw:local \
  policy check \
  --profile ci-standard \
  --action /workspace/examples/actions/git-status.json
```

## Container Doctor

Run the doctor before claiming strong container enforcement:

```bash
docker run --rm \
  -e PRODCLAW_EGRESS_BLOCKED=true \
  -v "$PWD:/workspace" \
  -v "$PWD/artifacts/prodclaw:/artifacts" \
  prodclaw:local \
  doctor --mode container --workspace /workspace --artifact-dir /artifacts
```

The doctor checks:

- container runtime evidence
- non-root runtime user
- `/workspace` mount presence
- `/artifacts` writability
- agent process environment allowlist
- explicit egress-control declaration

The text output prints `Strong enforcement claim:` only when every check passes. JSON output sets `strong_enforcement` to `true` only in that case.

`PRODCLAW_EGRESS_BLOCKED=true` is a runtime assertion made by the CI/container operator. Set it only after the job has a real egress block, such as `--network none` for offline dry-runs or a runner-level firewall for real agent jobs that need selected platform endpoints.

## Agent Environment Allowlist

ProdClaw launches Codex and Claude Code with the same safe agent environment allowlist used by the runtime checks. Sensitive variables such as `GITHUB_TOKEN`, `GITLAB_TOKEN`, `CI_JOB_TOKEN`, cloud keys, SSH agent paths, `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY` are not passed through to the agent process by default.

Safe defaults include only operational variables such as `PATH`, `HOME`, `TMPDIR`, `TEMP`, `TMP`, and `LANG`.

Secrets needed for governed actions must be materialized inside ProdClaw executors, not handed to the agent process. Agent CLI authentication should use the selected agent's non-env credential mechanism or a short-lived CI-specific setup that does not expose broad repository, cloud, or deployment credentials to the agent environment.

## Egress Guidance

For dry-run and policy-check jobs, use `--network none` where possible:

```bash
docker run --rm --network none \
  -e PRODCLAW_EGRESS_BLOCKED=true \
  -v "$PWD:/workspace" \
  -v "$PWD/artifacts/prodclaw:/artifacts" \
  prodclaw:local \
  --agent codex --task /workspace/task.md --dry-run
```

For real Codex or Claude Code jobs, the agent may need access to its model service. Use runner-level network policy, a CI firewall, or a controlled proxy that allows only the required platform endpoints and ProdClaw-governed paths. Do not set `PRODCLAW_EGRESS_BLOCKED=true` until those controls are active.

GitHub-hosted runners do not provide a general per-job outbound deny switch. Use a self-hosted runner, container firewall, or proxy if you need a strong egress claim.

GitLab self-hosted runners can enforce egress with Docker network configuration, host firewall rules, or an outbound proxy. Record that setup in the pipeline and run `prodclaw doctor --mode container` before the agent launch.

## CI Hardening Options

Use the strongest container options your CI platform supports:

```bash
--cap-drop=ALL
--security-opt=no-new-privileges
--read-only
--tmpfs /tmp:rw,noexec,nosuid,size=256m
```

If `--read-only` is enabled, keep `/workspace`, `/artifacts`, and `/tmp` writable through explicit mounts or tmpfs.
