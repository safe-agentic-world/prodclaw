# Default Profiles

ProdClaw ships two embedded CI profiles:

- `ci-strict` is the default when `job run` receives no customer bundle.
- `ci-standard` is a broader starter profile for feature-branch CI work.

The embedded profiles are useful for evaluation and safe defaults, but production teams should move to a customer-owned policy bundle once they know their required commands, hosts, and repository rules.

## Inspect The Built-Ins

```bash
prodclaw profiles list
prodclaw profiles show ci-strict
prodclaw profiles verify
prodclaw job run --agent codex --task-file task.md --dry-run
```

`profiles list` identifies the embedded source and hash shipped in the running binary. `profiles verify` validates embedded bundles and, when the canonical `profiles/` directory is present, checks that the generated embedded bytes match the canonical YAML. `job run --dry-run` prints the selected profile and the effective policy hash used for execution.

For adapter-specific launch details, see `docs/agent-adapters.md`.

## Replace A Built-In Profile

Use exactly one of `--profile` or `--policy-bundle`.

```bash
prodclaw job run \
  --agent codex \
  --task-file task.md \
  --policy-bundle ./policy/prodclaw.yaml \
  --dry-run
```

Customer bundles should encode explicit allow and deny rules for the actual CI job. If a required action is denied, update the policy deliberately; do not add human approval workflows to CI as a bypass.

ProdClaw intentionally has no manual profile-hash pin file. Profile and bundle hashes are computed from the bytes loaded by the running binary or the customer bundle path.

The canonical built-in policy sources live in `profiles/*.yaml`. Run `go generate ./profiles` after editing them; CI fails if the generated embedded copies drift from the canonical files.

## Network Defaults

Both embedded profiles deny unknown egress by default and deny requests that carry `Authorization` or `Cookie` headers after canonical header normalization.

`ci-standard` adds read-only allow rules for common CI source and package hosts such as GitHub, GitLab, the Go proxy, npm, and PyPI. Redirects stay disabled unless a customer rule explicitly enables `http_redirects`; when enabled, redirect destinations must also appear in that rule's `net_allowlist`.

Use `http_request_max_bytes` to cap outbound request bodies and `output_max_bytes` / `output_max_lines` to cap returned response bodies.
