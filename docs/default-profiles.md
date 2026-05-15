# Default Profiles

ProdClaw ships two embedded CI profiles:

- `ci-strict` is the default when `job run` receives no customer bundle.
- `ci-standard` is a broader starter profile for feature-branch CI work.

The embedded profiles are useful for evaluation and safe defaults, but production teams should move to a customer-owned policy bundle once they know their required commands, hosts, and repository rules.

## Inspect The Built-Ins

```bash
prodclaw profiles list
prodclaw profiles show ci-strict
prodclaw job run --agent codex --task task.md --dry-run
```

`job run --dry-run` prints the selected profile and the hash computed from the profile embedded in the running binary.

## Replace A Built-In Profile

Use exactly one of `--profile` or `--policy-bundle`.

```bash
prodclaw job run \
  --agent codex \
  --task task.md \
  --policy-bundle ./policy/prodclaw.yaml \
  --dry-run
```

Customer bundles should encode explicit allow and deny rules for the actual CI job. If a required action is denied, update the policy deliberately; do not add human approval workflows to CI as a bypass.

ProdClaw intentionally has no manual profile-hash pin file. Profile and bundle hashes are computed from the bytes loaded by the running binary or the customer bundle path.
