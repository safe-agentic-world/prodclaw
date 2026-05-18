# Agent Adapters

ProdClaw keeps Codex and Claude Code behind one launch-plan contract. The job metadata stays uniform; only the adapter-specific argv and MCP wiring details differ.

## Dry Run

Use dry-run before adding credentials to a CI job:

```bash
prodclaw job run --agent codex --profile ci-strict --task task.md --dry-run
prodclaw job run --agent claude --profile ci-strict --task task.md --dry-run
```

The JSON output includes:

- the selected profile or customer policy identity
- one generated MCP config containing only the `prodclaw` server
- the exact per-invocation agent argv
- the adapter capability record
- the truthful MCP wiring method and whether ProdClaw could verify attachment from the generated argv

Dry-run does not need OpenAI or Anthropic credentials and does not mutate global agent configuration.

## Wiring Contract

- Codex uses per-invocation `-c mcp_servers.prodclaw.*` overrides and does not require edits to `~/.codex/config.toml`.
- Claude Code uses a per-invocation `--mcp-config <path>` flag.

Both adapters build the same isolated MCP config shape first. ProdClaw rejects generated configs that contain any additional raw MCP server beside `prodclaw`; upstream tools must be reached through governed ProdClaw policy, not by silent side-by-side registration.

## Verification Limits

The adapter can verify that the generated launch argv attaches the ProdClaw MCP config. That is not the same as proving exclusive mediation once the agent starts. Native tools may still exist in the underlying agent, so launch plans include a bypass warning instead of claiming stronger enforcement than the adapter can mechanically prove.

`job run --no-launch` records an agent version when the binary is available. Dry-run intentionally omits environment-derived version discovery so identical inputs produce deterministic plan output.
