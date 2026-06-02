Run this as a ProdClaw-governed CI smoke task.

Requirements:
- Use only ProdClaw MCP tools for file writes, command execution, and artifacts.
- First call the ProdClaw MCP run_command tool with argv ["git", "status"].
- Then use the ProdClaw MCP write_file tool to create PRODCLAW_AGENT_SUMMARY.md.
- Then use the ProdClaw MCP write_artifact tool to create agent-summary.txt.
- The file must state that ProdClaw MCP governed the command and write action.
- The artifact must state that ProdClaw MCP governed the artifact write action.
- Do not commit, push, open merge requests, or call external HTTP services.
