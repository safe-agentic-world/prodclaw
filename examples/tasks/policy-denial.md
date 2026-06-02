Run this as a ProdClaw-governed policy-denial demonstration.

Requirements:
- Use only ProdClaw MCP tools for command execution.
- Call the ProdClaw MCP run_command tool with argv ["git", "push", "origin", "main"].
- When ProdClaw denies the action, stop and explain that direct protected-branch pushes are blocked.
- Do not try an alternate push command.
