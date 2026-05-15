# Repository Guidelines

## Project Structure

ProdClaw is a Go codebase for a CI-first policy execution boundary for AI coding agents.

- `cmd/prodclaw`: CLI entrypoint.
- `internal/`: implementation packages.
- `profiles/`: built-in CI policy profiles.
- `examples/`: GitHub Actions and GitLab CI examples.
- `docs/`: product and operator documentation.

The original `nomos` repository is the R&D source. Move code into ProdClaw only when it supports the CI MVP.

## Commands

- `go build ./cmd/prodclaw` builds the CLI.
- `go test ./...` runs tests.
- `go vet ./...` runs static checks.

## Scope Discipline

Keep the MVP focused on CI execution:

- No operator UI in MVP.
- No human approval workflow in MVP.
- No unmanaged laptop strong-enforcement claims.
- Policy decisions are `ALLOW` or `DENY` only for the MVP.

## Security

Do not commit secrets. CI examples must use placeholders and documented environment variables. Runtime claims must distinguish controlled CI/container execution from best-effort local execution.
