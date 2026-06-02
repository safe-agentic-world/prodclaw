# Installation

ProdClaw's first release path is the raw CLI. Docker image distribution is planned separately in M21.

## Go Install

Install the latest tagged CLI with:

```bash
go install github.com/safe-agentic-world/prodclaw/cmd/prodclaw@latest
```

Install a specific release with:

```bash
go install github.com/safe-agentic-world/prodclaw/cmd/prodclaw@v0.1.0
```

Confirm the installed binary:

```bash
prodclaw version
prodclaw profiles list
```

## Release Archives

Official releases publish Linux, macOS, and Windows archives on GitHub releases:

- `prodclaw-linux-amd64.tar.gz`
- `prodclaw-linux-arm64.tar.gz`
- `prodclaw-darwin-amd64.tar.gz`
- `prodclaw-darwin-arm64.tar.gz`
- `prodclaw-windows-amd64.zip`
- `prodclaw-windows-arm64.zip`

The standard release path mirrors Nomos:

- `Enterprise CI` passes on `main`.
- `Auto Tag Release` creates the next semantic tag for `feat`, `fix`, or breaking-change commits.
- `Auto Tag Release` dispatches the `Release` workflow with that tag.
- Operators can also run `Release` manually with an existing `vX.Y.Z` tag.

Verify archives before use with [Release Verification](release-verification.md).

## Homebrew And Scoop Handoff

The release workflow can update these package repositories when the GitHub secret `prodclaw_packages` is configured. The workflow passes that secret to the package-update script as `PACKAGES_REPO_TOKEN`.

- `safe-agentic-world/homebrew-prodclaw`
- `safe-agentic-world/scoop-prodclaw`

This package-manager handoff is optional for the MVP raw CLI release. If package repo updates fail, the GitHub release can still publish as long as required checksums, signatures, SBOM, and provenance artifacts are present.

Future install commands are expected to be:

```bash
brew tap safe-agentic-world/prodclaw
brew install prodclaw
```

```powershell
scoop bucket add prodclaw https://github.com/safe-agentic-world/scoop-prodclaw
scoop install prodclaw
```
