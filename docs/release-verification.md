# Release Verification

This document explains how to verify official ProdClaw release artifacts.

Release verification answers one question: whether a downloaded ProdClaw binary or archive is an authentic official build from the ProdClaw release workflow. It does not prove a runtime is strongly isolated, and it does not verify any customer policy bundle loaded by that runtime.

## Trust Root

ProdClaw release assets are signed with Sigstore keyless signing.

Verification trust root:

- Fulcio-issued signing certificate
- Rekor transparency log inclusion
- GitHub Actions OIDC identity for the ProdClaw release workflow

Expected signer identity:

- workflow: `.github/workflows/release.yml`
- repository: `safe-agentic-world/prodclaw`
- OIDC issuer: `https://token.actions.githubusercontent.com`

## Release Assets

Each official raw CLI release publishes:

- `prodclaw-linux-amd64.tar.gz`
- `prodclaw-linux-arm64.tar.gz`
- `prodclaw-darwin-amd64.tar.gz`
- `prodclaw-darwin-arm64.tar.gz`
- `prodclaw-windows-amd64.zip`
- `prodclaw-windows-arm64.zip`
- `prodclaw-checksums.txt`
- `prodclaw-sbom.spdx.json`
- `prodclaw-provenance.intoto.jsonl`

Each signed asset also has:

- `<asset>.sig`
- `<asset>.pem`

The M19 release path publishes raw CLI binaries only. Official container image distribution is a later M21 runtime-distribution milestone.

## Verify Checksums

Install `cosign`, download the release assets into one directory, then verify the signed checksum file:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/prodclaw/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature prodclaw-checksums.txt.sig \
  --certificate prodclaw-checksums.txt.pem \
  prodclaw-checksums.txt
```

Then verify the downloaded archive against the checksum list:

```bash
sha256sum -c prodclaw-checksums.txt --ignore-missing
```

## Verify An Archive Signature

Example for Linux amd64:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/prodclaw/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature prodclaw-linux-amd64.tar.gz.sig \
  --certificate prodclaw-linux-amd64.tar.gz.pem \
  prodclaw-linux-amd64.tar.gz
```

## Verify SBOM And Provenance

SBOM:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/prodclaw/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature prodclaw-sbom.spdx.json.sig \
  --certificate prodclaw-sbom.spdx.json.pem \
  prodclaw-sbom.spdx.json
```

Provenance:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/prodclaw/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature prodclaw-provenance.intoto.jsonl.sig \
  --certificate prodclaw-provenance.intoto.jsonl.pem \
  prodclaw-provenance.intoto.jsonl
```

## Verification Failure

Treat verification as failed if:

- any expected artifact is missing
- `cosign verify-blob` returns a non-zero exit code
- the certificate identity does not match the expected release workflow
- the OIDC issuer is not `https://token.actions.githubusercontent.com`
- the archive digest does not match `prodclaw-checksums.txt`

An invalid signature, missing artifact, or checksum mismatch means the release should not be trusted as an official ProdClaw build.

## Separate Trust Domains

Release verification answers:

- "Is this ProdClaw binary or archive an authentic official build?"

It does not answer:

- "Is this CI/container runtime strongly isolated?"
- "Is the policy bundle loaded by this runtime trusted?"

Runtime enforcement evidence is documented separately in controlled-runtime docs. Customer policy bundle trust remains a separate deployment responsibility.
