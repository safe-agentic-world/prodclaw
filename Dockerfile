# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X github.com/safe-agentic-world/prodclaw/internal/version.Version=${VERSION}" \
    -o /out/prodclaw ./cmd/prodclaw

FROM alpine:3.22

ARG INSTALL_CODEX=false
ARG CODEX_NPM_PACKAGE=@openai/codex
ARG CODEX_NPM_VERSION=latest
ARG INSTALL_CLAUDE=false
ARG CLAUDE_NPM_PACKAGE=@anthropic-ai/claude-code
ARG CLAUDE_NPM_VERSION=latest

RUN apk add --no-cache ca-certificates curl git nodejs npm openssh-client tini \
    && addgroup -S -g 10001 prodclaw \
    && adduser -S -D -H -h /home/prodclaw -u 10001 -G prodclaw prodclaw \
    && mkdir -p /home/prodclaw /workspace /artifacts /tmp/prodclaw \
    && chown -R prodclaw:prodclaw /home/prodclaw /workspace /artifacts /tmp/prodclaw \
    && if [ "$INSTALL_CODEX" = "true" ]; then npm install -g "${CODEX_NPM_PACKAGE}@${CODEX_NPM_VERSION}"; fi \
    && if [ "$INSTALL_CLAUDE" = "true" ]; then npm install -g "${CLAUDE_NPM_PACKAGE}@${CLAUDE_NPM_VERSION}"; fi \
    && npm cache clean --force

COPY --from=build /out/prodclaw /usr/local/bin/prodclaw
COPY docker/prodclaw-entrypoint.sh /usr/local/bin/prodclaw-entrypoint
RUN chmod 0755 /usr/local/bin/prodclaw /usr/local/bin/prodclaw-entrypoint

ENV HOME=/home/prodclaw \
    TMPDIR=/tmp/prodclaw \
    PRODCLAW_CONTAINER=true \
    PRODCLAW_WORKSPACE=/workspace \
    PRODCLAW_ARTIFACT_DIR=/artifacts

USER prodclaw
WORKDIR /workspace
VOLUME ["/workspace", "/artifacts"]

ENTRYPOINT ["/sbin/tini", "--", "prodclaw-entrypoint"]
CMD ["--help"]
