#!/bin/sh
set -eu

workspace="${PRODCLAW_WORKSPACE:-/workspace}"
artifacts="${PRODCLAW_ARTIFACT_DIR:-/artifacts}"

if [ "$#" -eq 0 ]; then
  set -- --help
fi

case "$1" in
  version|policy|profiles|mcp|job|doctor|help|-h|--help)
    exec prodclaw "$@"
    ;;
  -*)
    exec prodclaw job run --workspace "$workspace" --artifact-dir "$artifacts" "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
