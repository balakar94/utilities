#!/usr/bin/env bash
# __TOOL_NAME__ — one-line purpose.
# Usage: main.sh [--help] [--version]
set -euo pipefail
IFS=$' \t\n'

VERSION="0.1.0"

usage() {
  cat << EOF
Usage: __TOOL_NAME__ [--help] [--version]

Small description of what it does.
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  --version)
    echo "__TOOL_NAME__ $VERSION"
    exit 0
    ;;
  "")
    usage >&2
    exit 2
    ;;
  *)
    echo "ERROR: unknown arg: $1" >&2
    usage >&2
    exit 2
    ;;
esac
