#!/usr/bin/env bash
# scripts/common.sh — shared prelude. Source only, do not execute.
# Compat: bash 3.2+ (macOS) and bash 5.x (Linux).
set -euo pipefail
IFS=$' \t\n'

if [ -n "${__TOOLS_COMMON_SOURCED:-}" ]; then return 0; fi
__TOOLS_COMMON_SOURCED=1

: "${LOG_LEVEL:=INFO}"

_log() {
  level="$1"
  shift
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '[%s] %-5s %s\n' "$ts" "$level" "$*" >&2
}
log_debug() {
  [ "$LOG_LEVEL" = "DEBUG" ] && _log DEBUG "$*"
  return 0
}
log_info() { _log INFO "$*"; }
log_warn() { _log WARN "$*"; }
log_error() { _log ERROR "$*"; }
die() {
  log_error "$*"
  exit 1
}

repo_root() {
  if command -v git > /dev/null 2>&1 && git rev-parse --show-toplevel > /dev/null 2>&1; then
    git rev-parse --show-toplevel
  else
    (cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
  fi
}
need_cmd() {
  c=""
  for c in "$@"; do command -v "$c" > /dev/null 2>&1 || die "missing required command: $c"; done
}
is_kebab_name() {
  echo "${1:-}" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$' || return 1
  len=${#1}
  [ "$len" -ge 2 ] && [ "$len" -le 48 ]
}
