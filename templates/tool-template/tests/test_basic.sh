#!/usr/bin/env bash
# Smoke test for a bash tool: <30s, no network, no sudo, no writes.
set -euo pipefail
IFS=$' \t\n'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ENTRY="$HERE/main.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ -x "$ENTRY" ] || fail "no executable entrypoint: main.sh"

OUT="$("$ENTRY" --help 2>&1)" || fail "--help exit != 0"
printf '%s\n' "$OUT" | grep -qi "usage:" || fail "--help missing 'Usage:'"

if "$ENTRY" > /dev/null 2>&1; then
  fail "no-arg run should fail"
fi

A="$("$ENTRY" --help 2>&1)"
B="$("$ENTRY" --help 2>&1)"
[ "$A" = "$B" ] || fail "not idempotent"

echo "OK: $(basename "$HERE")"
