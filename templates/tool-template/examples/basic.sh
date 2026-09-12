#!/usr/bin/env bash
# Minimal copy-paste example. Must run in <5 min.
set -euo pipefail
IFS=$' \t\n'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

"$HERE/main.sh" --help
