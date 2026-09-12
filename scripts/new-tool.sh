#!/usr/bin/env bash
# scripts/new-tool.sh — scaffold a new tool from template.
# Usage: bash scripts/new-tool.sh [--lang bash|python|powershell|ruby] [--force] <kebab-name>
set -euo pipefail
IFS=$' \t\n'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=common.sh
source "$HERE/common.sh"

usage() {
  cat >&2 << 'EOF'
Usage: bash scripts/new-tool.sh [--lang bash|python|powershell|ruby] [--no-examples] [--force] <kebab-name>
  <kebab-name>  e.g. net-scan. Regex: ^[a-z0-9]+(-[a-z0-9]+)*$ (2-48 chars)
  --no-examples skip the optional examples/ folder
EOF
  exit 2
}

LANG="bash"
FORCE=0
EXAMPLES=1
NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --lang)
      LANG="${2:-}"
      shift 2
      ;;
    --lang=*)
      LANG="${1#--lang=}"
      shift
      ;;
    --no-examples)
      EXAMPLES=0
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h | --help) usage ;;
    -*) die "unknown flag: $1" ;;
    *)
      [ -z "$NAME" ] && NAME="$1" || die "too many args"
      shift
      ;;
  esac
done
[ -n "$NAME" ] || usage
case "$LANG" in ps1) LANG="powershell" ;; esac
case "$LANG" in
  bash | python | powershell | ruby) ;;
  *) die "--lang must be bash|python|powershell|ruby" ;;
esac
is_kebab_name "$NAME" || die "invalid tool name '$NAME'"
case "$NAME" in common | template | test | scripts | tools | templates) die "reserved name: $NAME" ;; esac

need_cmd cp chmod sed grep
ROOT="$(repo_root)"
TPL="$ROOT/templates/tool-template"
DEST="$ROOT/tools/$NAME"
[ -d "$TPL" ] || die "template missing: $TPL"
if [ -e "$DEST" ]; then
  if [ "$FORCE" = "1" ]; then rm -rf "$DEST"; else die "exists: tools/$NAME (use --force)"; fi
fi

mkdir -p "$DEST"
cp -R "$TPL/." "$DEST/"
# Drop bytecode/caches accidentally left in the template dir (never scaffold junk)
rm -rf "$DEST/__pycache__" "$DEST/.pytest_cache" "$DEST/.ruff_cache"
find "$DEST" -name '.DS_Store' -type f -delete 2> /dev/null || true
grep -rl '__TOOL_NAME__' "$DEST" | while IFS= read -r f; do
  sed -i.bak "s/__TOOL_NAME__/$NAME/g" "$f" && rm -f "$f.bak"
done
# One language only: keep the chosen entrypoint, its native test and (optional) example.
case "$LANG" in
  bash)
    ENTRY="main.sh"
    EXT="sh"
    ;;
  python)
    ENTRY="main.py"
    EXT="py"
    ;;
  powershell)
    ENTRY="main.ps1"
    EXT="ps1"
    ;;
  ruby)
    ENTRY="main.rb"
    EXT="rb"
    ;;
esac
for m in main.sh main.py main.ps1 main.rb; do
  [ "$m" = "$ENTRY" ] || rm -f "$DEST/$m"
done
for t in test_basic.sh test_basic.py test_basic.ps1 test_basic.rb; do
  [ "$t" = "test_basic.$EXT" ] || rm -f "$DEST/tests/$t"
done
for e in basic.sh basic.py basic.ps1 basic.rb; do
  [ "$e" = "basic.$EXT" ] || rm -f "$DEST/examples/$e"
done
if [ "$EXAMPLES" != "1" ]; then
  rm -rf "$DEST/examples"
fi

# Point the scaffolded README at the chosen entrypoint (template defaults to main.sh)
if [ "$ENTRY" != "main.sh" ]; then
  sed -i.bak "s/main\.sh/$ENTRY/g" "$DEST/README.md" && rm -f "$DEST/README.md.bak"
fi

chmod +x "$DEST/$ENTRY" "$DEST/tests/test_basic.$EXT"
if [ -f "$DEST/examples/basic.$EXT" ]; then
  chmod +x "$DEST/examples/basic.$EXT"
fi

case "$LANG" in
  bash) TESTCMD="bash tools/$NAME/tests/test_basic.sh" ;;
  python) TESTCMD="python3 tools/$NAME/tests/test_basic.py" ;;
  powershell) TESTCMD="pwsh tools/$NAME/tests/test_basic.ps1" ;;
  ruby) TESTCMD="ruby tools/$NAME/tests/test_basic.rb" ;;
esac

log_info "created tools/$NAME (lang=$LANG)"
cat >&2 << EOF
Next:
  1. Edit tools/$NAME/metadata.yaml (description, category, owner)
  2. Edit tools/$NAME/README.md
  3. $TESTCMD
  4. bash scripts/list-tools.sh --check
EOF
