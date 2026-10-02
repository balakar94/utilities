#!/usr/bin/env bash
# wg-manager installer helper (non-executable, run with: bash install.sh).
# Scope: packages + binary only. Never renders network/firewall/state (manager init/reload owns that).
set -euo pipefail
# Compatibility: bash 3.2 only, no associative arrays, no mapfile, no &>> redirection.
# Portability: no realpath; any in-place file edit must use portable sed -i.bak form.
# Safety: no curl|bash piping; no implicit sudo, only sudo -n when --sudo is given.
PREFIX="/usr/local"
APPLY=0
YES=0
SUDO=0
FORCE=0
UNINSTALL=0
RESTORE=0
VERIFY=0
DRYRUN=0
PRIV=""
TMP=""
usage() {
  printf '%s\n' "Usage: bash install.sh [options]" "  --prefix PATH  install prefix (default /usr/local, binary=PREFIX/bin/wg-manager)" "  --apply --yes --sudo  gated apply (default is dry-run, changes nothing)" "  --force  overwrite identical version; --uninstall removes binary and manifest" "  --restore  verify and reinstall the latest .bak backup of the binary" "  --verify  check the installed binary against the manifest sha256" "  --dry-run  explicit dry-run; --help  show this help" "Scope: packages + binary only. Build is staged and verified before replacing the binary."
}
# Remove the staging file on any exit path, including INT/TERM/HUP.
cleanup_tmp() {
  if [ -n "${TMP:-}" ] && [ -e "$TMP" ]; then
    ${PRIV:-} rm -f "$TMP" 2> /dev/null || true
  fi
}
trap cleanup_tmp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# Argument parsing (bash 3.2 compatible, no associative arrays).
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --prefix requires a path value." >&2
        usage >&2
        exit 2
      fi
      case "${2:-}" in
        --*)
          echo "ERROR: --prefix requires a path value, got flag: $2" >&2
          exit 2
          ;;
        "")
          echo "ERROR: --prefix requires a non-empty path." >&2
          exit 2
          ;;
      esac
      PREFIX="$2"
      shift 2
      ;;
    --prefix=*)
      PREFIX="${1#--prefix=}"
      shift
      ;;
    --apply)
      APPLY=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    --sudo)
      SUDO=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    --restore)
      RESTORE=1
      shift
      ;;
    --verify)
      VERIFY=1
      shift
      ;;
    --dry-run)
      DRYRUN=1
      shift
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done
if [ "$DRYRUN" -eq 1 ]; then APPLY=0; fi
# Audit fix: N16 - validate the prefix before it reaches install/manifest.
case "$PREFIX" in
  /*) : ;;
  *)
    echo "ERROR: --prefix must be an absolute path (got: $PREFIX)." >&2
    exit 2
    ;;
esac
# Audit fix: reject '..' path components. Wrapping the prefix in slashes makes
# every component boundary a slash, so only a literal '..' component matches.
case "/$PREFIX/" in
  */../*)
    echo "ERROR: --prefix must not contain '..' path components (got: $PREFIX)." >&2
    exit 2
    ;;
esac
case "$PREFIX" in
  *[!A-Za-z0-9._/+:-]*)
    echo "ERROR: --prefix contains unsafe characters: $PREFIX" >&2
    exit 2
    ;;
esac
# Resolve script dir without realpath (portable dirname + pwd -P).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
SRC="$SCRIPT_DIR/main.py"
if [ ! -f "$SRC" ]; then SRC="$SCRIPT_DIR/../main.py"; fi
BIN="$PREFIX/bin/wg-manager"
MANIFEST="/var/lib/wg-manager/install-manifest.json"
TS="$(date +%Y%m%d%H%M%S)"
# Distro detect via /etc/os-release ID and ID_LIKE.
PKG_MGR="unknown"
TIER="2"
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OSID="${ID:-unknown}"
  OSLIKE="${ID_LIKE:-}"
  case " $OSID $OSLIKE " in
    *" debian "* | *" ubuntu "*)
      PKG_MGR="apt"
      TIER="1"
      ;;
    *" rhel "* | *" fedora "* | *" alma "* | *" rocky "* | *" ol "* | *" centos "* | *" nobara "*)
      PKG_MGR="dnf"
      TIER="1"
      ;;
    *" arch "* | *" endeavouros "* | *" cachyos "* | *" manjaro "*)
      PKG_MGR="pacman"
      TIER="1"
      ;;
  esac
fi
# Packages come from distro repos only (no external repos) and are not version-pinned.
case "$PKG_MGR" in
  apt) PKGS="python3 wireguard-tools qrencode nftables iproute2" ;;
  pacman) PKGS="python wireguard-tools qrencode nftables iproute2" ;;
  dnf) PKGS="python3 wireguard-tools qrencode iproute NetworkManager firewalld policycoreutils-python-utils" ;;
  *) PKGS="python3 wireguard-tools qrencode iproute2" ;;
esac
if [ "$TIER" = "2" ]; then echo "WARN: Tier-2 distro, package names are best-effort." >&2; fi
SELINUX="no"
if command -v getenforce > /dev/null 2>&1 || [ -e /sys/fs/selinux/enforce ]; then SELINUX="yes"; fi
if [ ! -f "$SRC" ]; then
  echo "ERROR: source not found: $SRC" >&2
  exit 1
fi
# Audit fix: python3 is required to read the version, build the zipapp and verify it.
if ! command -v python3 > /dev/null 2>&1; then
  echo "ERROR: python3 not found; install python3 first (required to read the source version and build the manager)." >&2
  exit 1
fi
SRC_VER="$(python3 "$SRC" --version 2> /dev/null | sed 's/.* //')"
if [ -z "${SRC_VER:-}" ]; then
  echo "ERROR: cannot read source version." >&2
  exit 1
fi
INST_VER="none"
if [ -x "$BIN" ]; then INST_VER="$("$BIN" --version 2> /dev/null | sed 's/.* //' || true)"; fi
if [ -x "$BIN" ] && [ -z "${INST_VER:-}" ]; then INST_VER="corrupt"; fi
BACKUP="$BIN.bak.$TS"
if [ -e "$BACKUP" ]; then BACKUP="$BACKUP.$$"; fi
# Audit fix: sha256 helper for the manifest (sha256sum on Linux, shasum on macOS); "" if neither exists.
file_sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    printf ''
  fi
}
# Latest backup by modification time is unreliable across copies; the timestamp
# name sorts lexicographically because it is zero-padded YYYYmmddHHMMSS.
if [ "$UNINSTALL" -eq 1 ]; then
  if [ "$APPLY" -eq 0 ]; then
    echo "PLAN: uninstall $BIN (dry-run, changes nothing). Installed: $INST_VER."
    echo "PLAN: removes the binary and the install manifest if present: $MANIFEST"
    echo "PLAN: packages, services and state under /etc/wg-manager are NOT touched."
    exit 0
  fi
  if [ "$YES" -eq 0 ]; then
    echo "ERROR: --uninstall --apply requires --yes." >&2
    exit 2
  fi
  PRIV=""
  if [ "$(id -u)" -ne 0 ]; then
    if [ "$SUDO" -eq 0 ]; then
      echo "ERROR: need root or --sudo." >&2
      exit 2
    fi
    sudo -n true || {
      echo "ERROR: sudo -n failed." >&2
      exit 1
    }
    PRIV="sudo -n"
  fi
  # Audit fix: A9 - uninstall only removes; use --restore to bring a backup back.
  $PRIV rm -f "$BIN"
  if $PRIV test -e "$MANIFEST"; then
    $PRIV rm -f "$MANIFEST"
    echo "Removed manifest $MANIFEST."
  fi
  echo "Uninstalled $BIN (packages, services and /etc/wg-manager state untouched)."
  exit 0
fi
if [ "$RESTORE" -eq 1 ]; then
  LATEST="$(ls -1 "$BIN".bak.* 2> /dev/null | sort | tail -n 1 || true)"
  if [ "$APPLY" -eq 0 ]; then
    echo "PLAN: restore ${LATEST:-none} to $BIN (dry-run, changes nothing)."
    echo "PLAN: verify --version and --self-test on a staging copy before replacing $BIN."
    exit 0
  fi
  if [ "$YES" -eq 0 ]; then
    echo "ERROR: --restore --apply requires --yes." >&2
    exit 2
  fi
  if [ -z "${LATEST:-}" ] || [ ! -f "$LATEST" ]; then
    echo "ERROR: no backup found for $BIN." >&2
    exit 1
  fi
  PRIV=""
  if [ "$(id -u)" -ne 0 ]; then
    if [ "$SUDO" -eq 0 ]; then
      echo "ERROR: need root or --sudo." >&2
      exit 2
    fi
    sudo -n true || {
      echo "ERROR: sudo -n failed." >&2
      exit 1
    }
    PRIV="sudo -n"
  fi
  # Audit fix: stage the backup next to BIN and verify it before replacing anything.
  $PRIV mkdir -p "$PREFIX/bin"
  TMP="$($PRIV mktemp "$PREFIX/bin/.wg-manager.restore.XXXXXX")"
  if ! $PRIV cp -p "$LATEST" "$TMP"; then
    echo "ERROR: cannot copy backup $LATEST." >&2
    exit 1
  fi
  REST_VER="$($PRIV python3 "$TMP" --version 2> /dev/null | sed 's/.* //' || true)"
  if [ -z "${REST_VER:-}" ] || ! $PRIV python3 "$TMP" --self-test > /dev/null 2>&1; then
    echo "ERROR: backup $LATEST failed verification; keeping current $BIN." >&2
    exit 1
  fi
  $PRIV chmod 0755 "$TMP"
  $PRIV mv -f "$TMP" "$BIN"
  if [ "$SELINUX" = "yes" ] && command -v restorecon > /dev/null 2>&1; then $PRIV restorecon -v "$BIN" 2> /dev/null || true; fi
  # Keep --verify consistent after a restore: the manifest must describe the
  # binary now installed (zipapp builds are not byte-reproducible).
  if [ -f "$MANIFEST" ]; then
    REST_SHA="$(file_sha256 "$BIN")"
    if [ -n "$REST_SHA" ]; then
      $PRIV python3 - "$MANIFEST" "$REST_VER" "$REST_SHA" << 'PYEOF'
import json
import sys

path, ver, sha = sys.argv[1:4]
try:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
except (OSError, ValueError):
    raise SystemExit(0)
if isinstance(doc, dict):
    doc["installed_version"] = ver
    doc["binary_sha256"] = sha
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
PYEOF
    fi
  fi
  echo "Restored $LATEST to $BIN (version $REST_VER, self-test pass)."
  exit 0
fi
# Audit fix: WS-10 - read the manifest sha256 back before trusting an install.
if [ "$VERIFY" -eq 1 ]; then
  if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: manifest not found: $MANIFEST" >&2
    exit 1
  fi
  if [ ! -x "$BIN" ]; then
    echo "ERROR: installed binary not found or not executable: $BIN" >&2
    exit 1
  fi
  if ! command -v python3 > /dev/null 2>&1; then
    echo "ERROR: python3 not found; required to verify the manifest." >&2
    exit 1
  fi
  ACTUAL_SHA="$(file_sha256 "$BIN")"
  if [ -z "$ACTUAL_SHA" ]; then
    echo "ERROR: no sha256 tool available (sha256sum/shasum)." >&2
    exit 1
  fi
  python3 - "$MANIFEST" "$BIN" "$ACTUAL_SHA" << 'PYEOF'
import json
import sys

manifest, bin_path, actual = sys.argv[1:4]
try:
    with open(manifest, encoding="utf-8") as fh:
        doc = json.load(fh)
except (OSError, ValueError) as exc:
    print("ERROR: cannot read manifest: " + str(exc), file=sys.stderr)
    raise SystemExit(1)
if not isinstance(doc, dict):
    print("ERROR: manifest is not a JSON object.", file=sys.stderr)
    raise SystemExit(1)
expected = str(doc.get("binary_sha256", ""))
if not expected:
    print("ERROR: manifest has no binary_sha256; cannot verify.", file=sys.stderr)
    raise SystemExit(1)
if expected != actual:
    print("ERROR: binary hash mismatch (manifest " + expected + ", actual " + actual + ").", file=sys.stderr)
    raise SystemExit(1)
print("OK: verified " + bin_path + " against " + manifest + ".")
PYEOF
  exit $?
fi
if [ "$INST_VER" = "$SRC_VER" ] && [ "$FORCE" -eq 0 ]; then
  echo "OK: $BIN already at $SRC_VER (use --force)."
  exit 0
fi
echo "PLAN: source $SRC_VER ($SRC), installed $INST_VER."
echo "PLAN: manager $PKG_MGR (tier $TIER), packages: $PKGS."
echo "PLAN: packages come from distro repos, not version-pinned; no external repos are added."
if [ "$PKG_MGR" = "pacman" ]; then echo "PLAN: pacman DB refresh (-Sy) is operator responsibility on rolling hosts; installer runs -S --needed only."; fi
echo "PLAN: build zipapp to a staging file in $PREFIX/bin, verify --version/--self-test, then swap into $BIN."
if [ -x "$BIN" ]; then echo "PLAN: backup $BIN to $BACKUP with mode 0600 before the swap."; else echo "PLAN: fresh install, no backup."; fi
echo "PLAN: SELinux restorecon: $SELINUX. Manifest schema_version 1: $MANIFEST."
if [ "$APPLY" -eq 0 ]; then
  echo "Dry-run: changes nothing. Re-run with --apply --yes [--sudo]."
  exit 0
fi
if [ "$YES" -eq 0 ]; then
  echo "ERROR: --apply requires --yes." >&2
  exit 2
fi
PRIV=""
if [ "$(id -u)" -ne 0 ]; then
  if [ "$SUDO" -eq 0 ]; then
    echo "ERROR: need root or --sudo." >&2
    exit 2
  fi
  sudo -n true || {
    echo "ERROR: sudo -n failed." >&2
    exit 1
  }
  PRIV="sudo -n"
fi
# Packages first: a package failure leaves $BIN untouched.
export DEBIAN_FRONTEND=noninteractive
case "$PKG_MGR" in
  apt) $PRIV apt-get update && $PRIV env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS ;;
  dnf) $PRIV dnf install -y --setopt=install_weak_deps=False $PKGS ;;
  pacman) $PRIV pacman -S --needed --noconfirm $PKGS ;;
  *)
    echo "ERROR: unsupported distro for apply." >&2
    exit 1
    ;;
esac
# Audit fix: N16 - install(1) does not create parent dirs; create the prefix.
$PRIV mkdir -p "$PREFIX/bin"
# Audit fix: N16 - stage the zipapp in the target directory (same filesystem) and verify it first.
TMP="$($PRIV mktemp "$PREFIX/bin/.wg-manager.build.XXXXXX")"
$PRIV python3 - "$SCRIPT_DIR" "$TMP" << 'PYEOF'
import sys, tempfile, shutil, zipapp
from pathlib import Path

src_dir = Path(sys.argv[1]).resolve()
target_bin = Path(sys.argv[2]).resolve()

with tempfile.TemporaryDirectory() as tmpdir:
    staging = Path(tmpdir)
    lib_src = src_dir / "lib"
    if lib_src.is_dir():
        shutil.copytree(lib_src, staging / "lib")
    shutil.copyfile(src_dir / "main.py", staging / "__main__.py")
    zipapp.create_archive(
        staging,
        target=target_bin,
        interpreter="/usr/bin/env python3"
    )
PYEOF
$PRIV chmod 0600 "$TMP"
TMP_VER="$($PRIV python3 "$TMP" --version 2> /dev/null | sed 's/.* //' || true)"
if [ "$TMP_VER" != "$SRC_VER" ]; then
  echo "ERROR: staged build version '${TMP_VER:-none}' != source '$SRC_VER'; $BIN untouched." >&2
  exit 1
fi
if ! $PRIV python3 "$TMP" --self-test > /dev/null 2>&1; then
  echo "ERROR: staged build failed --self-test; $BIN untouched." >&2
  exit 1
fi
HAD_FILE=0
BACKUP_USED=""
if [ -e "$BIN" ]; then
  HAD_FILE=1
  $PRIV cp -p "$BIN" "$BACKUP"
  $PRIV chmod 0600 "$BACKUP"
  BACKUP_USED="$BACKUP"
fi
# Same filesystem: rename(2) via mv is atomic, so there is no truncated-binary window.
$PRIV chmod 0755 "$TMP"
$PRIV mv -f "$TMP" "$BIN"
if [ "$SELINUX" = "yes" ] && command -v restorecon > /dev/null 2>&1; then $PRIV restorecon -v "$BIN" 2> /dev/null || true; fi
DEP_VER="$("$BIN" --version 2> /dev/null | sed 's/.* //' || true)"
VERIFY="pass"
if [ "$DEP_VER" != "$SRC_VER" ]; then VERIFY="fail-version"; fi
if [ "$VERIFY" = "pass" ] && ! "$BIN" --self-test > /dev/null 2>&1; then VERIFY="fail-self-test"; fi
if [ "$VERIFY" != "pass" ]; then
  echo "ERROR: verify $VERIFY, rolling back." >&2
  if [ "$HAD_FILE" -eq 1 ]; then
    $PRIV cp -p "$BACKUP" "$BIN"
    $PRIV chmod 0755 "$BIN"
  else
    $PRIV rm -f "$BIN"
  fi
  exit 1
fi
# Audit fix: N1 - build the manifest with json.dump and argv, never sh -c interpolation.
$PRIV mkdir -p "$(dirname "$MANIFEST")"
BIN_SHA="$(file_sha256 "$BIN")"
$PRIV python3 - "$MANIFEST" "$SRC_VER" "$DEP_VER" "$TS" "$BACKUP_USED" "$PKGS" "$PREFIX" "$VERIFY" "$BIN_SHA" "$BIN" << 'PYEOF'
import json
import sys

(dest, src_ver, inst_ver, ts, backup, pkgs, prefix,
 verify, binary_sha256, bin_path) = sys.argv[1:11]
doc = {
    "schema_version": 1,
    "source_version": src_ver,
    "installed_version": inst_ver,
    "ts": ts,
    "backup": backup,
    "packages": pkgs,
    "prefix": prefix,
    "verify": verify,
    "binary_sha256": binary_sha256,
    "files": [bin_path],
}
with open(dest, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
echo "OK: installed $BIN $DEP_VER (verify $VERIFY)."
