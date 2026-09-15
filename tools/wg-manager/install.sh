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
DRYRUN=0
usage() {
  printf '%s\n' "Usage: bash install.sh [options]" "  --prefix PATH  install prefix (default /usr/local, binary=PREFIX/bin/wg-manager)" "  --apply --yes --sudo  gated apply (default is dry-run, changes nothing)" "  --force  overwrite identical version; --uninstall removes binary only" "  --restore  reinstall the latest .bak backup of the binary" "  --dry-run  explicit dry-run; --help  show this help" "Scope: packages + binary only. Mode 0755 in all cases."
}
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
# Packages pinned via distro repos only, no external repos.
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
SRC_VER="$(python3 "$SRC" --version 2> /dev/null | sed 's/.* //')"
if [ -z "${SRC_VER:-}" ]; then
  echo "ERROR: cannot read source version." >&2
  exit 1
fi
INST_VER="none"
if [ -x "$BIN" ]; then INST_VER="$("$BIN" --version 2> /dev/null | sed 's/.* //')"; fi
if [ -x "$BIN" ] && [ -z "${INST_VER:-}" ]; then INST_VER="corrupt"; fi
BACKUP="$BIN.bak.$TS"
if [ -e "$BACKUP" ]; then BACKUP="$BACKUP.$$"; fi
# Latest backup by modification time is unreliable across copies; the timestamp
# name sorts lexicographically because it is zero-padded YYYYmmddHHMMSS.
if [ "$UNINSTALL" -eq 1 ]; then
  if [ "$APPLY" -eq 0 ]; then
    echo "PLAN: uninstall $BIN (dry-run, changes nothing). Installed: $INST_VER."
    echo "PLAN: removes the binary only; packages, services and state are untouched."
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
  echo "Uninstalled $BIN (packages, services, state untouched)."
  exit 0
fi
if [ "$RESTORE" -eq 1 ]; then
  LATEST="$(ls -1 "$BIN".bak.* 2> /dev/null | sort | tail -n 1 || true)"
  if [ "$APPLY" -eq 0 ]; then
    echo "PLAN: restore ${LATEST:-none} to $BIN (dry-run, changes nothing)."
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
  $PRIV cp -p "$LATEST" "$BIN"
  $PRIV chmod 0755 "$BIN"
  echo "Restored $LATEST to $BIN."
  exit 0
fi
if [ "$INST_VER" = "$SRC_VER" ] && [ "$FORCE" -eq 0 ]; then
  echo "OK: $BIN already at $SRC_VER (use --force)."
  exit 0
fi
echo "PLAN: source $SRC_VER ($SRC), installed $INST_VER."
echo "PLAN: manager $PKG_MGR (tier $TIER), packages: $PKGS."
if [ "$PKG_MGR" = "pacman" ]; then echo "PLAN: pacman DB refresh (-Sy) is operator responsibility on rolling hosts; installer runs -S --needed only."; fi
echo "PLAN: deploy standalone zipapp from $SCRIPT_DIR to $BIN with mode 0755."
if [ -x "$BIN" ]; then echo "PLAN: backup $BIN to $BACKUP with mode 0600."; else echo "PLAN: fresh install, no backup."; fi
echo "PLAN: SELinux restorecon: $SELINUX. Verify --version plus --self-test. Manifest: $MANIFEST."
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
HAD_FILE=0
if [ -e "$BIN" ]; then
  HAD_FILE=1
  $PRIV cp -p "$BIN" "$BACKUP"
  $PRIV chmod 0600 "$BACKUP"
fi
case "$PKG_MGR" in
  apt) $PRIV apt-get update && $PRIV apt-get install -y $PKGS ;;
  dnf) $PRIV dnf install -y $PKGS ;;
  pacman) $PRIV pacman -S --needed --noconfirm $PKGS ;;
  *)
    echo "ERROR: unsupported distro for apply." >&2
    exit 1
    ;;
esac
# Audit fix: N16 - install(1) does not create parent dirs; create the prefix.
$PRIV mkdir -p "$PREFIX/bin"
# Build standalone executable zipapp from source tree
$PRIV python3 - "$SCRIPT_DIR" "$BIN" << 'PYEOF'
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
$PRIV chmod 0755 "$BIN"
if [ "$SELINUX" = "yes" ] && command -v restorecon > /dev/null 2>&1; then $PRIV restorecon -v "$BIN" 2> /dev/null || true; fi
DEP_VER="$("$BIN" --version 2> /dev/null | sed 's/.* //')"
VERIFY="pass"
if [ "$DEP_VER" != "$SRC_VER" ]; then VERIFY="fail-version"; fi
if [ "$VERIFY" = "pass" ] && ! "$BIN" --self-test > /dev/null 2>&1; then VERIFY="fail-self-test"; fi
if [ "$VERIFY" != "pass" ]; then
  echo "ERROR: verify $VERIFY, rolling back." >&2
  if [ "$HAD_FILE" -eq 1 ]; then
    $PRIV cp -p "$BACKUP" "$BIN"
    $PRIV chmod 0755 "$BIN"
  else $PRIV rm -f "$BIN"; fi
  exit 1
fi
# Audit fix: N1 - build the manifest with json.dump and argv, never sh -c interpolation.
$PRIV mkdir -p "$(dirname "$MANIFEST")"
$PRIV python3 - "$MANIFEST" "$SRC_VER" "$DEP_VER" "$TS" "$BACKUP" "$PKGS" "$PREFIX" "$VERIFY" << 'PYEOF'
import json
import sys
dest, src_ver, dep_ver, ts, backup, pkgs, prefix, verify = sys.argv[1:9]
with open(dest, "w", encoding="utf-8") as fh:
    json.dump({"source_version": src_ver, "installed_version": dep_ver, "ts": ts,
               "backup": backup, "packages": pkgs, "prefix": prefix, "verify": verify}, fh)
    fh.write("\n")
PYEOF
echo "OK: installed $BIN $DEP_VER (verify $VERIFY)."
