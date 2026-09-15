import os
import re

SYSROOT = os.environ.get("WG_MANAGER_SYSROOT", "")
# Audit fix: C1 - WireGuard base64 key material shape.
WGKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
# Audit fix: C4 - Linux IF_NAMESIZE bound and shell/nft-safe charset.
IFNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")
# Keys required for a non-interactive `init` (no silent defaults).
REQUIRED_INIT_KEYS = ("endpoint", "port", "mtu", "ifname", "backend", "wan_iface", "ipv4_prefix", "ipv4_hub", "ipv6_mode")

VERSION = "1.0.0"
PROG = "wg-manager"
SCHEMA_VERSION = 1
DEFAULT_STATE_PATH = "/etc/wg-manager/state.json"
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
LANG = "en"
# Minimal ANSI colors, gated by color_enabled() so pipes stay plain.
C_TITLE = "\033[1;36m"
C_OPT = "\033[32m"
C_OK = "\033[32m"
C_WARN = "\033[33m"
C_ERR = "\033[31m"
C_DIM = "\033[2m"
C_RESET = "\033[0m"


MARK = "..."
TAG = {
    "ok": "ok", "warn": "warn", "err": "fail", "skip": "skip", "info": "info",
    "dryrun": "dry-run", "applied": "applied", "destructive": "danger",
}
ROLES = {
    "title": "1;37",
    "section": "1;36",
    "label": "1;36",
    "value": "37",
    "accent": "1;36",
    "muted": "37",
    "ok": "1;32",
    "warn": "1;33",
    "err": "1;31",
    "skip": "37",
    "info": "1;36",
    "dryrun": "1;35",
    "applied": "1;32",
    "destructive": "1;31",
    "rule": "1;34",
    "num": "1;33",
    "cmd": "1;37",
    "shortcut": "1;32",
}


