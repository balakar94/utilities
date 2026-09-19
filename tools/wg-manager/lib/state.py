# state.py
import contextlib
import json
import os
import re
import secrets
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

from .constants import DEFAULT_STATE_PATH, IFNAME_RE, NAME_RE, SCHEMA_VERSION
from .i18n import t
from .presentation import eprint

# ---------------------------------------------------------------- schema
# Registry of migrations: from_version -> callable(data) -> data.
# Kept explicit so a future bump cannot silently accept old shapes.
MIGRATIONS = {}

_PEER_ROLES = ("client", "infra")
_PEER_TRAFFIC = ("server-only", "custom-routes", "full-tunnel")
_PEER_DNS_SCOPES = ("none", "tunnel", "all")
_IPV6_MODES = ("disabled", "ula", "routed", "nat66")
_BACKENDS = ("networkd", "nm")
_FIREWALLS = ("nft", "firewalld")


def _bad(detail):
    raise ValueError(t("err_state_invalid").format(detail=detail))


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_peer(peer, index):
    where = "peers[" + str(index) + "]"
    if not isinstance(peer, dict):
        _bad(where + " is not an object")
    name = peer.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name) or ".." in name or "/" in name:
        _bad(where + ".name")
    role = peer.get("role", "client")
    if role not in _PEER_ROLES:
        _bad(where + ".role")
    traffic = peer.get("traffic")
    if traffic is not None and traffic not in _PEER_TRAFFIC:
        _bad(where + ".traffic")
    dns_scope = peer.get("dns_scope")
    if dns_scope is not None and dns_scope not in _PEER_DNS_SCOPES:
        _bad(where + ".dns_scope")
    for key in ("v4", "v6", "pubkey", "privkey", "psk", "pool", "endpoint"):
        value = peer.get(key)
        if value is not None and not isinstance(value, str):
            _bad(where + "." + key)
    for key in ("keepalive", "expires_at"):
        value = peer.get(key)
        if value is not None and not _is_int(value):
            _bad(where + "." + key)
    for key in ("enabled", "tombstoned", "needs_reissue"):
        value = peer.get(key)
        if value is not None and not isinstance(value, bool):
            _bad(where + "." + key)
    routes = peer.get("custom_routes")
    if routes is not None and not isinstance(routes, list):
        _bad(where + ".custom_routes")


def _check_server(server):
    if not isinstance(server, dict):
        _bad("server is not an object")
    for key in ("endpoint", "ifname", "wan_iface", "backend", "firewall", "private_key", "public_key"):
        value = server.get(key)
        if value is not None and not isinstance(value, str):
            _bad("server." + key)
    ifname = server.get("ifname")
    if ifname is not None and not IFNAME_RE.match(ifname):
        _bad("server.ifname")
    backend = server.get("backend")
    if backend is not None and backend not in _BACKENDS:
        _bad("server.backend")
    firewall = server.get("firewall")
    if firewall is not None and firewall not in _FIREWALLS:
        _bad("server.firewall")
    for key in ("port", "mtu"):
        value = server.get(key)
        if value is not None and not _is_int(value):
            _bad("server." + key)
    if _is_int(server.get("port")) and not 1 <= server["port"] <= 65535:
        _bad("server.port range")
    if _is_int(server.get("mtu")) and not 1280 <= server["mtu"] <= 9000:
        _bad("server.mtu range")
    original = server.get("sysctl_original")
    if original is not None and not isinstance(original, dict):
        _bad("server.sysctl_original")


def validate_state(data):
    """Reject structurally invalid state before any command touches it."""
    if not isinstance(data, dict):
        _bad("state root is not an object")
    version = data.get("schema_version", SCHEMA_VERSION)
    if not _is_int(version) or version > SCHEMA_VERSION or version < 1:
        raise ValueError(t("err_state_schema").format(version=version, expected=SCHEMA_VERSION))
    server = data.get("server", {})
    if not isinstance(server, dict):
        _bad("server is not an object")
    _check_server(server)
    for section in ("ipv4", "ipv6"):
        value = data.get(section, {})
        if not isinstance(value, dict):
            _bad(section + " is not an object")
    ipv6_mode = data.get("ipv6", {}).get("mode")
    if ipv6_mode is not None and ipv6_mode not in _IPV6_MODES:
        _bad("ipv6.mode")
    for section in ("pools_v4", "pools_v6", "peers"):
        value = data.get(section, [])
        if not isinstance(value, list):
            _bad(section + " is not a list")
    for index, peer in enumerate(data.get("peers", [])):
        _check_peer(peer, index)
    return True


def migrate_state(data):
    """Apply schema migrations and stamp the current version."""
    if not isinstance(data, dict):
        _bad("state root is not an object")
    version = data.get("schema_version")
    if version is None:
        version = 0
    if not _is_int(version) or version > SCHEMA_VERSION:
        raise ValueError(t("err_state_schema").format(version=version, expected=SCHEMA_VERSION))
    while version < SCHEMA_VERSION:
        migration = MIGRATIONS.get(version)
        if migration is not None:
            data = migration(data)
        version += 1
        data["schema_version"] = version
    return data


# ---------------------------------------------------------------- state
def state_path():
    raw = os.environ.get("WG_MANAGER_STATE", DEFAULT_STATE_PATH)
    p = Path(str(raw)).expanduser()
    if not p.is_absolute():
        raise ValueError(t("err_state_path").format(path=raw))
    if ".." in p.parts:
        raise ValueError(t("err_state_path").format(path=raw))
    return p


def state_dir():
    return state_path().parent


def default_state():
    return {
        "schema_version": SCHEMA_VERSION,
        "server": {
            "endpoint": "vpn.example.com",
            "port": 51820,
            "mtu": 1420,
            "ifname": "wg0",
            "backend": "networkd",
            "wan_iface": "eth0",
        },
        "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
        "ipv6": {"mode": "disabled", "prefix": "", "hub": "", "wan_v6": ""},
        "pools_v4": [{"name": "clients", "range": "10.90.90.0/24", "kind": "next-free"}],
        "pools_v6": [],
        "peers": [],
    }


def load_state():
    p = state_path()
    if not p.exists():
        raise FileNotFoundError(t("err_state_missing").format(path=str(p)))
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(t("err_state_corrupt").format(detail=exc))
    if not isinstance(data, dict):
        raise ValueError(t("err_state_corrupt").format(detail="not a dict"))  # noqa: TRY004
    data = migrate_state(data)
    data.setdefault("server", {})
    data.setdefault("ipv4", {})
    data.setdefault("ipv6", {})
    data.setdefault("pools_v4", [])
    data.setdefault("pools_v6", [])
    data.setdefault("peers", [])
    # Audit fix: N10/N13 - reject wrong shapes and bad field types instead of
    # crashing later during status/check.
    validate_state(data)
    return data


def _mkdir_private(path):
    """Audit fix: N14 - private directories (0700) for state and secrets."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass


def atomic_write(path, content, mode=0o600, gid=None):
    """Audit fix: A3/N5 - O_EXCL+0600 tmp (random name), no symlink follow.

    Parent dirs are created with default perms: system dirs under /etc must not
    be tightened here; private dirs are handled explicitly where they are owned.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / (path.name + "." + secrets.token_hex(8) + ".tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(tmp), flags, mode)
    try:
        if gid is not None:
            try:
                os.fchown(fd, -1, gid)
            except OSError:
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
    except OSError:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    try:
        dfd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    if gid is not None:
        try:
            os.chown(str(path), -1, gid)
        except OSError:
            pass


def _rotate_backups(bdir, pattern, keep=20):
    """Audit fix: A8 - shared rotation for state-* and sys-* artifacts."""
    try:
        items = sorted(Path(bdir).glob(pattern))
    except OSError:
        return
    for old in items[:-keep]:
        try:
            old.unlink()
        except OSError:
            pass


def backup_state_file():
    """Copy current state to backups/state-<ts>.json, keep 20, chmod 0600."""
    p = state_path()
    if not p.exists():
        return None
    bdir = state_dir() / "backups"
    _mkdir_private(bdir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    dest = bdir / ("state-" + stamp + "-" + secrets.token_hex(4) + ".json")
    shutil.copy2(str(p), str(dest))
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    _rotate_backups(bdir, "state-*.json", 20)
    return dest


@contextlib.contextmanager
def state_lock(timeout=30.0):
    """Exclusive flock around state read-modify-write, with a bounded wait.

    The lock is taken with LOCK_NB in a retry loop so a stuck holder surfaces
    as a localized error instead of hanging forever.
    """
    lock_path = state_dir() / "state.lock"
    _mkdir_private(state_dir())
    with open(str(lock_path), "a+", encoding="utf-8") as fh:
        if fcntl is not None:
            deadline = time.monotonic() + max(0.0, float(timeout))
            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ValueError(t("err_lock_timeout"))
                    time.sleep(0.1)
        try:
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass


@contextlib.contextmanager
def locked_state(default_if_missing=False):
    """Lock + freshly loaded state, so RMW cycles never race on stale reads."""
    with state_lock():
        try:
            data = load_state()
        except FileNotFoundError:
            if not default_if_missing:
                raise
            data = default_state()
        yield data


def save_state(state):
    backup_state_file()
    payload = json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    atomic_write(state_path(), payload, mode=0o600)


def _audit_clean(value):
    """Audit fix: N12 - keep audit.log one record per line (no log forging)."""
    return re.sub(r"[\r\n\x00]+", " ", str(value))


AUDIT_MAX_BYTES = 1024 * 1024


def audit(action, detail=""):
    try:
        p = state_dir() / "audit.log"
        _mkdir_private(p.parent)
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        line = datetime.now(timezone.utc).isoformat() + " user=" + _audit_clean(user) + " action=" + _audit_clean(action) + " " + _audit_clean(detail) + "\n"
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(line)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        # Bound growth: rotate to audit.log.1 once the current file is too big.
        try:
            if p.stat().st_size > AUDIT_MAX_BYTES:
                rotated = p.parent / "audit.log.1"
                os.replace(str(p), str(rotated))
                try:
                    os.chmod(rotated, 0o600)
                except OSError:
                    pass
        except OSError:
            pass
    except OSError:
        pass


def list_backups():
    bdir = state_dir() / "backups"
    if not bdir.exists():
        return []
    return sorted(list(bdir.glob("state-*.json")) + list(bdir.glob("manual-*.json")))
def load_state_or_default(args):
    """Dry-run without state renders against defaults; --apply still requires state."""
    try:
        return load_state()
    except FileNotFoundError:
        if getattr(args, "apply", False):
            raise
        return default_state()


def _is_initialized():
    """True when a valid state file already exists (init is first-time-only)."""
    try:
        p = state_path()
    except (OSError, ValueError):
        return False
    try:
        if not p.exists():
            return False
    except OSError:
        return False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return "schema_version" in data


def remove_state_data():
    """Remove all state files, rendered configs, backups, and state directory."""
    sdir = state_dir()
    if not sdir.exists():
        return True
    try:
        resolved = sdir.resolve()
    except OSError:
        resolved = sdir
    if str(resolved) in ("/", "/etc", "/usr", "/var", "/home", "/root", "/tmp"):
        for target in ("state.json", "state.lock", "audit.log"):
            p = sdir / target
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
        for sub in ("rendered", "backups"):
            p = sdir / sub
            if p.is_dir():
                try:
                    shutil.rmtree(str(p))
                except OSError:
                    pass
        return True
    try:
        shutil.rmtree(str(sdir))
        return True
    except OSError as exc:
        eprint(str(exc))
        return False



