# state.py
import contextlib
import json
import os
import re
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

from .constants import DEFAULT_STATE_PATH, SCHEMA_VERSION
from .i18n import t
from .presentation import eprint


# ---------------------------------------------------------------- state
def state_path():
    return Path(os.environ.get("WG_MANAGER_STATE", DEFAULT_STATE_PATH))


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
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("server", {})
    data.setdefault("ipv4", {})
    data.setdefault("ipv6", {})
    data.setdefault("pools_v4", [])
    data.setdefault("pools_v6", [])
    data.setdefault("peers", [])
    # Audit fix: N10/N13 - reject wrong shapes instead of crashing later.
    for key, typ in (("server", dict), ("ipv4", dict), ("ipv6", dict), ("pools_v4", list), ("pools_v6", list), ("peers", list)):
        if not isinstance(data.get(key), typ):
            raise ValueError(t("err_state_corrupt").format(detail="bad type for " + key))  # noqa: TRY004
    if not all(isinstance(p, dict) for p in data.get("peers", [])):
        raise ValueError(t("err_state_corrupt").format(detail="bad peer entry"))
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
def state_lock():
    """Audit fix: A4 - exclusive flock around state read-modify-write."""
    lock_path = state_dir() / "state.lock"
    _mkdir_private(state_dir())
    with open(str(lock_path), "a+", encoding="utf-8") as fh:
        if fcntl is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            except OSError:
                pass
        try:
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass


def _state_file_candidates():
    paths = []
    env = os.environ.get("WG_MANAGER_STATE")
    if env:
        paths.append(Path(env).resolve())
    paths.append(DEFAULT_STATE_PATH)
    return paths


def _load_state_silent():
    """Load state quietly; return default empty state on missing or corrupt."""
    try:
        return load_state()
    except Exception:  # noqa: BLE001
        return default_state()


def save_state(state):
    backup_state_file()
    payload = json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    atomic_write(state_path(), payload, mode=0o600)


def _audit_clean(value):
    """Audit fix: N12 - keep audit.log one record per line (no log forging)."""
    return re.sub(r"[\r\n\x00]+", " ", str(value))


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
    except OSError:
        pass


def list_backups():
    bdir = state_dir() / "backups"
    if not bdir.exists():
        return []
    return sorted(bdir.glob("state-*.json"))
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



