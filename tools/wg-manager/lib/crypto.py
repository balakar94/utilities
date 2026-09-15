# crypto.py
import base64
import secrets
import shutil
import subprocess

from .constants import WGKEY_RE
from .i18n import t
from .presentation import eprint


def _server_pubkey(state): return (state.get("server", {}) or {}).get("public_key", "")
def _server_privkey(state): return (state.get("server", {}) or {}).get("private_key", "")

# ---------------------------------------------------------------- wireguard keys
def is_valid_wgkey(value):
    """Audit fix: C1 - base64 WireGuard key shape (43 chars + '=')."""
    return isinstance(value, str) and bool(WGKEY_RE.match(value))


def _wg_bin():
    exe = shutil.which("wg")
    if not exe:
        eprint(t("err_no_wg"))
        raise SystemExit(1)
    return exe


def wggen():
    """Audit fix: C1 - generate a real Curve25519 private key via wg genkey."""
    exe = _wg_bin()
    try:
        proc = subprocess.run([exe, "genkey"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        eprint(str(exc))
        raise SystemExit(1)
    key = (proc.stdout or "").strip()
    if proc.returncode != 0 or not is_valid_wgkey(key):
        eprint(t("err_no_wg"))
        raise SystemExit(1)
    return key


def wgpub(privkey):
    """Audit fix: C1 - derive the public key via wg pubkey."""
    exe = _wg_bin()
    try:
        proc = subprocess.run(
            [exe, "pubkey"], input=str(privkey), capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        eprint(str(exc))
        raise SystemExit(1)
    key = (proc.stdout or "").strip()
    if proc.returncode != 0 or not is_valid_wgkey(key):
        eprint(t("err_no_wg"))
        raise SystemExit(1)
    return key


def wgpsk():
    """Audit fix: C1 - pre-shared key via wg genpsk, stdlib fallback."""
    exe = shutil.which("wg")
    if exe:
        try:
            proc = subprocess.run([exe, "genpsk"], capture_output=True, text=True, timeout=15, check=False)
            key = (proc.stdout or "").strip()
            if proc.returncode == 0 and is_valid_wgkey(key):
                return key
        except (OSError, subprocess.SubprocessError):
            pass
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def validate_key_material(state):
    """Audit fix: C2 - all-or-nothing precheck before any privileged write."""
    priv = _server_privkey(state)
    if not is_valid_wgkey(priv):
        raise ValueError(t("err_render_invalid_key") + " (" + t("err_invalid_wgkey").format(path="server.private_key") + ")")
    pub = _server_pubkey(state)
    if pub and not is_valid_wgkey(pub):
        raise ValueError(t("err_render_invalid_key") + " (" + t("err_invalid_wgkey").format(path="server.public_key") + ")")
    for peer in state.get("peers", []):
        if peer.get("tombstoned") or not peer.get("enabled", True):
            continue
        pk = peer.get("pubkey", "")
        if not pk or not is_valid_wgkey(pk):
            raise ValueError(t("err_invalid_wgkey").format(path="peer " + str(peer.get("name", "?"))))
    return True


