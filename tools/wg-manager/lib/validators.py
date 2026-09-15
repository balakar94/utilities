# validators.py
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from .constants import IFNAME_RE, NAME_RE
from .i18n import t
from .presentation import eprint


# ---------------------------------------------------------------- validators
def validate_name(name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ValueError(t("err_invalid_name"))
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError(t("err_path_traversal").format(value=name))
    return name


def _int_range(value, lo, hi, key):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(t(key).format(value=value))
    if not lo <= n <= hi:
        raise ValueError(t(key).format(value=value))
    return n
def validate_port(value):
    return _int_range(value, 1, 65535, "err_invalid_port")
def validate_mtu(value):
    return _int_range(value, 1280, 1420, "err_invalid_mtu")
def validate_keepalive(value):
    return _int_range(value, 0, 120, "err_invalid_keepalive")


def validate_prefix(value):
    try:
        net = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        raise ValueError(t("err_invalid_prefix").format(value=value))
    return str(net)


def validate_ip(value):
    try:
        addr = ipaddress.ip_address(str(value).split("/")[0].strip())
    except ValueError:
        raise ValueError(t("err_invalid_ip").format(value=value))
    return str(addr)


def validate_endpoint(value):
    s = str(value)
    if not s.strip() or "\n" in s or "\r" in s:
        raise ValueError(t("err_invalid_endpoint"))
    return s.strip()


def validate_traffic(value):
    if value not in ("server-only", "custom-routes", "full-tunnel"):
        raise ValueError(t("err_invalid_traffic").format(value=value))
    return value


def validate_backend(value):
    if value not in ("networkd", "nm"):
        raise ValueError(t("err_invalid_backend").format(value=value))
    return value


def validate_ipv6_mode(value):
    if value not in ("disabled", "ula", "routed", "nat66"):
        raise ValueError(t("err_invalid_mode").format(value=value))
    return value


def validate_safe_path(value):
    s = str(value)
    if ".." in s or "\n" in s or "\r" in s or "\x00" in s:
        raise ValueError(t("err_path_traversal").format(value=value))
    return s


def validate_ifname(value):
    """Audit fix: C4 - strict Linux interface name, safe in nft/sysctl keys."""
    s = str(value)
    if not IFNAME_RE.match(s):
        raise ValueError(t("err_invalid_ifname").format(value=value))
    return s


def validate_expiry(value):
    """Parse expiry string (7d, 30d, 24h, 3600s, YYYY-MM-DD) to epoch integer."""
    if not value:
        return None
    s = str(value).strip().lower()
    if not s or s in ("none", "never"):
        return None
    now = int(datetime.now(timezone.utc).timestamp())
    m = re.match(r"^(\d+)([smhdw])?$", s)
    if m:
        num = int(m.group(1))
        unit = m.group(2) or "d"
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}.get(unit, 86400)
        return now + (num * mult)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", s)
    if m:
        try:
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), 23, 59, 59, tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            raise ValueError(t("err_invalid_expires").format(value=value))
    raise ValueError(t("err_invalid_expires").format(value=value))



def parse_routes_csv(raw):
    if not raw:
        return []
    out = []
    for part in str(raw).split(","):
        p = part.strip()
        if not p:
            continue
        validate_prefix(p)
        out.append(str(ipaddress.ip_network(p, strict=False)))
    return out


def validate_routes_for_role(routes, role):
    """Audit fix: N9 - a default route may only be advertised by infra peers."""
    for route in routes:
        if str(route) in ("0.0.0.0/0", "::/0") and role != "infra":
            raise ValueError(t("err_route_default_role").format(route=route))
    return routes


def parse_set_pairs(items):
    """Audit fix: A6 - parse repeated --set key=value into a dict."""
    out = {}
    for raw in items or []:
        if "=" not in str(raw):
            raise ValueError("invalid --set (expected key=value): " + str(raw))
        key, _, val = str(raw).partition("=")
        key = key.strip()
        if not key or "/" in key or ".." in key:
            raise ValueError("invalid --set key: " + key)
        out[key] = val.strip()
    return out



def nft_structural_ok(content):
    """Audit fix: N2 - offline sanity check so a missing nft is not a blind pass."""
    text = str(content)
    depth = 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    if depth != 0:
        return False
    for line in text.splitlines():
        if line.count('"') % 2 != 0:
            return False
    return True


def validate_nft_content(content):
    # Audit fix: N2 - structural check always; nft -c when the binary exists.
    if not nft_structural_ok(content):
        eprint("nft structural validation failed")
        return False
    exe = shutil.which("nft")
    if not exe:
        print(t("msg_nft_skip"))
        return True
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
        fh.write(content)
        tmp = fh.name
    try:
        proc = subprocess.run([exe, "-c", "-f", tmp], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return True
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if proc.returncode != 0:
        eprint(proc.stderr.strip() or "nft validation failed")
        return False
    print(t("msg_nft_ok"))
    return True



def _prefix_is_ula(prefix):
    """True when IPv6 prefix network address is inside fd00::/8."""
    try:
        net = ipaddress.ip_network(str(prefix), strict=False)
    except ValueError:
        return False
    if net.version != 6:
        return False
    try:
        ula = ipaddress.ip_network("fd00::/8")
        return bool(net.network_address in ula)
    except (ValueError, TypeError):
        return False


def validate_reconfigure_prefix(mode, prefix):
    """Validate new IPv6 prefix for mode; raises ValueError with localized text."""
    if mode == "disabled":
        return ""
    if not str(prefix or "").strip():
        # ula/routed/nat66 need an explicit prefix.
        raise ValueError(t("err_invalid_prefix").format(value=prefix))
    canon = validate_prefix(str(prefix).strip())
    try:
        net = ipaddress.ip_network(canon, strict=False)
    except ValueError:
        raise ValueError(t("err_invalid_prefix").format(value=prefix))
    if net.version != 6:
        raise ValueError(t("err_invalid_prefix").format(value=prefix))
    is_ula = _prefix_is_ula(canon)
    if mode == "routed" and is_ula:
        raise ValueError(t("err_need_gua").format(value=canon))
    if mode in ("ula", "nat66") and not is_ula:
        raise ValueError(t("err_need_ula").format(mode=mode, value=canon))
    return canon


