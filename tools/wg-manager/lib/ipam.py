# ipam.py
import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

from .i18n import t


# ---------------------------------------------------------------- IPAM
class IPAMError(Exception):
    pass


def peer_sort_key(peer):
    role = peer.get("role", "client")
    kind = peer.get("kind", "ondemand")
    if role == "infra" and kind == "permanent":
        rank = 0
    elif kind == "permanent":
        rank = 1
    else:
        rank = 2
    v4 = peer.get("v4") or ""
    try:
        off = int(ipaddress.ip_address(v4.split("/")[0])) if v4 else 2 ** 128
    except ValueError:
        off = 2 ** 128
    return (rank, off, peer.get("name", ""))


def peers_sorted(peers):
    return sorted(peers, key=peer_sort_key)


class PoolRange:
    """Normalized pool range: legacy CIDR or start-end host span."""
    def __init__(self, kind, version, network=None, start=None, end=None, raw=""):
        self.kind = kind  # "cidr" or "span"
        self.version = version
        self.network = network
        self.start = start
        self.end = end
        self.raw = raw
    def candidates(self):
        """Yield candidate host addresses in allocation order."""
        if self.kind == "cidr":
            assert self.network is not None
            yield from self.network.hosts()
            return
        lo = int(self.start)
        hi = int(self.end)
        for num in range(lo, hi + 1):
            yield ipaddress.ip_address(num)
    def __iter__(self):
        return iter(self.candidates())
    def contains(self, addr):
        """True when addr belongs to this range."""
        try:
            ip = addr if isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(addr).split("/")[0].strip())
        except ValueError:
            return False
        if ip.version != self.version:
            return False
        if self.kind == "cidr":
            assert self.network is not None
            try:
                return ip in self.network
            except TypeError:
                return False
        return int(self.start) <= int(ip) <= int(self.end)
    def __contains__(self, addr):
        return self.contains(addr)
    def bounds(self):
        """Return (lo, hi) integer bounds for overlap checks."""
        if self.kind == "cidr":
            assert self.network is not None
            lo = int(self.network.network_address)
            if self.network.version == 4:
                hi = int(self.network.broadcast_address)
            else:
                hi = int(self.network.network_address) + int(self.network.num_addresses) - 1
            return (lo, hi)
        return (int(self.start), int(self.end))


def parse_pool_range(range_str, version=None):
    """Parse pool range in CIDR legacy form or start-end span form."""
    s = str(range_str or "").strip()
    if not s:
        raise ValueError("invalid pool range: empty")
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise ValueError("invalid pool range: " + s)
        if version is not None and net.version != int(version):
            raise ValueError("invalid pool range version: " + s)
        if net.version == 4:
            start = net.network_address
            end = net.broadcast_address
        else:
            start = net.network_address
            end = net.network_address + (int(net.num_addresses) - 1)
        return PoolRange("cidr", net.version, network=net, start=start, end=end, raw=s)
    if "-" in s:
        left, _, right = s.partition("-")
        left = left.strip()
        right = right.strip()
        if not left or not right:
            raise ValueError("invalid pool range: " + s)
        try:
            start = ipaddress.ip_address(left)
        except ValueError:
            raise ValueError("invalid pool range: " + s)
        if "." not in right and ":" not in right:
            # Short suffix form: "10.90.90.10-20" expands with start prefix.
            if start.version != 4 or "." not in left:
                raise ValueError("invalid pool range: " + s)
            prefix = left.rsplit(".", 1)[0]
            try:
                end = ipaddress.ip_address(prefix + "." + right)
            except ValueError:
                raise ValueError("invalid pool range: " + s)
        else:
            try:
                end = ipaddress.ip_address(right)
            except ValueError:
                raise ValueError("invalid pool range: " + s)
        if start.version != end.version:
            raise ValueError("invalid pool range version mismatch: " + s)
        if version is not None and start.version != int(version):
            raise ValueError("invalid pool range version: " + s)
        if int(end) < int(start):
            raise ValueError("invalid pool range start > end: " + s)
        return PoolRange("span", start.version, start=start, end=end, raw=s)
    raise ValueError("invalid pool range: " + s)


def pool_ranges_overlap(a_str, b_str, version=None):
    """True when two pool range strings share at least one address."""
    try:
        first = parse_pool_range(a_str, version)
        second = parse_pool_range(b_str, version)
    except ValueError:
        return False
    if first.version != second.version:
        return False
    alo, ahi = first.bounds()
    blo, bhi = second.bounds()
    return max(alo, blo) <= min(ahi, bhi)


def default_pool_span(prefix_str, hub_str="", start_offset=10, end_offset=20):
    """Derive a start-end default span from offsets, clamped to usable hosts."""
    try:
        net = ipaddress.ip_network(str(prefix_str), strict=False)
    except ValueError:
        return ""
    hub = None
    if hub_str:
        try:
            hub = ipaddress.ip_address(str(hub_str).split("/")[0].strip())
        except ValueError:
            hub = None
    if net.version == 4:
        first_usable = int(net.network_address) + 1
        last_usable = int(net.broadcast_address) - 1
    else:
        first_usable = int(net.network_address) + 1
        last_usable = int(net.network_address) + int(net.num_addresses) - 1
    if last_usable < first_usable:
        return ""
    lo = max(int(net.network_address) + int(start_offset), first_usable)
    hi = min(int(net.network_address) + int(end_offset), last_usable)
    if hub is not None and hub.version == net.version:
        h = int(hub)
        if lo <= h <= hi:
            if h + 1 <= hi:
                lo = h + 1
            else:
                hi = h - 1
    if lo > hi:
        cand = first_usable
        while cand <= last_usable:
            if hub is None or cand != int(hub):
                return str(ipaddress.ip_address(cand)) + "-" + str(ipaddress.ip_address(cand))
            cand += 1
        return ""
    if hub is not None and hub.version == net.version:
        h = int(hub)
        if lo <= h <= hi:
            return ""
    return str(ipaddress.ip_address(lo)) + "-" + str(ipaddress.ip_address(hi))


def suggest_pool_spans(prefix_str, hub_str=""):
    """Return (infra_span, clients_span) defaults, non-overlapping."""
    try:
        net = ipaddress.ip_network(str(prefix_str), strict=False)
    except ValueError:
        return ("", "")
    # Large prefixes use offset convention: infra 10-20, clients 21-150.
    if int(net.num_addresses) >= 256:
        infra = default_pool_span(prefix_str, hub_str, 10, 20)
        clients = default_pool_span(prefix_str, hub_str, 21, 150)
        if infra and clients and not pool_ranges_overlap(infra, clients, net.version):
            return (infra, clients)
    # Small prefix fallback: split usable hosts.
    hub = None
    if hub_str:
        try:
            hub = ipaddress.ip_address(str(hub_str).split("/")[0].strip())
        except ValueError:
            hub = None
    try:
        usable = [a for a in net.hosts() if hub is None or a != hub]
    except ValueError:
        usable = []
    if not usable:
        return ("", "")
    if len(usable) == 1:
        single = str(usable[0]) + "-" + str(usable[0])
        return (single, single)
    infra = str(usable[0]) + "-" + str(usable[0])
    clients = str(usable[1]) + "-" + str(usable[-1])
    return (infra, clients)


def validate_pool_input(raw, tunnel_prefix, hub_ip, pool_name, version):
    """Validate wizard pool input; return normalized range string."""
    s = str(raw or "").strip()
    if version == 6 and not s:
        return ""
    if not s:
        raise ValueError(t("err_invalid_prefix").format(value=raw))
    try:
        tnet = ipaddress.ip_network(str(tunnel_prefix), strict=False)
    except ValueError:
        raise ValueError(t("err_invalid_prefix").format(value=tunnel_prefix))
    if "-" in s:
        p1, _, p2 = s.partition("-")
        p1 = p1.strip()
        p2 = p2.strip()
        if p1.isdigit() and p2.isdigit():
            v1, v2 = int(p1), int(p2)
            s = str(tnet.network_address + v1) + "-" + str(tnet.network_address + v2)
    try:
        parsed = parse_pool_range(s, version)
    except ValueError:
        raise ValueError(t("err_invalid_prefix").format(value=raw))
    if parsed.version != tnet.version:
        raise ValueError(t("err_invalid_prefix").format(value=raw))
    hub = None
    if hub_ip:
        try:
            hub = ipaddress.ip_address(str(hub_ip).split("/")[0].strip())
        except ValueError:
            hub = None
    if parsed.kind == "cidr":
        pnet = parsed.network
        assert pnet is not None
        try:
            inside = pnet.subnet_of(tnet)
        except AttributeError:
            if pnet.version == 4:
                plo, phi = int(pnet.network_address), int(pnet.broadcast_address)
                tlo, thi = int(tnet.network_address), int(tnet.broadcast_address)
            else:
                plo = int(pnet.network_address)
                phi = int(pnet.network_address) + int(pnet.num_addresses) - 1
                tlo = int(tnet.network_address)
                thi = int(tnet.network_address) + int(tnet.num_addresses) - 1
            inside = plo >= tlo and phi <= thi
        if not inside:
            raise ValueError(t("err_invalid_prefix").format(value=raw))
        if pnet.network_address == tnet.network_address and pnet.prefixlen == tnet.prefixlen:
            raise ValueError(t("err_invalid_prefix").format(value=raw))
        usable = 0
        for cand in pnet.hosts():
            if hub is not None and cand == hub:
                continue
            usable += 1
            break
        if usable == 0:
            raise ValueError(t("err_pool_empty").format(pool=pool_name))
        return str(pnet)
    start, end = parsed.start, parsed.end
    assert start is not None and end is not None
    if start not in tnet or end not in tnet:
        raise ValueError(t("err_invalid_prefix").format(value=raw))
    if parsed.version == 4:
        if start == tnet.network_address or end == tnet.network_address:
            raise ValueError(t("err_invalid_prefix").format(value=raw))
        if start == tnet.broadcast_address or end == tnet.broadcast_address:
            raise ValueError(t("err_invalid_prefix").format(value=raw))
    else:
        if start == tnet.network_address or end == tnet.network_address:
            raise ValueError(t("err_invalid_prefix").format(value=raw))
    if hub is not None and hub.version == parsed.version and int(start) <= int(hub) <= int(end):
        raise ValueError(t("err_invalid_prefix").format(value=raw))
    if int(end) < int(start):
        raise ValueError(t("err_pool_empty").format(pool=pool_name))
    return str(start) + "-" + str(end)


def _used_sets(state_or_peers, pool_range):
    if isinstance(state_or_peers, dict):
        peers = state_or_peers.get("peers", [])
    else:
        peers = state_or_peers
    try:
        parsed = parse_pool_range(pool_range)
    except ValueError:
        return set(), set(), 0, 0
    used = set()
    tomb = 0
    for peer in peers:
        for field in ("v4", "v6"):
            raw = (peer.get(field) or "").strip()
            if not raw:
                continue
            ip_txt = raw.split("/")[0].strip()
            try:
                addr = ipaddress.ip_address(ip_txt)
            except ValueError:
                continue
            if addr.version != parsed.version:
                continue
            try:
                if parsed.contains(addr):
                    used.add(str(addr))
                    if peer.get("tombstoned"):
                        tomb += 1
                        break
            except TypeError:
                continue
    active_used = len([u for u in used])
    return used, parsed, active_used, tomb


def next_free_ip(pool_range, peers, hub_ip="", exclude=None):
    """Lowest free address within CIDR hosts() or start-end span."""
    parsed = parse_pool_range(pool_range)
    used = set()
    for peer in peers:
        for field in ("v4", "v6"):
            raw = (peer.get(field) or "").strip()
            if not raw:
                continue
            ip_txt = raw.split("/")[0].strip()
            try:
                addr = ipaddress.ip_address(ip_txt)
            except ValueError:
                continue
            if addr.version == parsed.version and parsed.contains(addr):
                used.add(addr)
    if exclude:
        for item in exclude:
            try:
                used.add(ipaddress.ip_address(str(item).split("/")[0]))
            except ValueError:
                pass
    hub = None
    if hub_ip:
        try:
            hub = ipaddress.ip_address(str(hub_ip).split("/")[0])
        except ValueError:
            hub = None
    if parsed.kind == "span":
        assert parsed.start is not None and parsed.end is not None
        for num in range(int(parsed.start), int(parsed.end) + 1):
            addr = ipaddress.ip_address(num)
            if hub is not None and addr == hub:
                continue
            if addr in used:
                continue
            return str(addr)
        return None
    net = parsed.network
    assert net is not None
    for addr in net.hosts():
        # Never allocate network/broadcast/hub addresses.
        if hub is not None and addr == hub:
            continue
        if net.version == 6 and hub is None and addr == net.network_address + 1:
            continue
        if addr in used:
            continue
        return str(addr)
    # Fallback for /31, /127 or tiny nets where hosts() is empty.
    for addr in net:
        if addr == net.network_address:
            continue
        if net.version == 4 and addr == net.broadcast_address:
            continue
        if hub is not None and addr == hub:
            continue
        if addr in used:
            continue
        return str(addr)
    return None


def allocate_static(pool_range, peers, wanted_ip, hub_ip=""):
    parsed = parse_pool_range(pool_range)
    addr = ipaddress.ip_address(str(wanted_ip).split("/")[0].strip())
    if parsed.kind == "span":
        assert parsed.start is not None and parsed.end is not None
        if not parsed.contains(addr):
            raise IPAMError("wanted IP outside pool range")
        if hub_ip:
            hub = ipaddress.ip_address(str(hub_ip).split("/")[0])
            if addr == hub:
                raise IPAMError("cannot allocate hub address")
        for peer in peers:
            for field in ("v4", "v6"):
                raw = (peer.get(field) or "").strip()
                if not raw:
                    continue
                try:
                    other = ipaddress.ip_address(raw.split("/")[0].strip())
                except ValueError:
                    continue
                if other == addr:
                    raise IPAMError("address already used (active or tombstoned)")
        return str(addr)
    net = parsed.network
    assert net is not None
    if addr not in net:
        raise IPAMError("wanted IP outside pool range")
    if addr == net.network_address:
        raise IPAMError("cannot allocate network address")
    if net.version == 4 and addr == net.broadcast_address:
        raise IPAMError("cannot allocate broadcast address")
    if hub_ip:
        hub = ipaddress.ip_address(str(hub_ip).split("/")[0])
        if addr == hub:
            raise IPAMError("cannot allocate hub address")
    for peer in peers:
        for field in ("v4", "v6"):
            raw = (peer.get(field) or "").strip()
            if not raw:
                continue
            try:
                other = ipaddress.ip_address(raw.split("/")[0].strip())
            except ValueError:
                continue
            if other == addr:
                raise IPAMError("address already used (active or tombstoned)")
    return str(addr)


def exhaustion_message(pool, pool_range, peers):
    used = 0
    tomb = 0
    try:
        parsed = parse_pool_range(pool_range)
    except ValueError:
        parsed = None
    for peer in peers:
        for field in ("v4", "v6"):
            raw = (peer.get(field) or "").strip()
            if not raw:
                continue
            try:
                addr = ipaddress.ip_address(raw.split("/")[0].strip())
            except ValueError:
                continue
            if parsed is not None and not parsed.contains(addr):
                continue
            used += 1
            if peer.get("tombstoned"):
                tomb += 1
            break
    return t("err_exhaustion").format(pool=pool, range=pool_range, used=used, tombstoned=tomb)


def _parse_prefix_list(output, exclude_dev=None):
    found = []
    excludes = set(exclude_dev or [])
    for line in str(output).splitlines():
        tokens = line.replace(",", " ").split()
        if "dev" in tokens:
            idx = tokens.index("dev")
            if idx + 1 < len(tokens):
                dev = tokens[idx + 1]
                if dev in excludes or dev.startswith("wg") or dev in ("lo",):
                    continue
        for tok in tokens:
            if "/" in tok:
                cand = tok.strip().strip(",;")
                try:
                    found.append(str(ipaddress.ip_network(cand, strict=False)))
                except ValueError:
                    continue
    return found


def system_routes_txt():
    """Best-effort `ip route` output, empty string offline."""
    exe = shutil.which("ip")
    if not exe:
        return "", ""
    try:
        v4 = subprocess.run([exe, "route", "show"], capture_output=True, text=True, timeout=5, check=False)
        out4 = v4.stdout if v4.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        out4 = ""
    try:
        v6 = subprocess.run([exe, "-6", "route", "show"], capture_output=True, text=True, timeout=5, check=False)
        out6 = v6.stdout if v6.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        out6 = ""
    return out4, out6


def check_wan_overlap(prefix, route_outputs=None, ifname="wg0"):
    """Pure overlap check; route_outputs is list of prefix strings."""
    net = ipaddress.ip_network(prefix, strict=False)
    if route_outputs is None:
        out4, out6 = system_routes_txt()
        route_outputs = _parse_prefix_list(out4, [ifname]) + _parse_prefix_list(out6, [ifname])
    for route in route_outputs:
        try:
            other = ipaddress.ip_network(route, strict=False)
        except ValueError:
            continue
        if other.version != net.version:
            continue
        if net.overlaps(other):
            # Ignore default routes and host routes; only real LAN prefixes matter.
            if str(other) in ("0.0.0.0/0", "::/0"):
                continue
            if other.prefixlen in (32, 128):
                continue
            return str(other)
    return None


def check_wan_v6_onlink(prefix, wan_prefixes):
    """Return overlapping WAN on-link prefix or None (pure helper)."""
    net = ipaddress.ip_network(prefix, strict=False)
    for wan in wan_prefixes:
        try:
            other = ipaddress.ip_network(wan, strict=False)
        except ValueError:
            continue
        if other.version != 6 or net.version != 6:
            continue
        if net.overlaps(other):
            return str(other)
    return None


def wan_v6_prefixes_best_effort():
    exe = shutil.which("ip")
    if not exe:
        return []
    try:
        proc = subprocess.run([exe, "-6", "addr", "show"], capture_output=True, text=True, timeout=5, check=False)
        out = proc.stdout if proc.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return []
    prefixes = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet6"):
            parts = line.split()
            if len(parts) >= 2 and "/" in parts[1]:
                try:
                    prefixes.append(str(ipaddress.ip_network(parts[1], strict=False)))
                except ValueError:
                    continue
    return prefixes


def _parse_wan_iface(text):
    """Pure parser for `ip route show default` output; return iface or None."""
    try:
        blob = str(text or "")
    except Exception:  # noqa: BLE001
        return None
    if not blob.strip():
        return None
    # Only consider default-route lines; return the first dev token found.
    for line in blob.splitlines():
        stripped = line.strip()
        if not stripped or "default" not in stripped:
            continue
        match = re.search(r"\bdev\s+([^\s;,]+)", stripped)
        if match:
            name = match.group(1).strip().strip(",;")
            if name:
                return name
    return None


def detect_wan_iface():
    """Best-effort WAN interface detection; never raises, never writes."""
    # Primary source: default route via `ip route show default`.
    try:
        exe = shutil.which("ip")
        if exe:
            try:
                proc = subprocess.run(
                    [exe, "route", "show", "default"], capture_output=True, text=True, timeout=5, check=False
                )
                if proc.returncode == 0 and proc.stdout:
                    iface = _parse_wan_iface(proc.stdout)
                    if iface:
                        return iface
            except (OSError, subprocess.SubprocessError):
                pass
    except Exception:  # noqa: BLE001, S110
        pass
    # Fallback: list local interfaces, prefer common WAN names.
    try:
        netdir = Path("/sys/class/net")
        if not netdir.is_dir():
            return None
        try:
            entries = [p.name for p in netdir.iterdir() if p.name != "lo"]
        except OSError:
            return None
        cands = sorted([e for e in entries if e and str(e).strip()])
        if not cands:
            return None
        prefixes = ("eth", "en", "ens", "enp", "wlan", "wlp", "wan")
        preferred = sorted([n for n in cands if n.startswith(prefixes)])
        if preferred:
            return preferred[0]
        return cands[0]
    except Exception:  # noqa: BLE001
        return None



def find_pool(state, pool_name, version):
    for pool in state.get("pools_v4" if version == 4 else "pools_v6", []):
        if pool.get("name") == pool_name:
            return pool
    return None
def default_pool(state, version):
    pools = state.get("pools_v4" if version == 4 else "pools_v6", [])
    for pool in pools:
        if pool.get("name") == "clients":
            return pool
    return pools[0] if pools else None
def kind_to_role_kind(kind):
    k = str(kind).strip().lower()
    if k in ("infra", "router", "server", "permanent", "static", "servidor", "mikrotik", "mtk"):
        return "infra", "permanent"
    if k in ("client", "ondemand", "ondemand-client", "cliente", "usuario"):
        return "client", "ondemand"
    raise ValueError(t("err_invalid_kind").format(value=kind))


