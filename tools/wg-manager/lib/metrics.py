# metrics.py
"""Prometheus textfile metrics derived from the live state (read-only)."""
from .ipam import peers_sorted
from .renderers import _is_active_peer, _peer_is_expired
from .system import get_wg_live_dump


def _escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def collect_metrics(state, now=None):
    """Return a list of (name, labels, value) metric samples.

    Labels are (key, value) tuples; values are ints/floats. Pure apart from the
    single `wg show` read inside get_wg_live_dump(), which is best-effort.
    """
    import time as _time
    if now is None:
        now = int(_time.time())
    srv = state.get("server", {}) if isinstance(state, dict) else {}
    ifname = str(srv.get("ifname", "wg0") or "wg0")
    peers = peers_sorted(state.get("peers", []) if isinstance(state, dict) else [])
    dump = get_wg_live_dump(ifname)
    samples = []

    active = [p for p in peers if _is_active_peer(p)]
    online = 0
    expiring = 0
    for peer in peers:
        if peer.get("tombstoned") or not peer.get("enabled", True):
            continue
        exp = peer.get("expires_at")
        if exp is not None:
            try:
                if int(exp) > now and int(exp) - now <= 7 * 86400:
                    expiring += 1
            except (TypeError, ValueError):
                pass

    samples.append(("wg_manager_interface_present", [], 1 if dump else 0))
    samples.append(("wg_manager_peers_total", [], len(peers)))
    samples.append(("wg_manager_peers_active", [], len(active)))
    samples.append(("wg_manager_peers_expiring_7d", [], expiring))

    for peer in peers:
        name = _escape(peer.get("name", "?"))
        labels = [("peer", name)]
        pub = peer.get("pubkey", "")
        live = dump.get(pub, {}) if pub else {}
        hs = int(live.get("handshake", 0) or 0)
        age = max(0, now - hs) if hs else 0
        if hs and (now - hs) < 180:
            online += 1
        samples.append(("wg_manager_peer_handshake_age_seconds", labels, age))
        samples.append(("wg_manager_peer_rx_bytes_total", labels, int(live.get("rx", 0) or 0)))
        samples.append(("wg_manager_peer_tx_bytes_total", labels, int(live.get("tx", 0) or 0)))
        samples.append(("wg_manager_peer_enabled", labels, 1 if peer.get("enabled", True) else 0))
        # `expired` is a helper for alerting; `active` excludes tombstones.
        samples.append(("wg_manager_peer_expired", labels, 1 if _peer_is_expired(peer) else 0))
    samples.append(("wg_manager_peers_online", [], online))
    return samples


def render_prometheus(samples, version="1.0.0"):
    """Render samples as Prometheus text exposition format, with HELP/TYPE lines."""
    types = {}
    for name, _labels, _value in samples:
        if name.endswith("_total"):
            types.setdefault(name, "counter")
        else:
            types.setdefault(name, "gauge")
    lines = ["# wg-manager " + str(version) + " metrics"]
    for name in sorted(types):
        lines.append("# HELP " + name + " wg-manager metric")
        lines.append("# TYPE " + name + " " + types[name])
        for sample_name, labels, value in samples:
            if sample_name != name:
                continue
            if labels:
                label_text = ",".join(k + '="' + str(v) + '"' for k, v in labels)
                lines.append(name + "{" + label_text + "} " + str(value))
            else:
                lines.append(name + " " + str(value))
    return "\n".join(lines) + "\n"
