# reconcile.py
"""Pure desired-state diff: compute a plan without touching disk or the system."""

_MANAGED_PEER_FIELDS = ("traffic", "dns_scope", "keepalive", "endpoint", "enabled", "pool")


def _change(action, resource, name, field=None, old=None, new=None):
    return {"action": action, "resource": resource, "name": name,
            "field": field, "old": old, "new": new}


def _scalar_changes(resource, name, current, desired, fields):
    out = []
    for field in fields:
        if field not in desired:
            continue
        old = current.get(field)
        new = desired[field]
        if old != new:
            out.append(_change("update", resource, name, field, old, new))
    return out


def _peer_changes(current, desired):
    out = []
    for field in _MANAGED_PEER_FIELDS:
        if field in desired and desired[field] != current.get(field):
            out.append(_change("update", "peer", desired["name"], field, current.get(field), desired[field]))
    if "custom_routes" in desired:
        old_routes = current.get("custom_routes") or []
        if desired["custom_routes"] != old_routes:
            out.append(_change("update", "peer", desired["name"], "custom_routes", old_routes, desired["custom_routes"]))
    if "pubkey" in desired and desired["pubkey"] != current.get("pubkey"):
        out.append(_change("update", "peer", desired["name"], "pubkey", "<redacted>", "<redacted>"))
    if "expires" in desired and desired["expires"] != current.get("expires_spec"):
        out.append(_change("update", "peer", desired["name"], "expires", current.get("expires_spec"), desired["expires"]))
    if desired.get("no_psk") and current.get("psk"):
        out.append(_change("update", "peer", desired["name"], "psk", "<redacted>", None))
    return out


def compute_plan(current, desired, prune=False):
    """Return the ordered list of changes to converge `current` to `desired`."""
    changes = []
    changes.extend(_scalar_changes("server", "server", current.get("server", {}), desired["server"],
                                   ("endpoint", "port", "mtu", "ifname", "backend", "firewall", "wan_iface", "dns")))
    changes.extend(_scalar_changes("ipv4", "ipv4", current.get("ipv4", {}), desired["ipv4"], ("prefix", "hub")))
    changes.extend(_scalar_changes("ipv6", "ipv6", current.get("ipv6", {}), desired["ipv6"],
                                   ("mode", "prefix", "hub", "wan_v6")))

    for family in ("v4", "v6"):
        desired_pools = desired["pools"].get(family) or []
        if not desired_pools:
            continue
        # Compare only the pools the spec declares; pools managed elsewhere
        # (e.g. a per-peer static pool) must not cause permanent drift.
        current_by_name = {p.get("name"): p for p in current.get("pools_" + family) or []}
        for pool in desired_pools:
            existing = current_by_name.get(pool["name"])
            if existing != pool:
                changes.append(_change("update", "pools", pool["name"], "pools", existing, pool))

    current_peers = {p.get("name"): p for p in current.get("peers", []) if isinstance(p, dict)}
    desired_peers = {p["name"]: p for p in desired["peers"]}
    for name in sorted(desired_peers):
        spec_peer = desired_peers[name]
        cur = current_peers.get(name)
        if cur is None:
            changes.append(_change("add", "peer", name, None, None,
                                   {"role": spec_peer.get("role"), "traffic": spec_peer.get("traffic")}))
        elif cur.get("tombstoned"):
            changes.append(_change("update", "peer", name, "tombstoned", True, False))
        else:
            changes.extend(_peer_changes(cur, spec_peer))
    if prune:
        for name in sorted(current_peers):
            if name not in desired_peers and not current_peers[name].get("tombstoned"):
                changes.append(_change("delete", "peer", name, None, {"role": current_peers[name].get("role")}, None))
    return changes


def plan_summary(changes):
    """Count changes by action for machine-readable output."""
    summary = {"add": 0, "update": 0, "delete": 0}
    for change in changes:
        action = change.get("action", "update")
        summary[action] = summary.get(action, 0) + 1
    return summary
