# spec.py
"""Declarative desired-state spec: load, validate, normalize and resolve secrets.

The spec is the unattended single source of truth. It is validated with the
same field validators used by the CLI, so `plan`/`reconcile` cannot smuggle in
values the imperative commands would reject.
"""
import json
import os
import sys
from pathlib import Path

from .crypto import is_valid_wgkey, wgpsk
from .i18n import t
from .ipam import kind_to_role_kind
from .validators import (
    parse_routes_csv,
    validate_backend,
    validate_endpoint,
    validate_expiry,
    validate_firewall,
    validate_ifname,
    validate_ip,
    validate_ipv6_mode,
    validate_keepalive,
    validate_mtu,
    validate_name,
    validate_port,
    validate_prefix,
    validate_traffic,
)

SPEC_API = "wg-manager/v1"


def _bad(detail):
    raise ValueError(t("err_spec_invalid").format(detail=detail))


def load_spec_document(source):
    """Read a spec from a path or '-' (stdin); JSON, TOML, YAML when available."""
    if str(source) == "-":
        return _parse(sys.stdin.read(), "json")
    path = Path(str(source))
    if not path.exists():
        raise ValueError(t("err_spec_missing").format(path=source))
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(t("err_spec_invalid").format(detail=exc))
    suffix = path.suffix.lower()
    if suffix == ".toml":
        return _parse(text, "toml")
    if suffix in (".yaml", ".yml"):
        return _parse(text, "yaml")
    return _parse(text, "json")


def _parse(text, fmt):
    if fmt == "toml":
        try:
            import tomllib
            return tomllib.loads(text)
        except (ValueError, TypeError) as exc:
            raise ValueError(t("err_spec_invalid").format(detail=exc))
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            raise ValueError(t("err_spec_invalid").format(detail="PyYAML is not installed"))
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(t("err_spec_invalid").format(detail=exc))
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ValueError(t("err_spec_invalid").format(detail=exc))


def _require_object(value, where):
    if not isinstance(value, dict):
        _bad(where + " is not an object")
    return value


def _normalize_server(raw):
    _require_object(raw, "server")
    out = {}
    if "endpoint" in raw:
        out["endpoint"] = validate_endpoint(raw["endpoint"])
    if "port" in raw:
        out["port"] = validate_port(raw["port"])
    if "mtu" in raw:
        out["mtu"] = validate_mtu(raw["mtu"])
    if "ifname" in raw:
        out["ifname"] = validate_ifname(raw["ifname"])
    if "backend" in raw:
        out["backend"] = validate_backend(raw["backend"])
    if "firewall" in raw:
        out["firewall"] = validate_firewall(raw["firewall"])
    if "wan_iface" in raw:
        out["wan_iface"] = validate_ifname(raw["wan_iface"])
    if "dns" in raw:
        dns = raw["dns"]
        if not isinstance(dns, list):
            raise ValueError(t("err_spec_invalid").format(detail="server.dns is not a list"))
        out["dns"] = [validate_ip(entry) for entry in dns]
    return out


def _normalize_ipv4(raw):
    _require_object(raw, "ipv4")
    out = {}
    if raw.get("prefix"):
        out["prefix"] = validate_prefix(raw["prefix"])
    if raw.get("hub"):
        out["hub"] = validate_ip(raw["hub"])
    return out


def _normalize_ipv6(raw):
    _require_object(raw, "ipv6")
    out = {}
    if "mode" in raw:
        out["mode"] = validate_ipv6_mode(raw["mode"])
    if raw.get("prefix"):
        out["prefix"] = validate_prefix(raw["prefix"])
    if raw.get("hub"):
        out["hub"] = validate_ip(raw["hub"])
    if raw.get("wan_v6"):
        wan = str(raw["wan_v6"]).strip()
        out["wan_v6"] = validate_prefix(wan) if "/" in wan else validate_ip(wan)
    return out


def _normalize_pools(raw):
    _require_object(raw, "pools")
    out = {"v4": [], "v6": []}
    for family in ("v4", "v6"):
        pools = raw.get(family, []) or []
        if not isinstance(pools, list):
            _bad("pools." + family + " is not a list")
        for pool in pools:
            _require_object(pool, "pools." + family + "[]")
            name = validate_name(str(pool.get("name", "")))
            rng = str(pool.get("range", "")).strip()
            if not rng:
                raise ValueError(t("err_spec_invalid").format(detail="pool " + name + " has no range"))
            kind = str(pool.get("kind", "next-free"))
            if kind not in ("static", "next-free"):
                raise ValueError(t("err_spec_invalid").format(detail="pool " + name + " kind"))
            out[family].append({"name": name, "range": rng, "kind": kind})
    return out


def _normalize_peer(raw):
    _require_object(raw, "peers[]")
    name = validate_name(str(raw.get("name", "")))
    role, kind = kind_to_role_kind(str(raw.get("kind", raw.get("role", "client"))))
    peer = {"name": name, "role": role, "kind": kind}
    if "infra_type" in raw:
        peer["infra_type"] = str(raw["infra_type"]).strip().lower()
    if "traffic" in raw:
        peer["traffic"] = validate_traffic(raw["traffic"])
    if raw.get("custom_routes") is not None or raw.get("routes") is not None:
        routes = raw.get("custom_routes", raw.get("routes"))
        if isinstance(routes, list):
            routes = ",".join(str(entry) for entry in routes)
        peer["custom_routes"] = parse_routes_csv(routes)
    if "dns_scope" in raw:
        scope = str(raw["dns_scope"])
        if scope not in ("none", "tunnel", "all"):
            raise ValueError(t("err_spec_invalid").format(detail="peer " + name + " dns_scope"))
        peer["dns_scope"] = scope
    if "keepalive" in raw:
        peer["keepalive"] = validate_keepalive(raw["keepalive"])
    if "endpoint" in raw and str(raw["endpoint"]).strip():
        peer["endpoint"] = validate_endpoint(raw["endpoint"])
    if raw.get("ip"):
        peer["ip"] = validate_ip(raw["ip"])
    if raw.get("ip6"):
        peer["ip6"] = validate_ip(raw["ip6"])
    if raw.get("pool"):
        peer["pool"] = validate_name(str(raw["pool"]))
    if raw.get("expires"):
        validate_expiry(str(raw["expires"]))
        peer["expires"] = str(raw["expires"])
    if "enabled" in raw:
        peer["enabled"] = bool(raw["enabled"])
    if "pubkey" in raw and str(raw["pubkey"]).strip():
        pub = str(raw["pubkey"]).strip()
        if not is_valid_wgkey(pub):
            raise ValueError(t("err_invalid_wgkey").format(path="peer " + name + " pubkey"))
        peer["pubkey"] = pub
    if raw.get("no_psk"):
        peer["no_psk"] = True
    if "psk" in raw and raw["psk"] is not None:
        peer["psk"] = raw["psk"]
    return peer


def normalize_spec(doc):
    """Validate and canonicalize a spec document into a desired-state object."""
    if not isinstance(doc, dict):
        _bad("root is not an object")
    api = str(doc.get("apiVersion", SPEC_API))
    if api != SPEC_API:
        raise ValueError(t("err_spec_api").format(version=api, expected=SPEC_API))
    peers_raw = doc.get("peers", []) or []
    if not isinstance(peers_raw, list):
        _bad("peers is not a list")
    peers = []
    seen = set()
    for raw in peers_raw:
        peer = _normalize_peer(raw)
        if peer["name"] in seen:
            raise ValueError(t("err_spec_dup_peer").format(name=peer["name"]))
        seen.add(peer["name"])
        peers.append(peer)
    return {
        "apiVersion": SPEC_API,
        "server": _normalize_server(doc.get("server", {}) or {}),
        "ipv4": _normalize_ipv4(doc.get("ipv4", {}) or {}),
        "ipv6": _normalize_ipv6(doc.get("ipv6", {}) or {}),
        "pools": _normalize_pools(doc.get("pools", {}) or {}),
        "peers": peers,
    }


def resolve_psk(value):
    """Resolve a peer `psk` spec value to a concrete key, or None to skip.

    Supports "generate", a literal base64 key, {"from_file": path} and
    {"from_env": NAME}. Raises ValueError on an unreadable or invalid secret.
    """
    if value is None:
        return None
    if isinstance(value, dict):
        if "from_file" in value:
            try:
                text = Path(str(value["from_file"])).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ValueError(t("err_spec_psk").format(detail=exc))
        elif "from_env" in value:
            text = os.environ.get(str(value["from_env"]), "").strip()
        else:
            raise ValueError(t("err_spec_psk").format(detail="unsupported secret source"))
        if not is_valid_wgkey(text):
            raise ValueError(t("err_spec_psk").format(detail="secret is not a valid key"))
        return text
    text = str(value).strip()
    if text.lower() in ("generate", "auto", "yes", "true", "1", ""):
        return wgpsk()
    if is_valid_wgkey(text):
        return text
    raise ValueError(t("err_spec_psk").format(detail="expected 'generate', a key or an object"))
