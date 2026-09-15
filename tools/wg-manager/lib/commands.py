# commands.py
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .constants import REQUIRED_INIT_KEYS, SCHEMA_VERSION, SYSROOT, TAG
from .crypto import is_valid_wgkey, validate_key_material, wggen, wgpsk, wgpub
from .i18n import LANG, is_yes, t
from .ipam import (
    allocate_static,
    check_wan_overlap,
    check_wan_v6_onlink,
    default_pool,
    default_pool_span,
    detect_wan_iface,
    exhaustion_message,
    find_pool,
    kind_to_role_kind,
    next_free_ip,
    parse_pool_range,
    peers_sorted,
    pool_ranges_overlap,
    suggest_pool_spans,
    validate_pool_input,
    wan_v6_prefixes_best_effort,
)
from .presentation import (
    _stdin_isatty,
    banner,
    emit,
    eprint,
    hint,
    kv,
    note,
    paint,
    prompt_value,
    prompt_yesno,
    section,
    table,
    term_width,
    usage,
    wrap_text,
)
from .renderers import (
    redact_text,
    render_client_conf,
    render_firewalld,
    render_netdev,
    render_network,
    render_nft,
    render_nm,
    render_router_conf,
    render_rsc,
    render_sysctl,
    render_wgquick,
)
from .state import (
    _is_initialized,
    _mkdir_private,
    atomic_write,
    audit,
    default_state,
    list_backups,
    load_state,
    load_state_or_default,
    remove_state_data,
    save_state,
    state_dir,
    state_lock,
    state_path,
)
from .system import (
    _family_default_backend,
    _precheck_backend,
    apply_system_reload,
    apply_system_uninstall,
    detect_firewall_default,
    detect_net_backend,
    format_bytes,
    format_handshake_age,
    get_wg_live_dump,
    preview_system_uninstall,
    require_apply,
)
from .validators import (
    _prefix_is_ula,
    parse_routes_csv,
    parse_set_pairs,
    validate_backend,
    validate_endpoint,
    validate_expiry,
    validate_ifname,
    validate_ip,
    validate_ipv6_mode,
    validate_keepalive,
    validate_mtu,
    validate_name,
    validate_nft_content,
    validate_port,
    validate_prefix,
    validate_reconfigure_prefix,
    validate_routes_for_role,
    validate_safe_path,
    validate_traffic,
)


# ---------------------------------------------------------------- init wizard
def cmd_init(args):
    # Guard: init is first-time-only; refuse when state exists unless --force.
    if _is_initialized() and not getattr(args, "force", False):
        eprint(t("err_already_init").format(path=str(state_path())))
        raise SystemExit(1)
    # Audit fix: A6 - explicit inputs required when stdin is not a terminal.
    try:
        provided = parse_set_pairs(getattr(args, "set", None))
    except ValueError as exc:
        eprint(str(exc))
        raise SystemExit(1)
    tty = _stdin_isatty()
    dflt = default_state()
    if tty:
        print(paint(t("msg_wizard_hint"), "muted", args) + "\n")

    def ask(key, prompt, default):
        if key in provided:
            return provided[key]
        if tty:
            return prompt_value(prompt, default)
        return default

    def ask_valid(key, prompt, default, validator):
        while True:
            raw = ask(key, prompt, default)
            try:
                return validator(raw)
            except ValueError as exc:
                eprint(str(exc))
                if not tty or key in provided:
                    raise
                if key in provided:
                    raise

    endpoint = validate_endpoint(ask("endpoint", t("q_endpoint").format(default=dflt["server"]["endpoint"]), dflt["server"]["endpoint"]))
    port = validate_port(ask("port", t("q_port").format(default="51820"), "51820"))
    mtu = validate_mtu(ask("mtu", t("q_mtu").format(default="1420"), "1420"))
    ifname = validate_ifname(ask("ifname", t("q_ifname").format(default="wg0"), "wg0"))
    detected_backend, detected_reason = detect_net_backend()
    if detected_backend is not None:
        if tty:
            print(t("msg_backend_auto").format(backend=paint(detected_backend, "accent", args), reason=detected_reason))
        backend_default = detected_backend
    else:
        if tty:
            print(t("warn_backend_conflict"))
        backend_default = _family_default_backend()
    backend = validate_backend(ask("backend", t("q_backend").format(default=backend_default), backend_default))
    detected_wan = detect_wan_iface()
    wan_default = detected_wan or "eth0"
    if detected_wan and tty and "wan_iface" not in provided:
        print(t("msg_wan_auto").format(iface=paint(detected_wan, "accent", args)))
    wan_iface = validate_ifname(ask("wan_iface", t("q_wan_iface").format(default=wan_default), wan_default))
    v4prefix = validate_prefix(ask("ipv4_prefix", t("q_ipv4_prefix").format(default=dflt["ipv4"]["prefix"]), dflt["ipv4"]["prefix"]))
    v4hub = validate_ip(ask("ipv4_hub", t("q_ipv4_hub").format(default="10.90.90.1"), "10.90.90.1"))
    v6mode = validate_ipv6_mode(ask("ipv6_mode", t("q_ipv6_mode").format(default="disabled"), "disabled"))
    v6prefix = ""
    v6hub = ""
    wan_v6 = ""
    if v6mode != "disabled":
        base = "fd90:90:90::/64" if v6mode in ("ula", "nat66") else "2001:db8:1234:9000::/64"
        if v6mode in ("ula", "nat66"):
            v6prefix = ask_valid("ipv6_prefix", t("q_ipv6_prefix").format(default=base), base,
                                 lambda raw: validate_reconfigure_prefix(v6mode, raw))
        else:
            v6prefix = validate_prefix(ask("ipv6_prefix", t("q_ipv6_prefix").format(default=base), base))
        hub_base = str(ipaddress.ip_network(v6prefix, strict=False).network_address + 1)
        v6hub = validate_ip(ask("ipv6_hub", t("q_ipv6_hub").format(default=hub_base), hub_base))
        wan_v6 = ask("ipv6_wan", t("q_wan_v6").format(default=""), "")
        if wan_v6:
            validate_prefix(wan_v6) if "/" in wan_v6 else validate_ip(wan_v6)
    # Audit fix: A2 - collect DNS servers for clients.
    dns_raw = ask("dns", t("q_dns_servers").format(default="1.1.1.1, 8.8.8.8"), "1.1.1.1, 8.8.8.8")
    dns = []
    for part in str(dns_raw).split(","):
        p = part.strip()
        if p:
            dns.append(validate_ip(p))
    # WAN overlap guards (best-effort offline).
    for prefix in [v4prefix] + ([v6prefix] if v6prefix else []):
        hit = check_wan_overlap(prefix, ifname=ifname)
        if hit:
            eprint(t("err_wan_overlap").format(prefix=prefix, route=hit))
            raise SystemExit(1)
    # WAN /64 on-link guard for routed mode.
    if v6mode == "routed" and v6prefix:
        wans = [wan_v6] if wan_v6 else wan_v6_prefixes_best_effort()
        hit = check_wan_v6_onlink(v6prefix, wans)
        if hit:
            eprint(t("explain_need_delegated_prefix").format(prefix=v6prefix, wan=hit))
            raise SystemExit(1)
    if "permanent" in provided:
        want_perm = is_yes(provided["permanent"])
    elif tty:
        want_perm = prompt_yesno("q_permanent")
    else:
        want_perm = False
    pools_v4 = []
    pools_v6 = []
    def to_short_span(full_span, net_prefix):
        if "-" in full_span:
            p1, _, p2 = full_span.partition("-")
            tnet = ipaddress.ip_network(str(net_prefix), strict=False)
            try:
                ip1 = ipaddress.ip_address(p1.strip())
                ip2 = ipaddress.ip_address(p2.strip())
                if ip1 in tnet and ip2 in tnet:
                    off1 = int(ip1) - int(tnet.network_address)
                    off2 = int(ip2) - int(tnet.network_address)
                    return f"{off1}-{off2}"
            except ValueError:
                pass
        return full_span

    infra_default, clients_default = suggest_pool_spans(v4prefix, v4hub)
    if not infra_default:
        infra_default = default_pool_span(v4prefix, v4hub, 10, 20)
    if not clients_default:
        clients_default = default_pool_span(v4prefix, v4hub, 21, 150)
    # Audit fix: A6 - a privileged non-interactive init must be fully specified.
    if not tty and getattr(args, "apply", False):
        missing = [k for k in REQUIRED_INIT_KEYS if k not in provided]
        if want_perm and "infra" not in provided and not infra_default:
            missing.append("infra")
        if "clients" not in provided and not clients_default:
            missing.append("clients")
        if missing:
            eprint(t("err_init_noninteractive").format(keys=",".join(missing)))
            return 2
    infra_prompt_default = to_short_span(infra_default, v4prefix) if tty else infra_default
    clients_prompt_default = to_short_span(clients_default, v4prefix) if tty else clients_default
    infra_range = ""
    if want_perm:
        infra_range = ask_valid("infra", t("q_infra_pool").format(default=infra_prompt_default), infra_prompt_default,
                                lambda raw: validate_pool_input(raw, v4prefix, v4hub, "infra", 4))
        pools_v4.append({"name": "infra", "range": infra_range, "kind": "static"})
    client_v4 = ask_valid("clients", t("q_client_pool_v4").format(default=clients_prompt_default), clients_prompt_default,
                          lambda raw: validate_pool_input(raw, v4prefix, v4hub, "clients", 4))
    if infra_range and pool_ranges_overlap(infra_range, client_v4, 4):
        raise ValueError(t("err_pool_overlap").format(a=infra_range, b=client_v4))
    pools_v4.append({"name": "clients", "range": client_v4, "kind": "next-free"})
    if v6prefix:
        v6clients_default = default_pool_span(v6prefix, v6hub, 21, 150)
        v6_prompt_default = to_short_span(v6clients_default, v6prefix) if tty else v6clients_default
        client_v6_raw = ask("clients_v6", t("q_client_pool_v6").format(default=v6_prompt_default), v6_prompt_default).strip()
        if client_v6_raw:
            client_v6_norm = validate_pool_input(client_v6_raw, v6prefix, v6hub, "clients", 6)
            pools_v6.append({"name": "clients", "range": client_v6_norm, "kind": "next-free"})
        elif v6mode in ("ula", "nat66") and v6clients_default:
            pools_v6.append({"name": "clients", "range": v6clients_default, "kind": "next-free"})
    state = {
        "schema_version": SCHEMA_VERSION,
        "server": {"endpoint": endpoint, "port": port, "mtu": mtu, "ifname": ifname, "backend": backend, "wan_iface": wan_iface, "dns": dns},
        "ipv4": {"prefix": v4prefix, "hub": v4hub},
        "ipv6": {"mode": v6mode, "prefix": v6prefix, "hub": v6hub, "wan_v6": wan_v6},
        "pools_v4": pools_v4,
        "pools_v6": pools_v6,
        "peers": [],
    }
    if tty and not prompt_yesno("q_confirm"):
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        return 0
    can_write = require_apply(args, "init")
    if not can_write:
        # Show rendered output in dry-run mode only (dry-run preview uses redacted output).
        emit(["", section("preview", args)])
        emit(note(t("reload_dry_title"), "dryrun", args, indent=1))
        print(redact_text(render_netdev(state, show_secrets=False), show_secrets=False))
        print(render_network(state))
        print(render_nft(state))
        print(render_sysctl(state))
        emit(hint("add --apply --yes --sudo to write these files.", args))
        return 0
    # Refuse before saving state if the selected backend is not running.
    _precheck_backend(backend)
    # Audit fix: C1 - real key material only for privileged writes.
    import_path = getattr(args, "import_server_key", "") or ""
    if import_path:
        validate_safe_path(import_path)
        try:
            priv = Path(import_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not is_valid_wgkey(priv):
            eprint(t("err_invalid_wgkey").format(path=import_path))
            raise SystemExit(1)
        pub = wgpub(priv)
    else:
        priv = wggen()
        pub = wgpub(priv)
    state["server"]["private_key"] = priv
    state["server"]["public_key"] = pub
    validate_key_material(state)
    if not validate_nft_content(render_nft(state)):
        raise SystemExit(1)
    with state_lock():
        try:
            applied = apply_system_reload(state, backend, detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("init", "endpoint=" + endpoint)
    emit(["", section("result", args)])
    emit(note(t("msg_applied"), "applied", args, indent=1))
    emit(note(t("msg_init_done").format(path=str(state_path())), "ok", args, indent=1))
    return 0

def cmd_add(args):
    state = load_state_or_default(args)
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        emit(["", section(t("title_add_peer"), args)])
        prompt_label = paint(">> ", "accent", args) + t("add_name_prompt")
        name = prompt_value(prompt_label, "").strip()
        if not name or name.lower() in ("q", "cancel", "exit"):
            return 0
    validate_name(name)
    for peer in state.get("peers", []):
        if peer.get("name") == name:
            eprint(t("err_peer_exists").format(name=name))
            raise SystemExit(1)
    kind_raw = getattr(args, "kind", "") or ""
    if not kind_raw and sys.stdin.isatty():
        kind_raw = prompt_value(t("add_kind_prompt").format(default="client"), "client")
    kind_raw = kind_raw or "client"
    role, kind = kind_to_role_kind(kind_raw)
    infra_type = ""
    if role == "infra":
        k_low = str(kind_raw).strip().lower()
        if k_low in ("mikrotik", "mtk"):
            infra_type = "mikrotik"
        elif k_low in ("router",):
            infra_type = "router"
        elif k_low in ("server", "servidor"):
            infra_type = "server"
        else:
            cli_infra = getattr(args, "infra_type", "") or ""
            if cli_infra:
                infra_type = str(cli_infra).strip().lower()
            elif sys.stdin.isatty():
                infra_type = prompt_value(t("add_infra_type_prompt").format(default="mikrotik"), "mikrotik").strip().lower()
            else:
                infra_type = "mikrotik" if not getattr(args, "pubkey", "") else "server"
        if infra_type in ("servidor", "server"):
            infra_type = "server"
        elif infra_type in ("router",):
            infra_type = "router"
        elif infra_type in ("mikrotik", "mtk"):
            infra_type = "mikrotik"
        else:
            infra_type = "mikrotik"
    pool_name = getattr(args, "pool", "") or ""
    if not pool_name and sys.stdin.isatty():
        pool_descs = []
        for p in state.get("pools_v4", []):
            p_name = p.get("name", "")
            p_range = p.get("range", "")
            p_target = "infra" if p_name == "infra" or p.get("kind") == "static" else "client"
            pool_descs.append(f"{p_name} [{p_range}] ({p_target})")
        if pool_descs:
            emit(note(t("pools_available").format(pools=", ".join(pool_descs)), "info", args, indent=1))
        if role == "infra" and (find_pool(state, "infra", 4) or find_pool(state, "infra", 6)):
            dflt_name = "infra"
        elif role == "client" and (find_pool(state, "clients", 4) or find_pool(state, "clients", 6)):
            dflt_name = "clients"
        else:
            dflt_pool = default_pool(state, 4) or default_pool(state, 6)
            dflt_name = dflt_pool.get("name", "clients") if dflt_pool else "clients"
        pool_name = prompt_value(t("add_pool_prompt").format(default=dflt_name), dflt_name)
    if not pool_name:
        if role == "infra" and (find_pool(state, "infra", 4) or find_pool(state, "infra", 6)):
            pool_name = "infra"
        elif find_pool(state, "clients", 4) or find_pool(state, "clients", 6):
            pool_name = "clients"
        else:
            dflt_pool = default_pool(state, 4) or default_pool(state, 6)
            pool_name = dflt_pool.get("name", "clients") if dflt_pool else "clients"
    pool_v4 = find_pool(state, pool_name, 4)
    pool_v6 = find_pool(state, pool_name, 6)
    if pool_v4 is None and pool_v6 is None:
        eprint(t("err_pool_not_found").format(pool=pool_name))
        raise SystemExit(1)
    traffic = getattr(args, "traffic", "") or ""
    dflt_traffic = "server-only" if role == "infra" else "full-tunnel"
    if not traffic and sys.stdin.isatty():
        traffic = prompt_value(t("add_traffic_prompt").format(default=dflt_traffic), dflt_traffic)
    traffic = traffic or dflt_traffic
    validate_traffic(traffic)
    routes = parse_routes_csv(getattr(args, "routes", "") or "")
    if not routes and traffic == "custom-routes" and sys.stdin.isatty():
        routes = parse_routes_csv(prompt_value(t("add_routes_prompt"), ""))
    # Audit fix: N9 - reject a default route from non-infra peers.
    validate_routes_for_role(routes, role)
    dns_scope = getattr(args, "dns_scope", "") or ""
    dflt_dns = "tunnel" if (traffic == "full-tunnel" and (state.get("ipv4", {}).get("hub") or state.get("server", {}).get("dns"))) else "none"
    if not dns_scope and sys.stdin.isatty():
        dns_scope = prompt_value(t("add_dns_prompt").format(default=dflt_dns), dflt_dns)
    dns_scope = dns_scope or dflt_dns
    if dns_scope not in ("none", "tunnel", "all"):
        dns_scope = "none"
    keepalive = validate_keepalive(str(getattr(args, "keepalive", 25) if getattr(args, "keepalive", None) is not None else (prompt_value(t("add_keepalive_prompt").format(default="25"), "25") if sys.stdin.isatty() else "25")))
    endpoint = (getattr(args, "endpoint", "") or "")
    if not endpoint and sys.stdin.isatty():
        endpoint = prompt_value(t("add_endpoint_prompt"), "")
    if endpoint:
        validate_endpoint(endpoint)
    can_write = require_apply(args, "add")
    pubkey = (getattr(args, "pubkey", "") or "").strip()
    privkey = ""
    want_psk = False
    psk = ""
    cli_psk = getattr(args, "psk", None)
    cli_no_psk = getattr(args, "no_psk", False)

    if role == "client":
        if not pubkey and sys.stdin.isatty():
            pubkey = prompt_value(t("add_pubkey_prompt"), "").strip()
        if not pubkey and (can_write or shutil.which("wg")):
            try:
                privkey = wggen()
                pubkey = wgpub(privkey)
            except SystemExit:
                if can_write:
                    raise
                privkey = ""
                pubkey = ""
        if cli_no_psk:
            want_psk = False
        elif cli_psk is not None:
            want_psk = True
        elif sys.stdin.isatty():
            want_psk = prompt_yesno("q_add_psk", default=True)

    elif role == "infra":
        if infra_type == "mikrotik":
            import_existing = False
            if pubkey:
                import_existing = True
            elif sys.stdin.isatty():
                import_existing = prompt_yesno("q_mikrotik_import_existing", default=False)
            if import_existing:
                if not pubkey and sys.stdin.isatty():
                    pubkey = prompt_value(t("add_pubkey_prompt"), "").strip()
                if not pubkey and can_write:
                    eprint(t("err_invalid_wgkey").format(path="--pubkey"))
                    raise SystemExit(1)
                privkey = ""
                if cli_no_psk:
                    want_psk = False
                elif cli_psk is not None:
                    want_psk = True
                elif sys.stdin.isatty():
                    want_psk = prompt_yesno("q_add_psk", default=True)
            else:
                if can_write or shutil.which("wg"):
                    try:
                        privkey = wggen()
                        pubkey = wgpub(privkey)
                    except SystemExit:
                        if can_write:
                            raise
                        privkey = ""
                        pubkey = ""
                want_psk = not cli_no_psk

        elif infra_type == "router":
            gen_keys = True
            if pubkey:
                gen_keys = False
            elif sys.stdin.isatty():
                gen_keys = prompt_yesno("q_router_generate_keys", default=True)
            if gen_keys:
                if can_write or shutil.which("wg"):
                    try:
                        privkey = wggen()
                        pubkey = wgpub(privkey)
                    except SystemExit:
                        if can_write:
                            raise
                        privkey = ""
                        pubkey = ""
                want_psk = not cli_no_psk
            else:
                if not pubkey and sys.stdin.isatty():
                    pubkey = prompt_value(t("add_pubkey_prompt"), "").strip()
                if not pubkey and can_write:
                    eprint(t("err_invalid_wgkey").format(path="--pubkey"))
                    raise SystemExit(1)
                privkey = ""
                if cli_no_psk:
                    want_psk = False
                elif cli_psk is not None:
                    want_psk = True
                elif sys.stdin.isatty():
                    want_psk = prompt_yesno("q_add_psk", default=True)

        elif infra_type == "server":
            if not pubkey and sys.stdin.isatty():
                pubkey = prompt_value(t("add_pubkey_prompt"), "").strip()
            if not pubkey and can_write:
                eprint(t("err_invalid_wgkey").format(path="--pubkey (required for server)"))
                raise SystemExit(1)
            privkey = ""
            if cli_no_psk:
                want_psk = False
            elif cli_psk is not None:
                want_psk = True
            elif sys.stdin.isatty():
                want_psk = prompt_yesno("q_add_psk", default=True)

    if pubkey and not is_valid_wgkey(pubkey):
        raise ValueError(t("err_invalid_wgkey").format(path="--pubkey"))

    if cli_no_psk:
        want_psk = False
        psk = ""
    elif cli_psk is not None:
        if cli_psk and str(cli_psk).strip().lower() not in ("generate", "auto", "yes", "true", "1", ""):
            cand_psk = str(cli_psk).strip()
            if not is_valid_wgkey(cand_psk):
                raise ValueError(t("err_invalid_wgkey").format(path="--psk"))
            psk = cand_psk
        else:
            psk = wgpsk()
    elif want_psk and not psk:
        psk = wgpsk()

    if can_write and not pubkey:
        eprint(t("err_invalid_wgkey").format(path="--pubkey"))
        raise SystemExit(1)

    expires_raw = getattr(args, "expires", "") or ""
    if not expires_raw and sys.stdin.isatty():
        expires_raw = prompt_value(t("add_expires_prompt"), "")
    expires_at = validate_expiry(expires_raw) if expires_raw else None

    # IPAM.
    v4 = ""
    v6 = ""
    if pool_v4 is not None:
        hub = state.get("ipv4", {}).get("hub", "")
        if kind == "permanent" and role == "infra" and getattr(args, "ip", ""):
            v4 = allocate_static(pool_v4["range"], state.get("peers", []), args.ip, hub)
        else:
            v4 = next_free_ip(pool_v4["range"], state.get("peers", []), hub)
        if not v4:
            eprint(exhaustion_message(pool_name, pool_v4["range"], state.get("peers", [])))
            raise SystemExit(1)
    v6mode = state.get("ipv6", {}).get("mode", "disabled")
    if v6mode != "disabled":
        if pool_v6 is None:
            pool_v6 = default_pool(state, 6)
        if pool_v6 is None and v6mode in ("ula", "nat66"):
            v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
            if not v6prefix or not _prefix_is_ula(v6prefix):
                v6prefix = "fd90:90:90::/64"
                state.setdefault("ipv6", {})["prefix"] = v6prefix
            v6hub = (state.get("ipv6", {}).get("hub") or "").strip()
            if not v6hub:
                try:
                    net = ipaddress.ip_network(v6prefix, strict=False)
                    v6hub = str(net.network_address + 1)
                except ValueError:
                    v6hub = "fd90:90:90::1"
                state.setdefault("ipv6", {})["hub"] = v6hub
            v6span = default_pool_span(v6prefix, v6hub, 21, 150)
            if v6span:
                pool_v6 = {"name": pool_name or "clients", "range": v6span, "kind": "next-free"}
                state.setdefault("pools_v6", []).append(pool_v6)
        if pool_v6 is not None:
            hub6 = state.get("ipv6", {}).get("hub", "")
            if kind == "permanent" and role == "infra" and getattr(args, "ip6", ""):
                v6 = allocate_static(pool_v6["range"], state.get("peers", []), args.ip6, hub6)
            else:
                v6 = next_free_ip(pool_v6["range"], state.get("peers", []), hub6)
            if not v6:
                eprint(exhaustion_message(pool_name, pool_v6["range"], state.get("peers", [])))
                raise SystemExit(1)
        elif v6mode in ("ula", "nat66"):
            eprint(t("err_pool_not_found").format(pool=pool_name or "clients"))
            raise SystemExit(1)
    peer = {
        "name": name, "role": role, "kind": kind, "infra_type": infra_type, "traffic": traffic,
        "v4": v4, "v6": v6, "pubkey": pubkey, "privkey": privkey,
        "psk": psk,
        "endpoint": endpoint, "keepalive": keepalive, "dns_scope": dns_scope,
        "custom_routes": routes, "pool": pool_name,
        "enabled": True, "tombstoned": False,
        "created": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
    }
    if not can_write:
        if role == "client":
            print(render_wgquick(state, peer, show_secrets=getattr(args, "show_secrets", False)))
        elif infra_type == "mikrotik":
            print(render_rsc(state, peer, show_secrets=getattr(args, "show_secrets", False)))
        elif infra_type == "router":
            print(render_router_conf(state, peer, show_secrets=getattr(args, "show_secrets", False)))
        else:
            emit(note("Server peer: " + name + " (AllowedIPs: " + (v4 or "-") + ")", "info", args, indent=1))
        return 0
    validate_key_material(state)
    with state_lock():
        state["peers"].append(peer)
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("add", "name=" + name)
    v4d = v4 if v4 else "-"
    v6d = v6 if v6 else "-"
    try:
        outdir = state_dir() / "clients"
        _mkdir_private(outdir)
        if role == "client" and is_valid_wgkey(peer.get("privkey", "")):
            conf_file = outdir / (name + ".conf")
            atomic_write(conf_file, render_wgquick(state, peer, show_secrets=True), mode=0o600)
            emit(note(t("msg_wrote_conf").format(path=str(conf_file)), "applied", args, indent=1))
        elif role == "infra":
            if infra_type == "mikrotik":
                rsc_file = outdir / (name + ".rsc")
                atomic_write(rsc_file, render_rsc(state, peer, show_secrets=True), mode=0o600)
                emit(note(t("msg_wrote_rsc").format(path=str(rsc_file)), "applied", args, indent=1))
            elif infra_type == "router":
                conf_file = outdir / (name + ".conf")
                atomic_write(conf_file, render_router_conf(state, peer, show_secrets=True), mode=0o600)
                emit(note(t("msg_wrote_conf").format(path=str(conf_file)), "applied", args, indent=1))
    except OSError:
        pass
    emit(note(t("msg_add_done").format(name=name, v4=v4d, v6=v6d), "applied", args, indent=1))
    if role == "client":
        emit(hint(t("hint_qr_available"), args))
    return 0

def _select_peer(state, action_title="", role_filter=None, args=None):
    """Interactively select a peer by number or name; returns peer name or None."""
    peers = state.get("peers", [])
    if role_filter:
        peers = [p for p in peers if p.get("role") == role_filter]
    if not peers:
        emit(["", note(t("list_empty"), "info", args, indent=1)])
        return None
    emit(["", section(action_title or "select peer", args)])
    for idx, p in enumerate(peers, start=1):
        pname = p.get("name", "")
        prole = p.get("role", "client")
        pv4 = p.get("v4", "-") or "-"
        st = _peer_state(p)
        sp = "   [" if idx < 10 else "  ["
        line = (
            sp
            + paint(str(idx), "accent", args)
            + "] "
            + paint(pname.ljust(16), "title", args)
            + " "
            + paint(prole.ljust(8), "muted", args)
            + " "
            + paint(pv4.ljust(18), "accent", args)
            + " "
            + paint(st, "ok" if st in ("active", "enabled") else ("destructive" if st == "tombstone" else "muted"), args)
        )
        emit(line)
    emit("   [" + paint("0", "accent", args) + "] " + paint("cancel".ljust(16), "title", args) + " " + paint("exit / q", "muted", args))
    prompt_str = paint(">> ", "accent", args) + t("menu_prompt")
    try:
        raw = input(prompt_str).strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw or raw.lower() in ("0", "q", "quit", "cancel"):
        return None
    if raw.isdigit():
        val = int(raw)
        if 1 <= val <= len(peers):
            return peers[val - 1]["name"]
    for p in peers:
        if p.get("name", "").lower() == raw.lower():
            return p.get("name")
    eprint(note(t("err_peer_not_found").format(name=raw), "err", args))
    return None


def cmd_edit(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_edit"), args=args)
        if not name:
            return 0
    validate_name(name)
    peer = None
    for item in state.get("peers", []):
        if item.get("name") == name:
            peer = item
            break
    if peer is None:
        emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
        raise SystemExit(1)
    if sys.stdin.isatty() and not any([getattr(args, "new_name", ""), getattr(args, "endpoint", None) is not None, getattr(args, "traffic", ""), getattr(args, "routes", None) is not None, getattr(args, "dns_scope", ""), getattr(args, "keepalive", None) is not None, getattr(args, "move_pool", ""), getattr(args, "rotate_keys", False), getattr(args, "reclaim_ip", False), getattr(args, "enable", False), getattr(args, "disable", False)]):
        emit(["", section(t("menu_desc_edit") + ": " + name, args)])
        fields = [
            ("1", "rename", "cambiar nombre" if LANG == "es" else "change peer name"),
            ("2", "endpoint", "endpoint host:port"),
            ("3", "traffic", "server-only | custom-routes | full-tunnel"),
            ("4", "routes", "rutas/subredes custom" if LANG == "es" else "custom subnets"),
            ("5", "dns", "DNS scope: none | tunnel | all"),
            ("6", "keepalive", "keepalive persistente (0-120s)"),
            ("7", "pool", "cambiar de pool" if LANG == "es" else "move to another pool"),
            ("8", "expires", "expiracion TTL/fecha" if LANG == "es" else "expiration TTL/date"),
            ("9", "enable", "activar peer" if LANG == "es" else "enable peer"),
            ("10", "disable", "desactivar peer" if LANG == "es" else "disable peer"),
        ]
        for num, opt_name, desc in fields:
            sp = "   [" if len(num) == 1 else "  ["
            emit(sp + paint(num, "accent", args) + "] " + paint(opt_name.ljust(12), "title", args) + " " + paint(desc, "muted", args))
        emit("   [" + paint("0", "accent", args) + "] " + paint("cancel".ljust(12), "title", args) + " " + paint("exit / q", "muted", args))
        try:
            choice_raw = input(paint(">> ", "accent", args) + t("menu_prompt")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return 0
        choice_map = {num: opt_name for num, opt_name, _ in fields}
        choice = choice_map.get(choice_raw, choice_raw)
        if choice in ("0", "q", "quit", "cancel", ""):
            return 0
        if choice == "rename":
            args.new_name = prompt_value("new name: ", name)
        elif choice == "endpoint":
            args.endpoint = prompt_value(t("add_endpoint_prompt"), peer.get("endpoint", ""))
        elif choice == "traffic":
            args.traffic = prompt_value(t("add_traffic_prompt").format(default=peer.get("traffic", "server-only")), peer.get("traffic", "server-only"))
        elif choice == "routes":
            args.routes = prompt_value(t("add_routes_prompt"), ",".join(peer.get("custom_routes", []) or []))
        elif choice == "dns":
            args.dns_scope = prompt_value(t("add_dns_prompt").format(default=peer.get("dns_scope", "none")), peer.get("dns_scope", "none"))
        elif choice == "keepalive":
            args.keepalive = int(prompt_value(t("add_keepalive_prompt").format(default=str(peer.get("keepalive", 25))), str(peer.get("keepalive", 25))))
        elif choice == "pool":
            args.move_pool = prompt_value(t("add_pool_prompt").format(default=peer.get("pool", "clients")), peer.get("pool", "clients"))
        elif choice == "expires":
            args.expires = prompt_value(t("add_expires_prompt"), "")
        elif choice == "enable":
            args.enable = True
        elif choice == "disable":
            args.disable = True
    if getattr(args, "new_name", ""):
        validate_name(args.new_name)
        for item in state.get("peers", []):
            if item.get("name") == args.new_name and item is not peer:
                eprint(t("err_peer_exists").format(name=args.new_name))
                raise SystemExit(1)
        peer["name"] = args.new_name
    if getattr(args, "endpoint", None) is not None and getattr(args, "endpoint", "") != "":
        validate_endpoint(args.endpoint)
        peer["endpoint"] = args.endpoint
    if getattr(args, "traffic", ""):
        validate_traffic(args.traffic)
        peer["traffic"] = args.traffic
    if getattr(args, "routes", None) is not None:
        new_routes = parse_routes_csv(args.routes)
        validate_routes_for_role(new_routes, peer.get("role"))
        peer["custom_routes"] = new_routes
    if getattr(args, "pubkey", ""):
        if not is_valid_wgkey(args.pubkey):
            raise ValueError(t("err_invalid_wgkey").format(path="--pubkey"))
        peer["pubkey"] = args.pubkey
        peer["privkey"] = ""
    if getattr(args, "dns_scope", ""):
        if args.dns_scope not in ("none", "tunnel", "all"):
            args.dns_scope = "none"
        peer["dns_scope"] = args.dns_scope
    if getattr(args, "keepalive", None) is not None:
        peer["keepalive"] = validate_keepalive(args.keepalive)
    if getattr(args, "move_pool", ""):
        pool_name = args.move_pool
        pool_v4 = find_pool(state, pool_name, 4)
        if pool_v4 is None:
            eprint(t("err_pool_not_found").format(pool=pool_name))
            raise SystemExit(1)
        others = [p for p in state.get("peers", []) if p is not peer]
        hub = state.get("ipv4", {}).get("hub", "")
        fresh = next_free_ip(pool_v4["range"], others, hub)
        if not fresh:
            eprint(exhaustion_message(pool_name, pool_v4["range"], state.get("peers", [])))
            raise SystemExit(1)
        peer["v4"] = fresh
        peer["pool"] = pool_name
    if getattr(args, "reclaim_ip", False):
        pool_name = peer.get("pool", "clients")
        pool_v4 = find_pool(state, pool_name, 4)
        if pool_v4 is None:
            eprint(t("err_pool_not_found").format(pool=pool_name))
            raise SystemExit(1)
        others = [p for p in state.get("peers", []) if p is not peer]
        hub = state.get("ipv4", {}).get("hub", "")
        fresh = next_free_ip(pool_v4["range"], others, hub)
        if not fresh:
            eprint(exhaustion_message(pool_name, pool_v4["range"], state.get("peers", [])))
            raise SystemExit(1)
        peer["v4"] = fresh
    if getattr(args, "expires", None) is not None and getattr(args, "expires", "") != "":
        peer["expires_at"] = validate_expiry(args.expires)
    if getattr(args, "enable", False):
        peer["enabled"] = True
    if getattr(args, "disable", False):
        peer["enabled"] = False
    can_write = require_apply(args, "edit")
    # Audit fix: C1/A10 - real rotation, only for privileged writes; PSK dropped.
    if can_write and getattr(args, "rotate_keys", False):
        if not getattr(args, "keep_psk", False):
            peer.pop("psk", None)
        if peer.get("role") == "client":
            peer["privkey"] = wggen()
            peer["pubkey"] = wgpub(peer["privkey"])
        else:
            newpub = getattr(args, "pubkey", "") or ""
            if not is_valid_wgkey(newpub):
                eprint(t("err_invalid_wgkey").format(path="--pubkey (required to rotate a remote peer)"))
                raise SystemExit(1)
            peer["pubkey"] = newpub
            peer["privkey"] = ""
    if not can_write:
        if peer.get("role") == "client":
            print(render_wgquick(state, peer, show_secrets=getattr(args, "show_secrets", False)))
        else:
            print(render_rsc(state, peer))
        return 0
    validate_key_material(state)
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("edit", "name=" + peer.get("name", ""))
    emit(note(t("msg_edit_done").format(name=peer.get("name", "")), "applied", args, indent=1))
    return 0

def cmd_delete(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_delete"), args=args)
        if not name:
            return 0
    validate_name(name)
    found = None
    for peer in state.get("peers", []):
        if peer.get("name") == name:
            found = peer
            break
    if found is None:
        emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
        raise SystemExit(1)
    if sys.stdin.isatty() and not getattr(args, "yes", False) and not prompt_yesno("delete_confirm"):
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        return 0
    # Tombstone, never immediate reuse.
    can_write = require_apply(args, "delete")
    if not can_write:
        emit(note(t("delete_confirm").format(name=name, hint=t("confirm_hint")), "destructive", args, indent=1))
        return 0
    found["tombstoned"] = True
    found["enabled"] = False
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("delete", "name=" + name)
    emit(note(t("msg_delete_tombstoned").format(name=name), "ok", args, indent=1))
    return 0

def _peer_state(peer):
    """Language-invariant state token for tables: enabled|disabled|expired|reissue|tombstoned."""
    if peer.get("tombstoned"):
        return "tombstoned"
    if peer.get("expires_at"):
        try:
            now = int(datetime.now(timezone.utc).timestamp())
            if now > int(peer["expires_at"]):
                return "expired"
        except (ValueError, TypeError):
            pass
    if peer.get("needs_reissue"):
        return "reissue"
    if not peer.get("enabled", True):
        return "disabled"
    return "enabled"


def cmd_list(args):
    state = load_state_or_default(args)
    peers = peers_sorted(state.get("peers", []))
    emit(banner("wg-manager list", [("state", state_path())], args))
    if not peers:
        emit(["", note(t("list_empty"), "info", args, indent=1),
              hint(t("list_empty_hint"), args, indent=1)])
        return 0
    rows = [[peer.get("name", "-"), peer.get("role", "-"),
             peer.get("v4", "-") or "-", peer.get("v6", "-") or "-",
             _peer_state(peer)] for peer in peers]
    total = len(rows)
    tomb = sum(1 for p in peers if p.get("tombstoned"))
    active = sum(1 for p in peers if not p.get("tombstoned") and p.get("enabled", True))
    infra = sum(1 for p in peers if p.get("role") == "infra" and not p.get("tombstoned"))
    clients = sum(1 for p in peers if p.get("role") != "infra" and not p.get("tombstoned"))
    reissue = sum(1 for p in peers if p.get("needs_reissue") and not p.get("tombstoned"))
    emit(["", section("peers", args)])
    emit(table(["NAME", "ROLE", "V4", "V6", "STATE"], rows,
               priority=["NAME", "STATE", "ROLE", "V4", "V6"], args=args))
    summary = ("total=" + str(total) + "  active=" + str(active) + "  infra=" + str(infra)
               + "  clients=" + str(clients) + "  tombstoned=" + str(tomb) + "  reissue=" + str(reissue))
    emit("")
    for chunk in wrap_text(summary, term_width(args) - 2):
        emit("  " + chunk)
    if reissue:
        emit(note(t("menu_warn_reissue").format(count=reissue), "warn", args))
    emit(hint(t("list_hint"), args))
    return 0


def cmd_show(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_show"), args=args)
        if not name:
            return 0
    validate_name(name)
    peer = None
    for item in state.get("peers", []):
        if item.get("name") == name:
            peer = item
            break
    if peer is None:
        eprint(note(t("err_peer_not_found").format(name=name), "err", args))
        raise SystemExit(1)
    show_secrets = bool(getattr(args, "show_secrets", False))
    peer_state = _peer_state(peer)
    if peer.get("tombstoned"):
        peer_state += " (address reserved until purge)"
    elif peer.get("needs_reissue"):
        peer_state += " (reissue pending)"
    emit(banner("wg-manager show " + name, args=args))
    emit(["", section("peer", args)])
    emit(kv([("name", name), ("role", peer.get("role", "")), ("kind", peer.get("kind", "")),
             ("state", peer_state), ("traffic", peer.get("traffic", ""))], args=args))
    emit(["", section("addressing", args)])
    emit(kv([("v4", peer.get("v4", "")), ("v6", peer.get("v6", "")),
             ("pool", peer.get("pool", "")), ("dns-scope", peer.get("dns_scope", "none"))], args=args))
    emit(["", section("link", args)])
    emit(kv([("endpoint", peer.get("endpoint", "")), ("keepalive", peer.get("keepalive", 0)),
             ("pubkey", peer.get("pubkey", ""))], args=args))
    emit(["", section("secrets", args)])
    if show_secrets:
        emit(note("secrets visible; treat output as sensitive.", "warn", args, indent=1))
    else:
        emit(note("private-key: REDACTED   preshared-key: REDACTED", "info", args, indent=1))
        emit(hint(t("show_redacted_note"), args, indent=1))
    if peer.get("role") == "infra":
        infra_t = peer.get("infra_type", "")
        if infra_t == "mikrotik":
            emit(["", section("rendered: mikrotik routeros cli (.rsc)", args)])
            print(render_rsc(state, peer, show_secrets=show_secrets))
        elif infra_t == "router":
            emit(["", section("rendered: router peer (.conf)", args)])
            print(render_router_conf(state, peer, show_secrets=show_secrets))
        elif infra_t == "server":
            emit(["", section("server peer", args)])
            emit(note("Remote server peer: configuration managed on remote host.", "info", args, indent=1))
        else:
            emit(["", section("rendered: router / server peer (.conf)", args)])
            print(render_router_conf(state, peer, show_secrets=show_secrets))
            emit(["", section("rendered: router cli (.rsc)", args)])
            print(render_rsc(state, peer, show_secrets=show_secrets))
    elif show_secrets:
        emit(["", section("rendered: wg-quick", args)])
        print(render_wgquick(state, peer, show_secrets=True))
    else:
        emit(["", section("rendered: wg-quick (secrets redacted)", args)])
        print(redact_text(render_wgquick(state, peer, show_secrets=False), show_secrets=False))
    return 0

def cmd_qr(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_qr"), role_filter="client", args=args)
        if not name:
            return 0
    validate_name(name)
    peer = None
    for item in state.get("peers", []):
        if item.get("name") == name:
            peer = item
            break
    if peer is None:
        emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
        raise SystemExit(1)
    if peer.get("role") != "client":
        eprint(t("err_qr_only_client").format(name=name))
        raise SystemExit(1)
    # Audit fix: C3 - abort cleanly when the peer has no valid private key.
    try:
        content = render_wgquick(state, peer, show_secrets=True)
    except ValueError:
        eprint(t("err_peer_no_privkey").format(name=name))
        raise SystemExit(1)
    exe = shutil.which("qrencode")
    if not exe:
        print(t("msg_no_qrencode"))
        print(t("msg_qr_text_fallback"))
        print(content)
        return 0
    try:
        proc = subprocess.run(
            [exe, "-t", "ansiutf8"], input=content, capture_output=True, text=True, timeout=15, check=False
        )
        if proc.stdout:
            print(proc.stdout, end="")
    except (OSError, subprocess.SubprocessError):
        print(t("msg_no_qrencode"))
        print(content)
        return 0
    # PNG with 0600 when applied.
    if getattr(args, "apply", False):
        if not require_apply(args, "qr"):
            return 0
        try:
            outdir = state_dir() / "clients"
            _mkdir_private(outdir)
            png = outdir / (name + ".png")
            subprocess.run(
                [exe, "-o", str(png)], input=content, capture_output=True, text=True, timeout=15, check=False
            )
            try:
                os.chmod(png, 0o600)
            except OSError:
                pass
        except (OSError, subprocess.SubprocessError):
            pass
    return 0

def cmd_purge(args):
    state = load_state()
    pool_name = getattr(args, "pool", "") or ""
    if not pool_name and sys.stdin.isatty():
        pool_name = prompt_value(t("add_pool_prompt").format(default="clients"), "clients")
    pool_name = pool_name or "clients"
    # Audit fix: N12 - pool name is used in the audit log and filters state.
    validate_name(pool_name)
    tombstoned = [p for p in state.get("peers", []) if p.get("tombstoned") and p.get("pool", "clients") == pool_name]
    if sys.stdin.isatty() and not getattr(args, "yes", False) and not prompt_yesno("purge_confirm"):
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        return 0
    can_write = require_apply(args, "purge")
    if not can_write:
        emit(note(t("purge_confirm").format(pool=pool_name, hint=t("confirm_hint")), "destructive", args, indent=1))
        emit(note("count=" + str(len(tombstoned)), "info", args, indent=1))
        return 0
    state["peers"] = [p for p in state.get("peers", []) if not (p.get("tombstoned") and p.get("pool", "clients") == pool_name)]
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("purge", "pool=" + pool_name)
    emit(note(t("msg_purge_done").format(count=len(tombstoned), pool=pool_name), "ok", args, indent=1))
    return 0

def cmd_reclaim(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_reclaim"), args=args)
        if not name:
            return 0
    validate_name(name)
    peer = None
    for item in state.get("peers", []):
        if item.get("name") == name:
            peer = item
            break
    if peer is None:
        emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
        raise SystemExit(1)
    pool_name = peer.get("pool", "clients")
    pool_v4 = find_pool(state, pool_name, 4)
    if pool_v4 is None:
        eprint(t("err_pool_not_found").format(pool=pool_name))
        raise SystemExit(1)
    others = [p for p in state.get("peers", []) if p is not peer]
    hub = state.get("ipv4", {}).get("hub", "")
    fresh = next_free_ip(pool_v4["range"], others, hub)
    if not fresh:
        eprint(exhaustion_message(pool_name, pool_v4["range"], state.get("peers", [])))
        raise SystemExit(1)
    can_write = require_apply(args, "reclaim")
    if not can_write:
        emit(note("would-reclaim=" + fresh, "dryrun", args, indent=1))
        return 0
    peer["v4"] = fresh
    peer["tombstoned"] = False
    peer["enabled"] = True
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("reclaim", "name=" + name)
    emit(note(t("msg_reclaim_done").format(name=name, ip=fresh), "ok", args, indent=1))
    return 0


def cmd_reload(args):
    state = load_state_or_default(args)
    backend = getattr(args, "backend", "") or state.get("server", {}).get("backend", "networkd")
    firewall = getattr(args, "firewall", "") or detect_firewall_default()
    show_secrets = bool(getattr(args, "show_secrets", False))
    want_apply = bool(getattr(args, "apply", False))
    if not want_apply or getattr(args, "dry_run", False):
        emit(banner("wg-manager reload", [("mode", "DRY-RUN")], args))
        emit(note(t("reload_dry_title"), "dryrun", args, indent=1))
        if backend == "nm":
            print(redact_text(render_nm(state, show_secrets=show_secrets), show_secrets=show_secrets))
        else:
            print(redact_text(render_netdev(state, show_secrets=show_secrets), show_secrets=show_secrets))
            print(render_network(state))
        if firewall == "firewalld":
            for cmd in render_firewalld(state):
                print(cmd)
        else:
            print(redact_text(render_nft(state), show_secrets=True))
        print(render_sysctl(state))
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        return 0
    if not require_apply(args, "reload"):
        return 0
    _precheck_backend(backend)
    content = render_nft(state) if firewall == "nft" else "\n".join(render_firewalld(state))
    if firewall == "nft" and not validate_nft_content(content):
        raise SystemExit(1)
    # Staged rendered copies (0600 for secrets).
    try:
        outdir = state_dir() / "rendered"
        _mkdir_private(outdir)
        if backend == "nm":
            atomic_write(outdir / "wg-manager.nmconnection", render_nm(state, show_secrets=True), mode=0o600)
        else:
            atomic_write(outdir / "wg0.netdev", render_netdev(state, show_secrets=True), mode=0o600)
            atomic_write(outdir / "wg0.network", render_network(state), mode=0o644)
        atomic_write(outdir / "90-wg-manager.nft", render_nft(state), mode=0o644)
        atomic_write(outdir / "90-wg-manager.conf.sysctl", render_sysctl(state), mode=0o644)
    except OSError as exc:
        eprint(str(exc))
        raise SystemExit(1)
    # Real system apply when root (require_apply already enforced root/sudo).
    try:
        applied = apply_system_reload(state, backend, firewall, args)
    except OSError as exc:
        eprint(str(exc))
        raise SystemExit(1)
    if not applied:
        raise SystemExit(1)
    audit("reload", "backend=" + backend + " firewall=" + firewall)
    emit(banner("wg-manager reload", [("mode", "APPLIED")], args))
    emit(["", note(t("reload_applied_title"), "applied", args, indent=1),
          note(t("msg_applied"), "ok", args, indent=1)])
    return 0


def cmd_reconfigure(args):
    """Restructure server operation, e.g. NAT66 -> routed native."""
    if getattr(args, "apply", False):
        state = load_state()
    else:
        state = load_state_or_default(args)
    srv = state.get("server", {})
    ip6 = state.get("ipv6", {})
    cur = {
        "endpoint": str(srv.get("endpoint", "")),
        "port": int(srv.get("port", 51820)),
        "mtu": int(srv.get("mtu", 1420)),
        "wan": str(srv.get("wan_iface", "eth0") or "eth0"),
        "ipv6-mode": str(ip6.get("mode", "disabled")),
        "ipv6-prefix": str(ip6.get("prefix", "") or ""),
        "ipv6-wan": str(ip6.get("wan_v6", "") or ""),
    }
    # Proposed values default to current when flags are absent.
    raw_mode = getattr(args, "ipv6_mode", "") or ""
    raw_prefix = getattr(args, "ipv6_prefix", "") or ""
    raw_wan6 = getattr(args, "ipv6_wan", "") or ""
    raw_wan = getattr(args, "wan", "") or ""
    raw_endpoint = getattr(args, "endpoint", "") or ""
    raw_port = getattr(args, "port", None)
    raw_mtu = getattr(args, "mtu", None)
    new_mode = cur["ipv6-mode"]
    if str(raw_mode or "").strip():
        new_mode = validate_ipv6_mode(str(raw_mode).strip())
    new_prefix = cur["ipv6-prefix"]
    if str(raw_prefix or "").strip():
        new_prefix = str(raw_prefix).strip()
    elif raw_mode and new_mode == "disabled":
        new_prefix = ""
    elif not new_prefix and new_mode in ("ula", "nat66"):
        new_prefix = "fd90:90:90::/64"
    new_wan6 = cur["ipv6-wan"]
    if str(raw_wan6 or "").strip():
        cand = str(raw_wan6).strip()
        if "/" in cand:
            validate_prefix(cand)
        else:
            validate_ip(cand)
        new_wan6 = cand
    elif raw_mode and new_mode == "disabled":
        new_wan6 = ""
    new_wan = cur["wan"]
    if str(raw_wan or "").strip():
        # Audit fix: C4 - strict interface name.
        validate_ifname(str(raw_wan).strip())
        new_wan = str(raw_wan).strip()
    new_endpoint = cur["endpoint"]
    if str(raw_endpoint or "").strip():
        validate_endpoint(str(raw_endpoint).strip())
        new_endpoint = str(raw_endpoint).strip()
    new_port = cur["port"]
    if raw_port is not None and str(raw_port).strip() != "":
        new_port = validate_port(raw_port)
    new_mtu = cur["mtu"]
    if raw_mtu is not None and str(raw_mtu).strip() != "":
        new_mtu = validate_mtu(raw_mtu)
    # Validate IPv6 prefix semantics when mode needs it.
    if new_mode != "disabled":
        # When mode or prefix changed, or always, enforce GUA/ULA rules.
        effective_prefix = new_prefix
        new_prefix = validate_reconfigure_prefix(new_mode, effective_prefix)
        if new_mode == "routed" and new_prefix:
            wans = [new_wan6] if new_wan6 else []
            if not wans:
                stored_wan = str(ip6.get("wan_v6", "") or "")
                if stored_wan:
                    wans = [stored_wan]
                else:
                    wans = wan_v6_prefixes_best_effort()
            hit = check_wan_v6_onlink(new_prefix, wans)
            if hit:
                eprint(t("explain_need_delegated_prefix").format(prefix=new_prefix, wan=hit))
                raise SystemExit(1)
    else:
        new_prefix = ""
        new_wan6 = ""
    prop = {
        "endpoint": new_endpoint,
        "port": new_port,
        "mtu": new_mtu,
        "wan": new_wan,
        "ipv6-mode": new_mode,
        "ipv6-prefix": new_prefix,
        "ipv6-wan": new_wan6,
    }
    changes = []
    for field in ("endpoint", "port", "mtu", "wan", "ipv6-mode", "ipv6-prefix", "ipv6-wan"):
        old = str(cur[field])
        new = str(prop[field])
        if old != new:
            changes.append((field, old, new))
    peers = state.get("peers", [])
    active = [p for p in peers if not p.get("tombstoned")]
    # Always show preview before any write; keep QR warning even with no diff.
    if not changes:
        print(t("reconfigure_no_changes"))
        print(t("reconfigure_affected").format(count=len(active)))
        print(t("warn_reconfigure_clients"))
        print(t("reconfigure_next"))
        if not bool(getattr(args, "apply", False)) or bool(getattr(args, "dry_run", False)):
            print(t("msg_dry_run"))
        return 0
    print(t("reconfigure_title"))
    for field, old, new in changes:
        print(t("reconfigure_field").format(field=field, old=old or "-", new=new or "-"))
    print(t("reconfigure_affected").format(count=len(active)))
    print(t("warn_reconfigure_clients"))
    for peer in peers_sorted(active):
        if peer.get("role") == "infra":
            print(t("reconfigure_infra").format(name=peer.get("name", "")))
        else:
            print(t("reconfigure_client").format(name=peer.get("name", "")))
    print(t("reconfigure_next"))
    if not bool(getattr(args, "apply", False)) or bool(getattr(args, "dry_run", False)):
        print(t("msg_dry_run"))
        return 0
    if not require_apply(args, "reconfigure"):
        return 0
    # Apply: update ipv6/server fields, keep tombstone semantics.
    state.setdefault("server", {})["endpoint"] = prop["endpoint"]
    state["server"]["port"] = int(prop["port"])
    state["server"]["mtu"] = int(prop["mtu"])
    state["server"]["wan_iface"] = prop["wan"]
    state.setdefault("ipv6", {})["mode"] = prop["ipv6-mode"]
    state["ipv6"]["prefix"] = prop["ipv6-prefix"]
    if prop["ipv6-mode"] == "disabled":
        state["ipv6"]["hub"] = ""
        state["ipv6"]["wan_v6"] = ""
    else:
        # Refresh hub when prefix changed; keep old hub when still inside.
        old_hub = str(state["ipv6"].get("hub", "") or "")
        try:
            net = ipaddress.ip_network(prop["ipv6-prefix"], strict=False)
            keep = False
            if old_hub:
                try:
                    keep = bool(ipaddress.ip_address(old_hub.split("/")[0]) in net)
                except ValueError:
                    keep = False
            state["ipv6"]["hub"] = old_hub if keep else str(net.network_address + 1)
        except ValueError:
            state["ipv6"]["hub"] = state["ipv6"].get("hub", "")
        state["ipv6"]["wan_v6"] = prop["ipv6-wan"]
    # Audit fix: A5 - recompute peer v6 addresses for the new pool/prefix.
    new_v6net = None
    if prop["ipv6-mode"] != "disabled" and prop["ipv6-prefix"]:
        try:
            new_v6net = ipaddress.ip_network(prop["ipv6-prefix"], strict=False)
        except ValueError:
            new_v6net = None
        # Ensure a v6 client pool exists so peers actually get an address.
        client_pools = [p for p in state.get("pools_v6", []) if p.get("name") == "clients"]
        if not client_pools:
            default_v6 = default_pool_span(prop["ipv6-prefix"], str(state["ipv6"].get("hub", "")), 21, 150)
            if default_v6:
                state.setdefault("pools_v6", []).append({"name": "clients", "range": default_v6, "kind": "next-free"})
        else:
            for cp in client_pools:
                try:
                    parsed = parse_pool_range(cp.get("range", ""), 6)
                    if new_v6net is not None and (parsed.start not in new_v6net or parsed.end not in new_v6net):
                        cp["range"] = default_pool_span(prop["ipv6-prefix"], str(state["ipv6"].get("hub", "")), 21, 150)
                except Exception:  # noqa: BLE001
                    cp["range"] = default_pool_span(prop["ipv6-prefix"], str(state["ipv6"].get("hub", "")), 21, 150)
    for peer in peers_sorted(active):
        peer["needs_reissue"] = True
        if prop["ipv6-mode"] == "disabled":
            peer["v6"] = ""
            continue
        pool_v6 = find_pool(state, peer.get("pool", "clients"), 6)
        if pool_v6 is None:
            pool_v6 = default_pool(state, 6)
        others = [p for p in state.get("peers", []) if p is not peer]
        fresh6 = next_free_ip(pool_v6["range"], others, str(state["ipv6"].get("hub", ""))) if pool_v6 else None
        if fresh6:
            peer["v6"] = fresh6
        else:
            cur6 = str(peer.get("v6", "") or "")
            keep = False
            if cur6 and new_v6net is not None:
                try:
                    keep = bool(ipaddress.ip_address(cur6.split("/")[0]) in new_v6net)
                except ValueError:
                    keep = False
            if not keep:
                peer["v6"] = ""
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(str(exc))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        # Persist only after a successful system apply: a failed apply must not
        # leave a state file claiming the server is configured.
        save_state(state)
        audit("reconfigure", "mode=" + prop["ipv6-mode"] + " prefix=" + prop["ipv6-prefix"])
    print(t("msg_reconfigure_done").format(count=len(active)))
    print(t("reconfigure_next"))
    print(t("msg_applied"))
    return 0

def cmd_check(args):
    state = load_state_or_default(args)
    results = []
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    # Interface check (best-effort offline).
    iface_ok = False
    ip_exe = shutil.which("ip")
    if ip_exe:
        try:
            proc = subprocess.run([ip_exe, "link", "show", ifname], capture_output=True, text=True, timeout=5, check=False)
            iface_ok = proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            iface_ok = False
    else:
        iface_ok = Path("/sys/class/net/" + ifname).exists()
    if iface_ok:
        results.append(("ok", t("check_iface_ok").format(iface=ifname)))
    else:
        results.append(("err", t("check_iface_missing").format(iface=ifname)))
    # Service check.
    ctl = shutil.which("systemctl")
    if ctl:
        backend_choice = srv.get("backend", "networkd")
        backend_svc = "NetworkManager" if backend_choice == "nm" else "systemd-networkd"
        services_to_check = [backend_svc]
        fw_choice = detect_firewall_default()
        if fw_choice == "firewalld":
            services_to_check.append("firewalld")
        else:
            services_to_check.append("nftables")
        for svc in services_to_check:
            try:
                proc = subprocess.run([ctl, "is-active", svc], capture_output=True, text=True, timeout=5, check=False)
                st = proc.stdout.strip() or "unknown"
            except (OSError, subprocess.SubprocessError):
                st = "unknown"
            # Special check for nftables: in Linux, nftables is in the kernel.
            # Even if the systemd unit nftables.service is inactive (or oneshot exited),
            # nftables is active if rules/tables are loaded in the kernel.
            if svc == "nftables" and st != "active":
                nft_exe = shutil.which("nft")
                if nft_exe:
                    try:
                        kproc = subprocess.run([nft_exe, "list", "tables"], capture_output=True, text=True, timeout=5, check=False)
                        if kproc.returncode == 0:
                            st = "active"
                    except (OSError, subprocess.SubprocessError):
                        pass
            role = "ok" if st == "active" else ("skip" if st == "unknown" else "warn")
            results.append((role, t("check_service").format(svc=svc, state=st)))
    else:
        results.append(("skip", t("check_service").format(svc="systemd-networkd", state="unknown")))
    # Forwarding check.
    fwd_path = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        fwd_val = fwd_path.read_text(encoding="utf-8").strip() if fwd_path.exists() else "unknown"
    except OSError:
        fwd_val = "unknown"
    if fwd_val == "1":
        results.append(("ok", t("check_forward_ok")))
    else:
        results.append(("warn", t("check_forward_bad").format(value=fwd_val)))
    # Firewall check.
    nft_ok = False
    nft_exe = shutil.which("nft")
    if nft_exe:
        try:
            proc = subprocess.run([nft_exe, "list", "tables"], capture_output=True, text=True, timeout=5, check=False)
            nft_ok = "wg_manager" in proc.stdout
        except (OSError, subprocess.SubprocessError):
            nft_ok = False
    if nft_ok:
        results.append(("ok", t("check_firewall_ok")))
    else:
        results.append(("skip", t("check_firewall_missing")))
    # Audit host base filter table for drop policy conflicts
    if nft_exe and not SYSROOT:
        try:
            rproc = subprocess.run(
                [nft_exe, "list", "table", "inet", "filter"], capture_output=True, text=True, timeout=5, check=False
            )
            if rproc.returncode == 0 and rproc.stdout:
                txt = rproc.stdout
                has_drop = "policy drop" in txt
                has_wg_input = ("udp dport " + str(srv.get("port", 51820)) in txt) or ("wg-manager" in txt)
                has_wg_fwd = ('iifname "' + str(ifname) + '"' in txt) or ("wg-manager" in txt)
                if has_drop and (not has_wg_input or not has_wg_fwd):
                    results.append(("warn", t("check_host_firewall_conflict")))
                elif has_drop:
                    results.append(("ok", t("check_host_firewall_ok")))
        except (OSError, subprocess.SubprocessError):
            pass
    # Audit firewalld if present and active
    fw_exe = shutil.which("firewall-cmd")
    if fw_exe and not SYSROOT:
        try:
            fproc = subprocess.run([fw_exe, "--state"], capture_output=True, text=True, timeout=5, check=False)
            if fproc.returncode == 0 and "running" in fproc.stdout:
                qproc = subprocess.run(
                    [fw_exe, "--zone=trusted", "--query-interface=" + str(ifname)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if qproc.returncode == 0:
                    results.append(("ok", t("check_firewalld_zone_ok")))
                else:
                    results.append(("warn", t("check_firewalld_zone_conflict")))
        except (OSError, subprocess.SubprocessError):
            pass
    # Audit UFW if present and active
    ufw_exe = shutil.which("ufw")
    if ufw_exe and not SYSROOT:
        try:
            uproc = subprocess.run([ufw_exe, "status"], capture_output=True, text=True, timeout=5, check=False)
            if uproc.returncode == 0 and "Status: active" in uproc.stdout:
                utxt = uproc.stdout
                port_str = str(srv.get("port", 51820))
                has_port = (port_str + "/udp" in utxt) or (port_str in utxt)
                if has_port:
                    results.append(("ok", t("check_ufw_ok")))
                else:
                    results.append(("warn", t("check_ufw_conflict")))
        except (OSError, subprocess.SubprocessError):
            pass
    # Audit SELinux if present
    if not SYSROOT:
        selinux_exe = shutil.which("selinuxenabled")
        if selinux_exe:
            try:
                sproc = subprocess.run([selinux_exe], capture_output=True, timeout=5, check=False)
                if sproc.returncode == 0:
                    getenforce_exe = shutil.which("getenforce")
                    mode_str = "Enforcing"
                    if getenforce_exe:
                        gproc = subprocess.run(
                            [getenforce_exe], capture_output=True, text=True, timeout=5, check=False
                        )
                        mode_str = gproc.stdout.strip() or mode_str
                    results.append(("ok", t("check_selinux_ok").format(mode=mode_str)))
                else:
                    results.append(("skip", t("check_selinux_disabled")))
            except (OSError, subprocess.SubprocessError):
                pass
        # Audit AppArmor if present
        aa_path = Path("/sys/kernel/security/apparmor")
        aa_exe = shutil.which("aa-status")
        if aa_path.exists() or aa_exe:
            try:
                if aa_exe:
                    aproc = subprocess.run([aa_exe, "--enabled"], capture_output=True, timeout=5, check=False)
                    if aproc.returncode == 0:
                        results.append(("ok", t("check_apparmor_ok")))
                    else:
                        results.append(("skip", t("check_apparmor_disabled")))
                elif aa_path.exists():
                    results.append(("ok", t("check_apparmor_ok")))
            except (OSError, subprocess.SubprocessError):
                pass
    # MTU check
    wan_iface = detect_wan_iface()
    wan_mtu = None
    if wan_iface:
        mtu_path = Path("/sys/class/net/" + wan_iface + "/mtu")
        try:
            if mtu_path.exists():
                wan_mtu = int(mtu_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pass
    wg_mtu = int(srv.get("mtu") or 1420)
    if wan_mtu is not None:
        rec_mtu = max(1280, wan_mtu - 80)
        if wan_mtu < 1500 and wg_mtu > rec_mtu:
            results.append(("warn", t("check_mtu_warn").format(wan_mtu=wan_mtu, wg_mtu=wg_mtu, rec_mtu=rec_mtu)))
        else:
            results.append(("ok", t("check_mtu_ok").format(wan_mtu=wan_mtu, wg_mtu=wg_mtu)))
    # MSS clamping check in firewall
    mss_ok = False
    if nft_ok and nft_exe:
        try:
            proc = subprocess.run([nft_exe, "list", "ruleset"], capture_output=True, text=True, timeout=5, check=False)
            if "tcp flags syn tcp option maxseg size set rt mtu" in proc.stdout or "clamp-mss-to-pmtu" in proc.stdout:
                mss_ok = True
        except (OSError, subprocess.SubprocessError):
            pass
    if not mss_ok:
        ipt_exe = shutil.which("iptables")
        if ipt_exe:
            try:
                proc = subprocess.run([ipt_exe, "-S", "FORWARD"], capture_output=True, text=True, timeout=5, check=False)
                if "TCPMSS --clamp-mss-to-pmtu" in proc.stdout:
                    mss_ok = True
            except (OSError, subprocess.SubprocessError):
                pass
    if mss_ok:
        results.append(("ok", t("check_mss_ok")))
    elif nft_ok:
        results.append(("skip", t("check_mss_missing")))
    # Handshake age (best-effort via wg show).
    wg_exe = shutil.which("wg")
    dump = {}
    if wg_exe:
        try:
            proc = subprocess.run([wg_exe, "show", ifname, "dump"], capture_output=True, text=True, timeout=5, check=False)
            for line in proc.stdout.splitlines()[1:]:
                fields = line.split("\t")
                if len(fields) >= 5:
                    try:
                        dump[fields[0]] = int(fields[4])
                    except ValueError:
                        pass
        except (OSError, subprocess.SubprocessError):
            dump = {}
    # Audit fix: A2 - flag peers that request DNS without configured servers.
    server_dns = srv.get("dns", [])
    if isinstance(server_dns, str):
        server_dns = [d for d in server_dns.split(",") if d.strip()]
    now = int(datetime.now(timezone.utc).timestamp())
    for peer in peers_sorted(state.get("peers", [])):
        if peer.get("tombstoned"):
            continue
        exp = peer.get("expires_at")
        if exp and now > int(exp):
            exp_date = datetime.fromtimestamp(int(exp), tz=timezone.utc).strftime("%Y-%m-%d")
            results.append(("warn", t("check_peer_expired").format(name=peer.get("name", ""), date=exp_date)))
        if peer.get("dns_scope", "none") != "none" and not server_dns:
            results.append(("warn", t("check_dns_missing").format(name=peer.get("name", ""), scope=peer.get("dns_scope", "none"))))
        # Audit fix: A7 - skip handshake for peers without a valid public key.
        if not is_valid_wgkey(peer.get("pubkey", "")):
            results.append(("warn", t("warn_peer_bad_key").format(name=peer.get("name", ""))))
            continue
        ts = dump.get(peer.get("pubkey", ""), 0)
        if not ts:
            results.append(("warn", t("check_handshake_stale").format(name=peer.get("name", ""), age="never")))
        else:
            age_s = max(0, now - ts)
            age = str(age_s) + "s" if age_s < 60 else str(age_s // 60) + "m" if age_s < 3600 else str(age_s // 3600) + "h"
            if age_s > 600:
                results.append(("warn", t("check_handshake_stale").format(name=peer.get("name", ""), age=age)))
            else:
                results.append(("ok", t("check_handshake_ok").format(name=peer.get("name", ""), age=age)))
    emit(banner("wg-manager check", args=args))
    emit(["", section("checks", args)])
    pad = max([len("[" + (TAG.get(r) or r) + "]") for r, _ in results] + [0])
    for role, text in results:
        emit(note(text, role, args, indent=1, pad=pad))
    passed = sum(1 for r, _ in results if r == "ok")
    warned = sum(1 for r, _ in results if r == "warn")
    failed = sum(1 for r, _ in results if r == "err")
    skipped = sum(1 for r, _ in results if r == "skip")
    emit(["", section("summary", args),
          "  passed=" + str(passed) + "  warnings=" + str(warned)
          + "  failed=" + str(failed) + "  skipped=" + str(skipped)])
    if failed:
        emit(hint("fix failed rows first, then re-run check.", args))
    return 0

def cmd_backup(args):
    state = load_state()
    dest_raw = getattr(args, "output", "") or ""
    if dest_raw:
        validate_safe_path(dest_raw)
        dest = Path(dest_raw)
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        dest = state_dir() / "backups" / ("manual-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4) + ".json")
        _mkdir_private(dest.parent)
    # Audit fix: N5 - honor the dry-run-by-default gate like every other writer.
    can_write = require_apply(args, "backup")
    if not can_write:
        emit(note("would-backup=" + str(dest), "dryrun", args, indent=1))
        return 0
    payload = json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    atomic_write(dest, payload, mode=0o600)
    audit("backup", "dest=" + str(dest))
    emit(note(t("msg_backup_done").format(path=str(dest)), "ok", args, indent=1))
    return 0

def cmd_rollback(args):
    if getattr(args, "list", False):
        items = list_backups()
        if not items:
            print(t("msg_rollback_list_empty"))
            return 0
        print(t("backup_list_title"))
        for item in items:
            print(str(item))
        return 0
    target = getattr(args, "to", "") or ""
    if not target:
        eprint(usage())
        raise SystemExit(2)
    validate_safe_path(target)
    src = Path(target)
    if not src.exists():
        eprint(t("err_state_corrupt").format(detail=target))
        raise SystemExit(1)
    if not require_apply(args, "rollback"):
        print("would-rollback=" + str(src))
        return 0
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        eprint(t("err_state_corrupt").format(detail=exc))
        raise SystemExit(1)
    # Audit fix: N13 - only a well-formed state object may be restored.
    if not isinstance(data, dict) or not isinstance(data.get("server", {}), dict) or not isinstance(data.get("peers", []), list):
        eprint(t("err_state_corrupt").format(detail="not a state object"))
        raise SystemExit(1)
    with state_lock():
        save_state(data)
        audit("rollback", "to=" + str(src))
    emit(note(t("msg_rollback_done").format(path=str(src)), "ok", args, indent=1))
    return 0


def cmd_status(args):
    state = load_state_or_default(args)
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    dump = get_wg_live_dump(ifname)
    now = int(datetime.now(timezone.utc).timestamp())
    peers = peers_sorted(state.get("peers", []))
    emit(banner("wg-manager status", [("interface", ifname), ("state", state_path())], args))
    if not peers:
        emit(["", note(t("list_empty"), "info", args, indent=1)])
        return 0
    rows = []
    online_count = 0
    for peer in peers:
        name = peer.get("name", "-")
        ip = peer.get("v4", "-") or "-"
        pub = peer.get("pubkey") or peer.get("public_key", "")
        live = dump.get(pub, {}) if pub else {}
        hs = live.get("handshake", 0)
        rx = live.get("rx", 0)
        tx = live.get("tx", 0)
        ep = live.get("endpoint", "-")
        traffic = format_bytes(rx) + " / " + format_bytes(tx) if (rx or tx) else "-"
        if peer.get("tombstoned"):
            st = "tombstoned"
        elif not peer.get("enabled", True):
            st = "disabled"
        elif peer.get("expires_at") and now > int(peer["expires_at"]):
            st = "expired"
        elif hs and (now - hs < 180):
            st = "online"
            online_count += 1
        elif hs:
            st = "idle"
        else:
            st = "never"
        hs_str = format_handshake_age(hs, now)
        rows.append([name, ip, st, hs_str, traffic, ep])

    emit(["", section("live peers", args)])
    headers = ["NAME", "IP", "STATUS", "HANDSHAKE", "RX/TX", "ENDPOINT"]
    priority = ["NAME", "STATUS", "IP", "HANDSHAKE", "RX/TX", "ENDPOINT"]
    emit(table(headers, rows, priority=priority, args=args))
    summary = "total=" + str(len(peers)) + "  online=" + str(online_count) + "  interface=" + ifname
    emit("")
    for chunk in wrap_text(summary, term_width(args) - 2):
        emit("  " + chunk)
    return 0


def cmd_enable(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_enable"), args=args)
        if not name:
            return 0
    validate_name(name)
    found = None
    for peer in state.get("peers", []):
        if peer.get("name") == name:
            found = peer
            break
    if found is None:
        emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
        raise SystemExit(1)
    if not require_apply(args, "enable"):
        emit(note("would-enable=" + name, "dryrun", args, indent=1))
        return 0
    found["enabled"] = True
    found["tombstoned"] = False
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(t("err_apply_failed").format(reason=str(exc)))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        save_state(state)
        audit("enable", "name=" + name)
    emit(note(t("msg_peer_enabled").format(name=name), "applied", args, indent=1))
    return 0


def cmd_disable(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    if not name and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_disable"), args=args)
        if not name:
            return 0
    validate_name(name)
    found = None
    for peer in state.get("peers", []):
        if peer.get("name") == name:
            found = peer
            break
    if found is None:
        emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
        raise SystemExit(1)
    if not require_apply(args, "disable"):
        emit(note("would-disable=" + name, "dryrun", args, indent=1))
        return 0
    found["enabled"] = False
    with state_lock():
        try:
            applied = apply_system_reload(state, state.get("server", {}).get("backend", "networkd") or "networkd", detect_firewall_default(), args)
        except OSError as exc:
            eprint(t("err_apply_failed").format(reason=str(exc)))
            raise SystemExit(1)
        if not applied:
            raise SystemExit(1)
        save_state(state)
        audit("disable", "name=" + name)
    emit(note(t("msg_peer_disabled").format(name=name), "applied", args, indent=1))
    return 0


def cmd_export(args):
    state = load_state()
    name = getattr(args, "name", "") or ""
    all_clients = getattr(args, "all", False)
    out_dir = getattr(args, "out_dir", "") or "."
    peers = state.get("peers", [])
    if not name and not all_clients and sys.stdin.isatty():
        name = _select_peer(state, t("menu_desc_export"), role_filter="client", args=args)
        if not name:
            return 0
    if name:
        target_peers = [p for p in peers if p.get("name") == name and p.get("role", "client") != "infra"]
        if not target_peers:
            emit(note(t("err_peer_not_found").format(name=name), "err", args, indent=1), stream="err")
            raise SystemExit(1)
    else:
        target_peers = [p for p in peers if p.get("role", "client") != "infra" and not p.get("tombstoned")]
    if not target_peers:
        emit(note(t("list_empty"), "info", args, indent=1))
        return 0
    out_path = Path(out_dir).resolve()
    if not require_apply(args, "export"):
        emit(note("would-export=" + str(len(target_peers)) + " configs to " + str(out_path), "dryrun", args, indent=1))
        return 0
    out_path.mkdir(parents=True, exist_ok=True)
    count = 0
    for peer in target_peers:
        conf_text = render_client_conf(state, peer, show_secrets=True)
        conf_file = out_path / (peer.get("name", "peer") + ".conf")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(conf_file), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(conf_text)
        except Exception:
            os.close(fd)
            raise
        count += 1
    emit(note(t("msg_exported").format(count=count, path=str(out_path)), "ok", args, indent=1))
    return 0


def cmd_uninstall(args):
    try:
        state = load_state()
    except (OSError, ValueError):
        state = default_state()

    is_dry = getattr(args, "dry_run", False)
    tty = _stdin_isatty()

    if tty and not getattr(args, "yes", False) and not is_dry:
        if not prompt_yesno("uninstall_confirm"):
            emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
            return 0
        try:
            euid = os.geteuid()
        except AttributeError:
            euid = 1000
        if euid == 0 or getattr(args, "sudo", False):
            args.apply = True
            args.yes = True

    can_write = require_apply(args, "uninstall")
    if not can_write:
        emit(banner(t("uninstall_title"), [("mode", "DRY-RUN")], args))
        emit(note(t("uninstall_dry_title"), "dryrun", args, indent=1))
        for label, path in preview_system_uninstall(state):
            emit(note(label + ": " + path, "dryrun", args, indent=2))
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        emit(note(t("uninstall_keep_bin"), "info", args, indent=1))
        return 0

    apply_system_uninstall(state, args)
    remove_state_data()

    emit(banner(t("uninstall_title"), [("mode", "APPLIED")], args))
    emit(["", note(t("uninstall_done"), "applied", args, indent=1),
          note(t("uninstall_keep_bin"), "ok", args, indent=1)])
    return 0


