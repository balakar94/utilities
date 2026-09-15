# renderers.py
import ipaddress
import re
import shutil
import subprocess

from .crypto import _server_privkey, _server_pubkey, is_valid_wgkey
from .i18n import t
from .ipam import peers_sorted
from .validators import validate_ifname


def _run_capture(cmd, input_text=None, timeout=10):
    try:
        proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)

def render_client_conf(state, peer, show_secrets=True):
    if peer.get("role") == "infra":
        return render_router_conf(state, peer)
    return render_wgquick(state, peer, show_secrets=show_secrets)

def _wan_iface(state):
    srv = state.get("server", {})
    return srv.get("wan_iface") or srv.get("wan") or "eth0"
def _hub_with_len(hub, prefix):
    net = ipaddress.ip_network(prefix, strict=False)
    addr = str(hub).split("/")[0].strip() if hub else str(net.network_address + 1)
    return addr + "/" + str(net.prefixlen)


def _peer_allowed_on_server(state, peer):
    """AllowedIPs for the server side: peer addresses only (/32 and /128)."""
    out = []
    if peer.get("v4"):
        out.append(peer["v4"].split("/")[0].strip() + "/32")
    if peer.get("v6"):
        out.append(peer["v6"].split("/")[0].strip() + "/128")
    for route in peer.get("custom_routes", []) or []:
        out.append(str(route))
    return ", ".join(out) if out else ""


def _client_allowed_ips(state, peer):
    """AllowedIPs for the client side, derived from traffic mode."""
    mode = state.get("ipv6", {}).get("mode", "disabled")
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    traffic = peer.get("traffic", "server-only")
    if traffic == "full-tunnel":
        out = ["0.0.0.0/0"]
        if v6prefix and mode not in ("disabled", "ula"):
            out.append("::/0")
        elif v6prefix and mode == "ula":
            # Audit fix: keep reachability to ULA peers in full-tunnel mode.
            out.append(v6prefix)
        return ", ".join(out)
    if traffic == "custom-routes":
        base = ([v4prefix] if v4prefix else []) + ([v6prefix] if v6prefix else []) + list(peer.get("custom_routes", []) or [])
        return ", ".join(base) if base else ""
    return ", ".join([p for p in (v4prefix, v6prefix) if p])


def render_netdev(state, show_secrets=False):
    """Pure systemd .netdev renderer (config keys and paths stay English)."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    validate_ifname(ifname)
    port = srv.get("port", 51820)
    mtu = srv.get("mtu", 1420)
    priv = _server_privkey(state)
    # Audit fix: C2 - never emit secret material to disk unless it is valid.
    if show_secrets and not is_valid_wgkey(priv):
        raise ValueError(t("err_invalid_wgkey").format(path="server.private_key"))
    if priv and not show_secrets:
        priv = "REDACTED"
    if not priv:
        priv = "REDACTED"
    lines = [
        "# Managed by wg-manager. Do not edit manually.",
        "[NetDev]",
        "Name=" + str(ifname),
        "Kind=wireguard",
        "MTUBytes=" + str(mtu),
        "",
        "[WireGuard]",
        "PrivateKey=" + str(priv),
        "ListenPort=" + str(port),
        "",
    ]
    for peer in peers_sorted(state.get("peers", [])):
        if not peer.get("enabled", True):
            continue
        if peer.get("tombstoned"):
            continue
        if not peer.get("pubkey"):
            continue
        # Audit fix: C2 - reject placeholder peer keys on secret render.
        if show_secrets and not is_valid_wgkey(peer.get("pubkey", "")):
            raise ValueError(t("err_invalid_wgkey").format(path="peer " + str(peer.get("name", "?"))))
        lines.append("[WireGuardPeer]")
        lines.append("# peer: " + peer.get("name", ""))
        lines.append("PublicKey=" + str(peer.get("pubkey", "")))
        if peer.get("psk"):
            psk = peer["psk"] if show_secrets else "REDACTED"
            lines.append("PresharedKey=" + str(psk))
        allowed = _peer_allowed_on_server(state, peer)
        if allowed:
            lines.append("AllowedIPs=" + allowed)
        ka = peer.get("keepalive", 0)
        try:
            ka_n = int(ka)
        except (TypeError, ValueError):
            ka_n = 0
        if ka_n:
            lines.append("PersistentKeepalive=" + str(ka_n))
        lines.append("")
    return "\n".join(lines)


def _systemd_version():
    """Detect systemd major version if available; returns int or None."""
    for bin_name in ("systemctl", "networkctl", "systemd-networkd"):
        exe = shutil.which(bin_name)
        if not exe:
            continue
        rc, out, _err = _run_capture([exe, "--version"])
        if rc == 0 and out:
            parts = out.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1].split(".")[0])
                except (ValueError, IndexError):
                    pass
    return None


def render_network(state):
    """Pure systemd .network renderer."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    validate_ifname(ifname)
    lines = ["# Managed by wg-manager. Do not edit manually.", "[Match]", "Name=" + str(ifname), "", "[Network]"]
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    v4hub = (state.get("ipv4", {}).get("hub") or "").strip()
    if v4prefix:
        lines.append("Address=" + _hub_with_len(v4hub, v4prefix))
    mode = state.get("ipv6", {}).get("mode", "disabled")
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    v6hub = (state.get("ipv6", {}).get("hub") or "").strip()
    if v6prefix and mode != "disabled":
        lines.append("Address=" + _hub_with_len(v6hub, v6prefix))
        # Audit fix: A-net - enforce (not just comment) RA off on the wg iface.
        lines.append("IPv6AcceptRA=false")
    ver = _systemd_version()
    if ver is not None and ver >= 256:
        # Modern systemd (Arch Linux, Fedora 41+, systemd 256+)
        lines.append("IPv4Forwarding=yes")
        if v6prefix and mode != "disabled":
            lines.append("IPv6Forwarding=yes")
    elif ver is not None and ver < 256:
        # Legacy systemd (Debian 12, Ubuntu 22.04/24.04, systemd < 256)
        lines.append("IPForward=yes")
    else:
        # Fallback when version cannot be probed offline: provide universal directives
        lines.append("IPForward=yes")
        lines.append("IPv4Forwarding=yes")
        if v6prefix and mode != "disabled":
            lines.append("IPv6Forwarding=yes")
    lines.append("")
    return "\n".join(lines)


def render_nm(state, show_secrets=False):
    """Pure NetworkManager keyfile renderer."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    validate_ifname(ifname)
    priv = _server_privkey(state)
    # Audit fix: C2 - NM keyfiles are rendered to disk only with a valid key.
    if show_secrets and not is_valid_wgkey(priv):
        raise ValueError(t("err_invalid_wgkey").format(path="server.private_key"))
    if priv and not show_secrets:
        priv = "REDACTED"
    lines = [
        "# Managed by wg-manager. Do not edit manually.",
        "[connection]",
        "id=wg-manager-" + str(ifname),
        "type=wireguard",
        "interface-name=" + str(ifname),
        "",
        "[wireguard]",
        "private-key=" + str(priv if priv else "REDACTED"),
        "listen-port=" + str(srv.get("port", 51820)),
        "",
        "[ipv4]",
        "method=manual",
    ]
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    v4hub = (state.get("ipv4", {}).get("hub") or "").strip()
    if v4prefix:
        lines.append("address1=" + _hub_with_len(v4hub, v4prefix))
    mode = state.get("ipv6", {}).get("mode", "disabled")
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    v6hub = (state.get("ipv6", {}).get("hub") or "").strip()
    lines.extend(["", "[ipv6]", "method=manual" if (v6prefix and mode != "disabled") else "method=disabled"])
    if v6prefix and mode != "disabled":
        lines.append("address1=" + _hub_with_len(v6hub, v6prefix))
    for peer in peers_sorted(state.get("peers", [])):
        if not peer.get("enabled", True) or peer.get("tombstoned") or not peer.get("pubkey"):
            continue
        if show_secrets and not is_valid_wgkey(peer.get("pubkey", "")):
            raise ValueError(t("err_invalid_wgkey").format(path="peer " + str(peer.get("name", "?"))))
        lines.extend(["", "[wireguard-peer." + str(peer.get("pubkey", "")) + "]"])
        if peer.get("psk"):
            psk_val = peer["psk"] if show_secrets else "REDACTED"
            lines.append("preshared-key=" + str(psk_val))
            lines.append("preshared-key-flags=0")
        allowed = _peer_allowed_on_server(state, peer)
        if allowed:
            lines.append("allowed-ips=" + allowed)
        ka = peer.get("keepalive", 0)
        try:
            ka_n = int(ka)
        except (TypeError, ValueError):
            ka_n = 0
        if ka_n:
            lines.append("persistent-keepalive=" + str(ka_n))
    lines.append("")
    return "\n".join(lines)


def render_nft(state):
    """Pure nftables renderer: complementary unified table, idempotent, scoped NAT."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    validate_ifname(ifname)
    port = srv.get("port", 51820)
    wan = srv.get("wan_iface") or srv.get("wan") or "eth0"
    validate_ifname(wan)
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    mode = state.get("ipv6", {}).get("mode", "disabled")
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    lines = [
        "# Managed by wg-manager. Do not edit manually.",
        "# Complementary to the host firewall: this table never sets a drop policy",
        "# on existing traffic; it only accepts the WireGuard flow and clamps MSS.",
        "table inet wg_manager {}",
        "delete table inet wg_manager",
        "table ip wg_manager_nat4 {}",
        "delete table ip wg_manager_nat4",
        "table ip6 wg_manager_nat6 {}",
        "delete table ip6 wg_manager_nat6",
        "",
        "# Ensure host base filter table (e.g. Arch/Debian default inet filter)",
        "# does not drop WireGuard input handshakes or forwarded traffic:",
        "table inet filter {}",
        "add chain inet filter input { type filter hook input priority filter; }",
        "add chain inet filter forward { type filter hook forward priority filter; }",
        'insert rule inet filter input udp dport ' + str(port) + ' accept comment "wg-manager"',
        'insert rule inet filter input iifname "' + str(ifname) + '" accept comment "wg-manager"',
        'add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu comment "wg-manager"',
        'add rule inet filter forward iifname "' + str(ifname) + '" accept comment "wg-manager"',
        'add rule inet filter forward oifname "' + str(ifname) + '" ct state established,related accept comment "wg-manager"',
        "",
        "table inet wg_manager {",
        "  chain input {",
        "    type filter hook input priority filter; policy accept;",
        '    udp dport ' + str(port) + " accept",
        '    iifname "' + str(ifname) + '" accept',
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy accept;",
        "    tcp flags syn tcp option maxseg size set rt mtu",
        '    iifname "' + str(ifname) + '" accept',
        '    oifname "' + str(ifname) + '" ct state established,related accept',
        "  }",
    ]
    has_nat4 = bool(v4prefix)
    has_nat6 = bool(mode == "nat66" and v6prefix)
    if has_nat4 or has_nat6:
        lines.extend([
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
        ])
        if has_nat4:
            lines.append('    ip saddr ' + str(v4prefix) + ' oifname != "' + str(ifname) + '" masquerade')
        if has_nat6:
            lines.append('    ip6 saddr ' + str(v6prefix) + ' oifname != "' + str(ifname) + '" masquerade')
        lines.append("  }")
    lines.extend([
        "}",
        "",
    ])
    return "\n".join(lines)
def firewalld_argv(state):
    """Audit fix: N6 - single source of truth for firewalld changes (argv lists)."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    validate_ifname(ifname)
    port = srv.get("port", 51820)
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    mode = state.get("ipv6", {}).get("mode", "disabled")
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    out = [
        ["firewall-cmd", "--permanent", "--zone=trusted", "--add-interface=" + str(ifname)],
        ["firewall-cmd", "--permanent", "--add-port=" + str(port) + "/udp"],
        ["firewall-cmd", "--permanent", "--add-masquerade"],
    ]
    if v4prefix:
        out.append(["firewall-cmd", "--permanent", "--add-rich-rule", 'rule family="ipv4" source address="' + str(v4prefix) + '" masquerade'])
    if mode == "nat66" and v6prefix:
        out.append(["firewall-cmd", "--permanent", "--add-rich-rule", 'rule family="ipv6" source address="' + str(v6prefix) + '" masquerade'])
    out.append(["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv4", "filter", "FORWARD", "0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])
    if mode != "disabled":
        out.append(["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv6", "filter", "FORWARD", "0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])
    out.append(["firewall-cmd", "--reload"])
    return out


def render_firewalld(state):
    """Render firewalld commands as printable strings (pure, from firewalld_argv)."""
    return [" ".join(argv) for argv in firewalld_argv(state)]


def render_sysctl(state):
    """Pure sysctl renderer: forwarding plus per-iface loose rp_filter."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    validate_ifname(ifname)
    wan = srv.get("wan_iface") or srv.get("wan") or "eth0"
    validate_ifname(wan)
    mode = state.get("ipv6", {}).get("mode", "disabled")
    lines = [
        "# Managed by wg-manager. Do not edit manually.",
        "net.ipv4.ip_forward = 1",
        "net.ipv4.conf.all.forwarding = 1",
        "net.ipv4.conf.default.forwarding = 1",
        "net.ipv4.conf." + str(wan) + ".forwarding = 1",
        "net.ipv4.conf." + str(ifname) + ".forwarding = 1",
    ]
    # Audit fix: N15 - only enable IPv6 forwarding when IPv6 is in use.
    if mode != "disabled":
        lines.extend([
            "net.ipv6.conf.all.forwarding = 1",
            "net.ipv6.conf.default.forwarding = 1",
            "net.ipv6.conf." + str(wan) + ".forwarding = 1",
            "net.ipv6.conf." + str(ifname) + ".forwarding = 1",
        ])
    lines.extend([
        "# Loose RPF: all and per-iface must allow loose mode for tunnel routing.",
        "net.ipv4.conf.all.rp_filter = 2",
        "net.ipv4.conf.default.rp_filter = 2",
        "net.ipv4.conf." + str(wan) + ".rp_filter = 2",
        "net.ipv4.conf." + str(ifname) + ".rp_filter = 2",
        "# Keep IPv6 RA on WAN only; wg interfaces use static addresses.",
        "# net.ipv6.conf." + str(wan) + ".accept_ra = 1",
        "# net.ipv6.conf." + str(ifname) + ".accept_ra = 0",
    ])
    return "\n".join(lines) + "\n"
def _bracket_endpoint(host):
    h = str(host).strip()
    if ":" in h and not (h.startswith("[") and h.endswith("]")):
        return "[" + h + "]"
    return h


def render_rsc(state, peer, show_secrets=True):
    """Pure MikroTik RouterOS renderer for one peer."""
    srv = state.get("server", {})
    ifname = srv.get("ifname", "wg0")
    mtu = srv.get("mtu", 1420)
    endpoint = srv.get("endpoint", "")
    port = srv.get("port", 51820)
    server_pub = _server_pubkey(state)
    mode = state.get("ipv6", {}).get("mode", "disabled")
    lines = ["# Managed by wg-manager. Do not edit manually.", "# peer: " + str(peer.get("name", ""))]
    # Interface creation with private-key if present
    wg_iface = '/interface wireguard add name="' + str(ifname) + '" mtu=' + str(mtu)
    if peer.get("privkey"):
        priv = peer["privkey"] if show_secrets else "REDACTED"
        wg_iface += ' private-key="' + str(priv) + '"'
    lines.append(wg_iface)
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    if peer.get("v4"):
        v4_pl = str(ipaddress.ip_network(v4prefix, strict=False).prefixlen) if v4prefix else "32"
        lines.append('/ip address add address="' + peer["v4"].split("/")[0].strip() + '/' + v4_pl + '" interface="' + str(ifname) + '"')
    if peer.get("v6"):
        v6_pl = str(ipaddress.ip_network(v6prefix, strict=False).prefixlen) if v6prefix else "128"
        lines.append('/ipv6 address add address="' + peer["v6"].split("/")[0].strip() + '/' + v6_pl + '" interface="' + str(ifname) + '" advertise=no')
    allowed = _client_allowed_ips(state, peer)
    ka = peer.get("keepalive", 0)
    try:
        ka_n = int(ka)
    except (TypeError, ValueError):
        ka_n = 0
    peer_line = '/interface wireguard peers add interface="' + str(ifname) + '" public-key="' + str(server_pub) + '"'
    if peer.get("psk"):
        psk_val = peer["psk"] if show_secrets else "REDACTED"
        peer_line += ' preshared-key="' + str(psk_val) + '"'
    if endpoint:
        # Audit fix: N10 - RouterOS takes a bare address (no brackets).
        peer_line += ' endpoint-address="' + str(endpoint).strip().strip("[]") + '" endpoint-port=' + str(port)
    if allowed:
        peer_line += ' allowed-address="' + allowed + '"'
    if ka_n:
        peer_line += " persistent-keepalive=" + str(ka_n) + "s"
    lines.append(peer_line)
    # Audit fix: A2 - push DNS servers when the peer requests a DNS scope.
    dns_scope = peer.get("dns_scope", "none")
    dns_list = srv.get("dns", [])
    if isinstance(dns_list, str):
        dns_list = [d for d in dns_list.split(",") if d.strip()]
    if dns_scope != "none" and dns_list:
        lines.append('/ip dns set servers=' + ",".join(str(d) for d in dns_list) + ' comment="wg-manager"')
    # Routes via wg0.
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    if v4prefix:
        lines.append('/ip route add dst-address="' + v4prefix + '" gateway="' + str(ifname) + '"')
    if v6prefix and mode not in ("disabled", "ula"):
        lines.append('/ipv6 route add dst-address="' + v6prefix + '" gateway="' + str(ifname) + '"')
    # Full-tunnel guard: keep endpoint reachable via WAN gateway.
    if peer.get("traffic") == "full-tunnel" and endpoint:
        wan_gw = srv.get("wan_gw", "")
        host = str(endpoint).split("/")[0].strip()
        eip = None
        try:
            eip = ipaddress.ip_address(host)
        except ValueError:
            eip = None
        if wan_gw and eip is not None:
            suffix = "/32" if eip.version == 4 else "/128"
            lines.append('/ip route add dst-address="' + str(eip) + suffix + '" gateway="' + str(wan_gw) + '" comment="keep wg endpoint via WAN"')
        elif eip is not None:
            suffix = "/32" if eip.version == 4 else "/128"
            lines.append('# IMPORTANT full-tunnel: add destination ' + str(eip) + suffix + ' via the WAN gateway or the wg UDP flow enters the tunnel.')
        else:
            lines.append('# IMPORTANT full-tunnel: resolve endpoint ' + str(endpoint) + ' to an IP and add a host route via the WAN gateway.')
    return "\n".join(lines) + "\n"


def render_router_conf(state, peer, show_secrets=True):
    """Universal WireGuard configuration for a remote router or server peer (OpenWrt, Linux, VyOS, pfSense)."""
    srv = state.get("server", {})
    endpoint = srv.get("endpoint", "")
    port = srv.get("port", 51820)
    server_pub = _server_pubkey(state)
    addrs = []
    v4prefix = (state.get("ipv4", {}).get("prefix") or "").strip()
    v6prefix = (state.get("ipv6", {}).get("prefix") or "").strip()
    if peer.get("v4"):
        v4_pl = str(ipaddress.ip_network(v4prefix, strict=False).prefixlen) if v4prefix else "32"
        addrs.append(peer["v4"].split("/")[0].strip() + "/" + v4_pl)
    if peer.get("v6"):
        v6_pl = str(ipaddress.ip_network(v6prefix, strict=False).prefixlen) if v6prefix else "128"
        addrs.append(peer["v6"].split("/")[0].strip() + "/" + v6_pl)
    priv = peer.get("privkey", "")
    if priv and not show_secrets:
        priv = "REDACTED"
    lines = [
        "# WireGuard router/server peer configuration for: " + str(peer.get("name", "")),
        "# Compatible with OpenWrt, Linux, VyOS, pfSense, OPNsense, etc.",
        "",
        "[Interface]",
    ]
    if priv:
        lines.append("PrivateKey = " + str(priv))
    else:
        lines.append("# PrivateKey = <private-key-generated-on-remote-router>")
    if addrs:
        lines.append("Address = " + ", ".join(addrs))
    lines.extend([
        "",
        "[Peer]",
        "PublicKey = " + str(server_pub),
    ])
    if peer.get("psk"):
        psk_val = peer["psk"] if show_secrets else "REDACTED"
        lines.append("PresharedKey = " + str(psk_val))
    allowed = _client_allowed_ips(state, peer)
    if allowed:
        lines.append("AllowedIPs = " + allowed)
    if endpoint:
        lines.append("Endpoint = " + _bracket_endpoint(endpoint) + ":" + str(port))
    ka = peer.get("keepalive", 0)
    try:
        ka_n = int(ka)
    except (TypeError, ValueError):
        ka_n = 0
    if ka_n:
        lines.append("PersistentKeepalive = " + str(ka_n))
    return "\n".join(lines) + "\n"


def render_wgquick(state, peer, show_secrets=False):
    """Pure wg-quick renderer used for QR and text fallback."""
    srv = state.get("server", {})
    endpoint = srv.get("endpoint", "")
    port = srv.get("port", 51820)
    server_pub = _server_pubkey(state)
    priv = peer.get("privkey", "") or peer.get("private_key", "")
    # Audit fix: C3 - quick configs must never carry REDACTED/placeholder keys.
    if show_secrets and not is_valid_wgkey(priv):
        raise ValueError(t("err_peer_no_privkey").format(name=str(peer.get("name", "?"))))
    if priv and not show_secrets:
        priv = "REDACTED"
    addrs = []
    if peer.get("v4"):
        addrs.append(peer["v4"].split("/")[0].strip() + "/32")
    if peer.get("v6"):
        addrs.append(peer["v6"].split("/")[0].strip() + "/128")
    lines = ["[Interface]", "PrivateKey = " + str(priv if priv else "REDACTED")]
    if addrs:
        lines.append("Address = " + ", ".join(addrs))
    mtu = srv.get("mtu", 1420)
    lines.append("MTU = " + str(mtu))
    dns_scope = peer.get("dns_scope", "none")
    # Audit fix: A2 - tunnel scope uses the hub, all scope uses configured servers.
    dns_note = "wg-manager"
    if dns_scope == "tunnel":
        hub4 = (state.get("ipv4", {}).get("hub") or "").strip()
        dns_list = srv.get("dns", [])
        if isinstance(dns_list, str):
            dns_list = [d for d in dns_list.split(",") if d.strip()]
        if hub4:
            lines.append("DNS = " + hub4 + "  # " + dns_note)
        elif dns_list:
            lines.append("DNS = " + ", ".join(str(d) for d in dns_list) + "  # " + dns_note)
    elif dns_scope == "all":
        dns_list = srv.get("dns", [])
        if isinstance(dns_list, str):
            dns_list = [d for d in dns_list.split(",") if d.strip()]
        if dns_list:
            lines.append("DNS = " + ", ".join(str(d) for d in dns_list) + "  # " + dns_note)
        elif hub4:
            lines.append("DNS = " + hub4 + "  # " + dns_note)
        else:
            lines.append("DNS = 1.1.1.1, 8.8.8.8  # " + dns_note)
    lines.extend(["", "[Peer]", "PublicKey = " + str(server_pub)])
    if peer.get("psk"):
        psk = peer["psk"] if show_secrets else "REDACTED"
        lines.append("PresharedKey = " + str(psk))
    allowed = _client_allowed_ips(state, peer)
    if allowed:
        lines.append("AllowedIPs = " + allowed)
    if endpoint:
        lines.append("Endpoint = " + _bracket_endpoint(endpoint) + ":" + str(port))
    try:
        ka_n = int(peer.get("keepalive", 0))
    except (TypeError, ValueError):
        ka_n = 0
    if ka_n:
        lines.append("PersistentKeepalive = " + str(ka_n))
    return "\n".join(lines) + "\n"


def redact_text(text, show_secrets=False):
    # Audit fix: N18 - redact key material anywhere on the line (and JSON).
    if show_secrets:
        return text
    out = []
    secret_kv = re.compile(r"(?i)((?:private[-_ ]?key|preshared[-_ ]?key)\s*[=:]\s*)(\S+)")
    secret_json = re.compile(r"(?i)(\"(?:privkey|private_key|preshared_key|psk)\"\s*:\s*\")([^\"]*)(\")")
    for line in str(text).splitlines():
        line = secret_json.sub(lambda m: m.group(1) + "REDACTED" + m.group(3), line)
        if secret_kv.search(line):
            line = secret_kv.sub(lambda m: m.group(1) + "REDACTED", line)
        out.append(line)
    return "\n".join(out)


def render_wg_syncconf(state, show_secrets=True):
    """Pure WireGuard configuration renderer for live kernel sync (wg syncconf)."""
    srv = state.get("server", {})
    port = srv.get("port", 51820)
    priv = _server_privkey(state)
    lines = [
        "[Interface]",
        "ListenPort = " + str(port),
    ]
    if priv and is_valid_wgkey(priv) and show_secrets:
        lines.append("PrivateKey = " + str(priv))
    for peer in peers_sorted(state.get("peers", [])):
        if not peer.get("enabled", True) or peer.get("tombstoned") or not peer.get("pubkey"):
            continue
        pk = str(peer.get("pubkey", ""))
        if not is_valid_wgkey(pk):
            continue
        lines.extend(["", "[Peer]", "PublicKey = " + pk])
        if peer.get("psk"):
            psk = peer["psk"] if show_secrets else "REDACTED"
            lines.append("PresharedKey = " + str(psk))
        allowed = _peer_allowed_on_server(state, peer)
        if allowed:
            lines.append("AllowedIPs = " + allowed)
        ka = peer.get("keepalive", 0)
        try:
            ka_n = int(ka)
        except (TypeError, ValueError):
            ka_n = 0
        if ka_n:
            lines.append("PersistentKeepalive = " + str(ka_n))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- system ops

