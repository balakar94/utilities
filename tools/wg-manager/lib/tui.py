# tui.py
import argparse
import re
import sys
import time
from pathlib import Path

from .commands import (
    _peer_state,
    cmd_add,
    cmd_backup,
    cmd_check,
    cmd_delete,
    cmd_disable,
    cmd_edit,
    cmd_enable,
    cmd_export,
    cmd_init,
    cmd_list,
    cmd_purge,
    cmd_qr,
    cmd_reclaim,
    cmd_reconfigure,
    cmd_reload,
    cmd_rollback,
    cmd_show,
    cmd_status,
    cmd_uninstall,
)
from .constants import C_ERR, C_OK, DEFAULT_STATE_PATH, PROG, VERSION
from .i18n import LANG, STRINGS, current_lang, t
from .ipam import peers_sorted
from .presentation import (
    _stdin_isatty,
    banner,
    clear_screen,
    clip,
    color_enabled,
    cwrap,
    emit,
    eprint,
    note,
    paint,
    table,
    term_width,
)
from .renderers import _wan_iface
from .state import _is_initialized, load_state, state_path
from .system import (
    detect_firewall_default,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def visible_len(s):
    """Visible terminal width of a string ignoring ANSI escape codes."""
    return len(_ANSI_RE.sub("", str(s)))


_HANDLERS = {
    "init": cmd_init,
    "add": cmd_add,
    "edit": cmd_edit,
    "delete": cmd_delete,
    "list": cmd_list,
    "show": cmd_show,
    "qr": cmd_qr,
    "purge": cmd_purge,
    "reclaim": cmd_reclaim,
    "reconfigure": cmd_reconfigure,
    "reload": cmd_reload,
    "check": cmd_check,
    "backup": cmd_backup,
    "rollback": cmd_rollback,
    "status": cmd_status,
    "enable": cmd_enable,
    "disable": cmd_disable,
    "export": cmd_export,
    "uninstall": cmd_uninstall,
}

_SHORTCUTS = {
    "a": "add",
    "l": "list",
    "s": "status",
    "c": "check",
    "r": "reload",
    "b": "backup",
    "e": "edit",
    "d": "delete",
    "x": "export",
    "t": "export",
    "q": "quit",
    "0": "quit",
    "i": "init",
    "v": "show",
    "g": "qr",
    "k": "reclaim",
    "p": "purge",
    "u": "rollback",
    "o": "enable",
    "f": "disable",
    "w": "reconfigure",
    "h": "check",
}

_SHORTCUT_HINTS = {
    "list": "l",
    "add": "a",
    "show": "v",
    "qr": "g",
    "edit": "e",
    "enable": "o",
    "disable": "f",
    "delete": "d",
    "reclaim": "k",
    "purge": "p",
    "status": "s",
    "reload": "r",
    "check": "c",
    "reconfigure": "w",
    "export": "x",
    "backup": "b",
    "rollback": "u",
}



_SHORT_DESCS = {
    "es": {
        "list": "Listar peers",
        "add": "Anadir nuevo peer",
        "show": "Ver configuracion",
        "qr": "Codigo QR movil",
        "edit": "Editar parametros",
        "enable": "Activar peer",
        "disable": "Desactivar peer",
        "delete": "Tombstone (baja)",
        "reclaim": "Liberar IP",
        "purge": "Purgar bajas",
        "init": "Asistente inicial",
        "status": "Telemetria en vivo",
        "reload": "Aplicar y recargar",
        "check": "Chequeo de salud",
        "reconfigure": "Cambiar red",
        "reconfig": "Cambiar red",
        "export": "Exportar .conf",
        "backup": "Copia seguridad",
        "rollback": "Restaurar backup",
    },
    "de": {
        "list": "Peers auflisten",
        "add": "Neuen Peer anlegen",
        "show": "Konfiguration zeigen",
        "qr": "QR-Code erzeugen",
        "edit": "Peer bearbeiten",
        "enable": "Peer aktivieren",
        "disable": "Peer deaktivieren",
        "delete": "Peer stilllegen",
        "reclaim": "IP freigeben",
        "purge": "Geloeschte leeren",
        "init": "Einrichtungsassistent",
        "status": "Live-Telemetrie",
        "reload": "Anwenden & neu laden",
        "check": "Integritaetstest",
        "reconfigure": "Netzwerk aendern",
        "reconfig": "Netzwerk aendern",
        "export": "Exportieren .conf",
        "backup": "Backup erstellen",
        "rollback": "Aus Backup wiederherstellen",
    },
    "en": {
        "list": "List all peers",
        "add": "Add new peer",
        "show": "Show peer config",
        "qr": "Generate QR code",
        "edit": "Edit parameters",
        "enable": "Enable peer",
        "disable": "Disable peer",
        "delete": "Tombstone peer",
        "reclaim": "Reclaim peer IP",
        "purge": "Purge tombstoned",
        "init": "Setup wizard",
        "status": "Live telemetry",
        "reload": "Apply & reload",
        "check": "Health check",
        "reconfigure": "Change network",
        "reconfig": "Change network",
        "export": "Export .conf files",
        "backup": "Create backup",
        "rollback": "Restore backup",
    },
}


def _format_item(num_str, label, sc, target_w, args=None):
    lang = current_lang()
    lang_map = _SHORT_DESCS.get(lang, _SHORT_DESCS["en"])
    desc = lang_map.get(label, label)

    n_str = f"{int(num_str):2d}"
    display_cmd = "reconfig" if label == "reconfigure" else label
    lbl_str = f"{display_cmd:<8}"
    sc_str = f"[{sc}]" if sc else "   "

    avail = max(4, target_w - 18)
    d_str = clip(desc, avail)

    space_count = max(1, target_w - 17 - visible_len(d_str))
    padding = " " * space_count

    if not color_enabled(args):
        line = f"[{n_str}] {lbl_str} {d_str}{padding}{sc_str}"
        return line[:target_w].ljust(target_w)

    p_num = paint("[", "rule", args) + paint(n_str, "num", args) + paint("] ", "rule", args)
    p_lbl = paint(lbl_str, "cmd", args) + " "
    p_desc = paint(d_str, "value", args)
    p_sc = (paint("[", "rule", args) + paint(sc, "shortcut", args) + paint("]", "rule", args)) if sc else "   "

    return p_num + p_lbl + p_desc + padding + p_sc


def _safe_t(key, fallback=""):
    try:
        return t(key)
    except Exception:  # noqa: BLE001
        return fallback


def _menu_banner_lines(args):
    """Banner with product, version, language and state path (width-safe)."""
    try:
        path = str(state_path())
    except (OSError, ValueError):
        path = DEFAULT_STATE_PATH
    mode = "APPLY" if getattr(args, "apply", False) else "DRY-RUN"
    title = PROG + " " + VERSION + " [" + current_lang() + "]  *  WireGuard Manager  [" + mode + "]"
    return banner(title, [("state", path)], args)




def _menu_forwarding_state():
    """Best-effort read of IPv4 forwarding flag: ON, OFF or unknown."""
    try:
        val = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, ValueError):
        return "unknown"
    if val == "1":
        return "ON"
    if val == "0":
        return "OFF"
    return "unknown"


def _menu_firewall_default():
    """Best-effort firewall default without writes: firewalld or nft."""
    try:
        return str(detect_firewall_default())
    except Exception:  # noqa: BLE001
        return "-"


def _menu_status_lines(args):
    """Best-effort read-only status snapshot; never raises, never writes."""
    try:
        path = str(state_path())
    except (OSError, ValueError):
        path = DEFAULT_STATE_PATH
    try:
        has_state = Path(path).exists()
    except OSError:
        has_state = False
    fwd = _menu_forwarding_state()
    lbl_server = _safe_t("menu_box_server", "Server")
    lbl_net = _safe_t("menu_box_net", "Net")
    lbl_v6 = _safe_t("menu_box_ipv6", "IPv6")
    lbl_fwd = _safe_t("menu_box_fwd", "Forwarding")
    lbl_peers = _safe_t("menu_box_peers", "Peers")
    lbl_warn = _safe_t("menu_warn", "Warnings")
    if not has_state:
        warn_no = _safe_t("menu_warn_no_state", "NO STATE -> run init")
        return [
            (lbl_server, "-", "muted"),
            (lbl_net, "-", "muted"),
            (lbl_v6, "-", "muted"),
            (lbl_fwd, fwd, "ok" if fwd == "ON" else ("err" if fwd == "OFF" else "muted")),
            (lbl_peers, "total=0 active=0 infra=0 clients=0 tombstoned=0 needs_reissue=0", "muted"),
            (lbl_warn, warn_no, "warn"),
        ]
    try:
        state = load_state()
    except (OSError, ValueError):
        try:
            detail = t("menu_no_state").format(path=path)
        except (KeyError, IndexError, ValueError):
            detail = "No state at " + path
        return [
            (lbl_server, "-", "muted"),
            (lbl_net, "-", "muted"),
            (lbl_v6, "-", "muted"),
            (lbl_fwd, fwd, "ok" if fwd == "ON" else ("err" if fwd == "OFF" else "muted")),
            (lbl_peers, "total=0 active=0 infra=0 clients=0 tombstoned=0 needs_reissue=0", "muted"),
            (lbl_warn, detail, "warn"),
        ]
    try:
        if not isinstance(state, dict):
            raise TypeError("bad state")
        server = state.get("server", {})
        ipv6 = state.get("ipv6", {})
        peers = state.get("peers", [])
        if not isinstance(server, dict):
            server = {}
        if not isinstance(ipv6, dict):
            ipv6 = {}
        if not isinstance(peers, list):
            peers = []
        endpoint = str(server.get("endpoint", "-") or "-")
        port = str(server.get("port", "-") or "-")
        backend = str(server.get("backend", "-") or "-")
        try:
            wan = str(_wan_iface(state) or "-")
        except Exception:  # noqa: BLE001
            wan = "-"
        fw = _menu_firewall_default()
        mode = str(ipv6.get("mode", "-") or "-")
        prefix = str(ipv6.get("prefix", "") or "-")
        hub = str(ipv6.get("hub", "") or "-")
        total = len([p for p in peers if isinstance(p, dict)])
        tomb = sum(1 for p in peers if isinstance(p, dict) and p.get("tombstoned"))
        active = sum(1 for p in peers if isinstance(p, dict) and not p.get("tombstoned") and p.get("enabled", True))
        infra = sum(1 for p in peers if isinstance(p, dict) and p.get("role") == "infra" and not p.get("tombstoned"))
        clients = sum(1 for p in peers if isinstance(p, dict) and p.get("role") != "infra" and not p.get("tombstoned"))
        reissue = sum(1 for p in peers if isinstance(p, dict) and p.get("needs_reissue") and not p.get("tombstoned"))
        warnings = []
        if reissue > 0:
            try:
                warnings.append(t("menu_warn_reissue").format(count=reissue))
            except (KeyError, IndexError, ValueError):
                warnings.append(str(reissue) + " peer(s) need reissue")
        if fwd == "OFF":
            try:
                warnings.append(t("menu_warn_fwd_off"))
            except Exception:  # noqa: BLE001
                warnings.append("forwarding OFF")
        warn_text = "; ".join(warnings) if warnings else "-"
        return [
            (lbl_server, endpoint + ":" + port, "accent" if endpoint != "-" else "muted"),
            (lbl_net, "backend=" + backend + " firewall=" + fw + " wan=" + wan, "value"),
            (lbl_v6, mode + " " + prefix + " hub=" + hub, "value"),
            (lbl_fwd, fwd, "ok" if fwd == "ON" else ("err" if fwd == "OFF" else "muted")),
            (lbl_peers, "total=" + str(total) + " active=" + str(active) + " infra=" + str(infra)
             + " clients=" + str(clients) + " tombstoned=" + str(tomb) + " needs_reissue=" + str(reissue), "value"),
            (lbl_warn, warn_text, "warn" if warnings else "muted"),
        ]
    except Exception:  # noqa: BLE001
        try:
            detail = t("menu_no_state").format(path=path)
        except (KeyError, IndexError, ValueError):
            detail = "No state at " + path
        return [(lbl_warn, detail, "warn")]


def _menu_peers_preview_lines(args):
    """Peers preview table, permanents-first, max 6 rows; empty when no state."""
    try:
        path = str(state_path())
    except (OSError, ValueError):
        return []
    try:
        if not Path(path).exists():
            return []
        state = load_state()
    except (OSError, ValueError):
        return []
    try:
        peers = state.get("peers", [])
        if not isinstance(peers, list):
            return []
        ordered = peers_sorted([p for p in peers if isinstance(p, dict)])
    except Exception:  # noqa: BLE001
        return []
    if not ordered:
        try:
            return [note(t("list_empty"), "info", args, indent=1)]
        except Exception:  # noqa: BLE001
            return []
    rows = [[str(p.get("name", "-") or "-"), str(p.get("role", "-") or "-"),
             str(p.get("v4", "-") or "-"), str(p.get("v6", "-") or "-"),
             _peer_state(p)] for p in ordered[:6]]
    lines = table(["NAME", "ROLE", "V4", "V6", "STATE"], rows,
                  priority=["NAME", "STATE", "ROLE", "V4", "V6"], args=args)
    if len(ordered) > 6:
        try:
            more = t("menu_more").format(count=len(ordered) - 6)
        except (KeyError, IndexError, ValueError):
            more = "...+" + str(len(ordered) - 6) + " more (use list)"
        lines.append(paint("  " + more, "muted", args))
    return lines


def _menu_pause_tty(args):
    """TTY-only pause; EOF-safe, Ctrl-C aborts with code 130."""
    try:
        if not sys.stdin.isatty():
            return 0
    except (OSError, ValueError):
        return 0
    try:
        input(t("menu_continue"))
    except EOFError:
        return 0
    except KeyboardInterrupt:
        eprint(t("interrupted"))
        return 130
    return 0


def _menu_items():
    """Ordered menu commands (1-17); init is handled on first run."""
    return [
        ("1", "list"),
        ("2", "add"),
        ("3", "show"),
        ("4", "qr"),
        ("5", "edit"),
        ("6", "enable"),
        ("7", "disable"),
        ("8", "delete"),
        ("9", "reclaim"),
        ("10", "purge"),
        ("11", "status"),
        ("12", "reload"),
        ("13", "check"),
        ("14", "reconfigure"),
        ("15", "export"),
        ("16", "backup"),
        ("17", "rollback"),
    ]


def _box_chars():
    can_u = "utf" in (sys.stdout.encoding or "").lower()
    return {
        "tl": "\u250c" if can_u else "+",
        "tr": "\u2510" if can_u else "+",
        "bl": "\u2514" if can_u else "+",
        "br": "\u2518" if can_u else "+",
        "h": "\u2500" if can_u else "-",
        "v": "\u2502" if can_u else "|",
        "div_l": "\u251c" if can_u else "+",
        "div_r": "\u2524" if can_u else "+",
        "bullet": "\u2022" if can_u else "*",
    }


def _print_menu_screen(args, flash=None):
    """Full-screen boxed cockpit dashboard with live status and 2-column menu."""
    width = max(60, min(term_width(args), 120))
    chars = _box_chars()
    v = chars["v"]
    h = chars["h"]
    inner = width - 2

    def box_line(left_text="", right_text="", left_role=None, right_role=None):
        p_left = paint(left_text, left_role, args) if left_role else str(left_text)
        p_right = paint(right_text, right_role, args) if right_role else str(right_text)
        v_left = visible_len(p_left)
        v_right = visible_len(p_right)
        if right_text:
            space = max(1, inner - v_left - v_right)
            return paint(v, "rule", args) + p_left + (" " * space) + p_right + paint(v, "rule", args)
        space = max(0, inner - v_left)
        return paint(v, "rule", args) + p_left + (" " * space) + paint(v, "rule", args)

    top = chars["tl"] + (h * inner) + chars["tr"]
    sep = chars["div_l"] + (h * inner) + chars["div_r"]
    bot = chars["bl"] + (h * inner) + chars["br"]

    try:
        path = str(state_path())
    except (OSError, ValueError):
        path = DEFAULT_STATE_PATH
    mode_label = "APPLY" if getattr(args, "apply", False) else "DRY-RUN"
    lang = current_lang()

    title_left = "  " + paint(PROG + " " + VERSION, "title", args) + " " + paint(chars["bullet"], "accent", args) + " " + paint("WireGuard Control Center", "title", args)
    title_right = paint("[" + lang.upper() + "]", "accent", args) + " " + paint("[AUTO]", "ok", args) + "  "

    state_lbl = "Estado" if lang == "es" else ("Status" if lang == "de" else "State")
    mode_safe = "MODO SEGURO" if lang == "es" else ("SICHERER MODUS" if lang == "de" else "SAFE MODE")
    sub_left = "  " + paint(state_lbl + ":", "label", args) + " " + paint(clip(path, max(12, inner - 35)), "value", args)
    mode_colored = paint(mode_label, "ok", args) if mode_label == "APPLY" else paint(mode_label, "warn", args)
    sub_right = paint("[ " + mode_safe + ": ", "label", args) + mode_colored + paint(" ]  ", "label", args)

    lines = []
    if flash:
        f_text = "  [OK] " + str(flash)
        lines.append(paint(chars["tl"] + (h * inner) + chars["tr"], "ok", args))
        lines.append(box_line(paint(f_text, "ok", args)))
        lines.append(paint(chars["bl"] + (h * inner) + chars["br"], "ok", args))

    lines.append(paint(top, "rule", args))
    lines.append(box_line(title_left, title_right))
    lines.append(box_line(sub_left, sub_right))
    lines.append(paint(sep, "rule", args))

    # Status Section
    st_title = "ESTADO DEL SERVIDOR" if lang == "es" else ("SERVERSTATUS" if lang == "de" else "SERVER STATUS")
    lines.append(box_line("  " + paint(chars["bullet"] + " " + st_title, "section", args)))

    status_dict = {str(item[0]): item for item in _menu_status_lines(args)}
    lbl_srv = t("menu_box_server")
    lbl_net = t("menu_box_net")
    lbl_v6 = t("menu_box_ipv6")
    lbl_fwd = t("menu_box_fwd")
    lbl_prs = t("menu_box_peers")
    lbl_wrn = t("menu_warn")

    srv_val = str(status_dict.get(lbl_srv, (lbl_srv, "-"))[1])
    net_val = str(status_dict.get(lbl_net, (lbl_net, "-"))[1])
    v6_val = str(status_dict.get(lbl_v6, (lbl_v6, "-"))[1])
    fwd_val = str(status_dict.get(lbl_fwd, (lbl_fwd, "-"))[1])
    prs_val = str(status_dict.get(lbl_prs, (lbl_prs, "-"))[1])
    wrn_val = str(status_dict.get(lbl_wrn, (lbl_wrn, "-"))[1])

    lbl_ep = "Endpoint:"
    net_lbl = "Red:" if lang == "es" else ("Netz:" if lang == "de" else "Net:")
    prs_lbl = "Peers:"
    wrn_lbl = "Avisos:" if lang == "es" else ("Warnungen:" if lang == "de" else "Warnings:")

    l1_left = "  " + paint(lbl_ep, "label", args) + " " + paint(srv_val, "value", args)
    l1_right = paint("IPv6:", "label", args) + " " + paint(clip(v6_val, 24), "value", args) + "  "
    lines.append(box_line(l1_left, l1_right))

    l2_left = "  " + paint(net_lbl, "label", args) + " " + paint(clip(net_val, max(12, inner - 32)), "value", args)
    if fwd_val == "ON":
        fwd_badge = paint("[ ON ]", "ok", args)
    elif fwd_val == "OFF":
        fwd_badge = paint("[ OFF ]", "err", args)
    else:
        fwd_badge = paint("[ - ]", "muted", args)
    l2_right = paint("Forward:", "label", args) + " " + fwd_badge + "  "
    lines.append(box_line(l2_left, l2_right))

    l3_left = "  " + paint(prs_lbl, "label", args) + " " + paint(clip(prs_val, max(12, inner - 14)), "value", args)
    lines.append(box_line(l3_left))

    if wrn_val and wrn_val != "-":
        lines.append(box_line("  " + paint(wrn_lbl, "warn", args) + " " + paint(clip(wrn_val, max(12, inner - 14)), "warn", args)))

    lines.append(paint(sep, "rule", args))
    lines.append(box_line(""))

    # Workflows / Menus
    col1_w = (inner - 6) // 2
    col2_w = col1_w
    mid_space = max(2, inner - 4 - col1_w - col2_w)

    # Group headers
    t_peers = t("menu_group_peers")
    t_server = t("menu_group_server")
    t_safety = t("menu_group_safety")

    h1_text = (h * 2) + " " + t_peers + " "
    h1 = paint(h1_text, "section", args) + paint(h * max(0, col1_w - len(h1_text)), "rule", args)

    h2_srv_text = (h * 2) + " " + t_server + " "
    h2_srv = paint(h2_srv_text, "section", args) + paint(h * max(0, col2_w - len(h2_srv_text)), "rule", args)

    h2_saf_text = (h * 2) + " " + t_safety + " "
    h2_saf = paint(h2_saf_text, "section", args) + paint(h * max(0, col2_w - len(h2_saf_text)), "rule", args)

    col1 = [
        h1,
        _format_item("1", "list", "l", col1_w, args),
        _format_item("2", "add", "a", col1_w, args),
        _format_item("3", "show", "v", col1_w, args),
        _format_item("4", "qr", "g", col1_w, args),
        _format_item("5", "edit", "e", col1_w, args),
        _format_item("6", "enable", "o", col1_w, args),
        _format_item("7", "disable", "f", col1_w, args),
        _format_item("8", "delete", "d", col1_w, args),
        _format_item("9", "reclaim", "k", col1_w, args),
        _format_item("10", "purge", "p", col1_w, args),
    ]

    col2 = [
        h2_srv,
        _format_item("11", "status", "s", col2_w, args),
        _format_item("12", "reload", "r", col2_w, args),
        _format_item("13", "check", "c", col2_w, args),
        _format_item("14", "reconfigure", "w", col2_w, args),
        _format_item("15", "export", "x", col2_w, args),
        "",
        h2_saf,
        _format_item("16", "backup", "b", col2_w, args),
        _format_item("17", "rollback", "u", col2_w, args),
        "",
    ]

    if width >= 76:
        for c1, c2 in zip(col1, col2):
            pad1 = " " * max(0, col1_w - visible_len(c1))
            pad2 = " " * max(0, col2_w - visible_len(c2))
            lines.append(box_line("  " + c1 + pad1 + (" " * mid_space) + c2 + pad2 + "  "))
    else:
        for c1 in col1:
            if c1:
                lines.append(box_line("  " + c1))
        lines.append(box_line(""))
        for c2 in col2:
            if c2:
                lines.append(box_line("  " + c2))

    lines.append(box_line(""))
    lines.append(paint(sep, "rule", args))
    exit_desc = "[0/q] Salir / Exit" if lang == "es" else ("[0/q] Beenden / Exit" if lang == "de" else "[0/q] Exit / Quit")
    help_desc = "[h] Ayuda" if lang == "es" else ("[h] Hilfe" if lang == "de" else "[h] Help")
    l_foot = paint("  " + exit_desc, "warn", args)
    r_foot = paint(help_desc + "  ", "ok", args)
    lines.append(box_line(l_foot, r_foot))
    lines.append(paint(bot, "rule", args))
    lines.append("")

    for line in lines:
        emit(line)


def _menu_is_tty():
    """Return True when stdin is a TTY; never raises."""
    try:
        return bool(sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def cmd_menu(args):
    # Guided first-run setup wizard: if uninitialized and in TTY, guide user through setup first!
    if _stdin_isatty() and not _is_initialized():
        print(paint("\n" + "=" * 60, "rule", args))
        print(paint("  " + PROG + " " + VERSION + " - WireGuard Control Center", "title", args))
        print(paint("=" * 60, "rule", args))
        print(paint("\n  [!] " + t("first_run_notice"), "accent", args))
        print(paint("      " + t("first_run_prompt_help"), "value", args) + "\n")
        init_args = argparse.Namespace(**vars(args))
        init_args.apply = True
        init_args.yes = True
        try:
            res = cmd_init(init_args)
            if res not in (0, None):
                return int(res or 1)
        except SystemExit as exc:
            if exc.code not in (0, None):
                return int(exc.code or 1)
        except KeyboardInterrupt:
            eprint(t("interrupted"))
            return 130
        print(paint("\n  [OK] " + t("first_run_complete") + "\n", "ok", args))
        time.sleep(1.5)

    items = _menu_items() + [("0", "quit")]
    by_number = {key: label for key, label in items}
    by_number.setdefault("18", "export")
    by_label = {label.lower(): label for _key, label in items}
    by_label["init"] = "init"
    by_label["help"] = "check"
    by_label["ayuda"] = "check"
    flash = None
    while True:
        clear_screen(args)
        _print_menu_screen(args, flash=flash)
        flash = None
        prompt_icon = paint(">> ", "accent", args)
        prompt_text = prompt_icon + paint(t("menu_prompt"), "title", args) + " "
        try:
            raw = input(prompt_text).strip()
        except EOFError:
            return 0
        except KeyboardInterrupt:
            eprint(t("interrupted"))
            return 130
        low = raw.lower()
        hit = None
        if raw in by_number:
            hit = by_number[raw]
        elif low in by_label:
            hit = by_label[low]
        elif low in _SHORTCUTS:
            cand = _SHORTCUTS[low]
            if cand in by_label or cand in ("quit", "check", "init"):
                hit = cand
        if hit is None:
            print(cwrap(t("menu_invalid"), C_ERR, args), file=sys.stderr)
            if _stdin_isatty():
                time.sleep(1)
            continue
        if hit == "quit":
            return 0
        call_args = args
        try:
            tty_dispatch = bool(sys.stdin.isatty())
        except (OSError, ValueError):
            tty_dispatch = False
        if tty_dispatch:
            call_args = argparse.Namespace(**vars(args))
            call_args.apply = True
            call_args.yes = True
        ok = True
        try:
            result = _HANDLERS[hit](call_args)
            if result not in (0, None):
                ok = False
        except SystemExit as exc:
            ok = exc.code in (0, None)
            if not ok:
                eprint(cwrap(str(exc.code), C_ERR, args))
        except KeyboardInterrupt:
            eprint(t("interrupted"))
            return 130
        if not _menu_is_tty():
            return 0
        if ok:
            print(cwrap(t("menu_done"), C_OK, args))
            desc_key = "menu_desc_" + hit
            desc_val = t(desc_key) if desc_key in STRINGS.get(str(LANG), {}) else hit
            flash = hit + ": " + desc_val
        code = _menu_pause_tty(args)
        if code != 0:
            return int(code)

