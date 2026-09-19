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
from .i18n import current_lang, is_yes, t
from .ipam import peers_sorted
from .presentation import (
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
    wrap_text,
)
from .renderers import _wan_iface
from .state import _is_initialized, list_backups, load_state, state_path
from .system import (
    detect_firewall_default,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def visible_len(s):
    """Visible terminal width of a string ignoring ANSI escape codes."""
    return len(_ANSI_RE.sub("", str(s)))


def _truncate_visible(text, cap):
    """Truncate to a visible-width cap, keeping ANSI sequences intact and balanced."""
    s = str(text)
    if cap <= 0:
        return ""
    if visible_len(s) <= cap:
        return s
    out = []
    visible = 0
    index = 0
    truncated = False
    while index < len(s):
        match = _ANSI_RE.match(s, index)
        if match:
            out.append(match.group(0))
            index = match.end()
            continue
        if visible >= cap:
            truncated = True
            break
        out.append(s[index])
        visible += 1
        index += 1
    result = "".join(out)
    if truncated and "\x1b" in result:
        result += "\x1b[0m"
    return result


# Actions that mutate or destroy data and therefore need typed confirmation in APPLY mode.
_DESTRUCTIVE_ACTIONS = ("delete", "purge", "rollback", "uninstall")


def _menu_apply_mode(args):
    """Explicit initial mode: APPLY only with --apply and without --dry-run."""
    return bool(getattr(args, "apply", False)) and not bool(getattr(args, "dry_run", False))


def _menu_frame_width(args):
    """Frame width: explicit --width >= 40 wins, clamped to 40..200."""
    try:
        requested = int(getattr(args, "width", 0) or 0)
    except (TypeError, ValueError):
        requested = 0
    if requested < 40:
        requested = term_width(args)
    return max(40, min(requested, 200))



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
    "h": "help",
    "?": "help",
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

    return _truncate_visible(p_num + p_lbl + p_desc + padding + p_sc, target_w)


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
    mode = t("menu_mode_apply") if _menu_apply_mode(args) else t("menu_mode_dry")
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


def _menu_pause_tty(args, show_prompt=True):
    """TTY-only pause; EOF-safe, Ctrl-C aborts with code 130."""
    try:
        if not sys.stdin.isatty():
            return 0
    except (OSError, ValueError):
        return 0
    try:
        input(t("menu_continue") if show_prompt else "")
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


def _frame_line(text, inner, args):
    """One box row: pad/truncate content to the inner width with side borders."""
    chars = _box_chars()
    body = _truncate_visible(str(text), inner)
    pad = " " * max(0, inner - visible_len(body))
    return paint(chars["v"], "rule", args) + body + pad + paint(chars["v"], "rule", args)


def _print_menu_screen(args, flash=None, apply_mode=None):
    """Full-screen boxed cockpit dashboard with live status and 2-column menu."""
    if apply_mode is None:
        apply_mode = _menu_apply_mode(args)
    apply_mode = bool(apply_mode)
    width = _menu_frame_width(args)
    chars = _box_chars()
    v = chars["v"]
    h = chars["h"]
    inner = width - 2

    def box_line(left_text="", right_text="", left_role=None, right_role=None):
        p_left = paint(left_text, left_role, args) if left_role else str(left_text)
        p_right = paint(right_text, right_role, args) if right_role else str(right_text)
        p_left = _truncate_visible(p_left, inner)
        v_left = visible_len(p_left)
        if right_text:
            p_right = _truncate_visible(p_right, max(0, inner - v_left - 1))
            v_right = visible_len(p_right)
            if v_left + v_right + 1 > inner:
                p_left = _truncate_visible(p_left, max(0, inner - v_right - 1))
                v_left = visible_len(p_left)
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
    mode_label = t("menu_mode_apply") if apply_mode else t("menu_mode_dry")
    lang = current_lang()

    title_core = PROG + " " + VERSION
    if width >= 72:
        title_core += " " + chars["bullet"] + " WireGuard Control Center"
    title_left = "  " + paint(title_core, "title", args)
    title_right = paint("[" + lang.upper() + "]", "accent", args)
    title_right += " " + paint("[AUTO]", "ok", args) + "  "

    state_lbl = "Estado" if lang == "es" else ("Status" if lang == "de" else "State")
    state_path_txt = paint(clip(path, max(12, inner - 35)), "value", args)
    sub_left = "  " + paint(state_lbl + ":", "label", args) + " " + state_path_txt
    mode_colored = paint(mode_label, "ok" if apply_mode else "warn", args)
    sub_right = paint("[ ", "label", args) + mode_colored + paint(" ]  ", "label", args)

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
        warn_line = "  " + paint(wrn_lbl, "warn", args) + " " + paint(clip(wrn_val, max(12, inner - 14)), "warn", args)
        lines.append(box_line(warn_line))

    lines.append(paint(sep, "rule", args))
    lines.append(box_line(""))

    # Workflows / Menus
    narrow = width < 76
    col1_w = (inner - 6) // 2
    col2_w = col1_w
    mid_space = max(2, inner - 4 - col1_w - col2_w)
    item_w = col1_w if not narrow else max(20, inner - 4)

    # Group headers
    t_peers = t("menu_group_peers")
    t_server = t("menu_group_server")
    t_safety = t("menu_group_safety")

    h1_text = (h * 2) + " " + t_peers + " "
    h1 = paint(h1_text, "section", args) + paint(h * max(0, item_w - len(h1_text)), "rule", args)

    h2_srv_text = (h * 2) + " " + t_server + " "
    h2_srv = paint(h2_srv_text, "section", args) + paint(h * max(0, item_w - len(h2_srv_text)), "rule", args)

    h2_saf_text = (h * 2) + " " + t_safety + " "
    h2_saf = paint(h2_saf_text, "section", args) + paint(h * max(0, item_w - len(h2_saf_text)), "rule", args)

    col1 = [
        h1,
        _format_item("1", "list", "l", item_w, args),
        _format_item("2", "add", "a", item_w, args),
        _format_item("3", "show", "v", item_w, args),
        _format_item("4", "qr", "g", item_w, args),
        _format_item("5", "edit", "e", item_w, args),
        _format_item("6", "enable", "o", item_w, args),
        _format_item("7", "disable", "f", item_w, args),
        _format_item("8", "delete", "d", item_w, args),
        _format_item("9", "reclaim", "k", item_w, args),
        _format_item("10", "purge", "p", item_w, args),
    ]

    col2 = [
        h2_srv,
        _format_item("11", "status", "s", item_w, args),
        _format_item("12", "reload", "r", item_w, args),
        _format_item("13", "check", "c", item_w, args),
        _format_item("14", "reconfigure", "w", item_w, args),
        _format_item("15", "export", "x", item_w, args),
        "",
        h2_saf,
        _format_item("16", "backup", "b", item_w, args),
        _format_item("17", "rollback", "u", item_w, args),
        "",
    ]

    if not narrow:
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
    if lang == "es":
        exit_desc = "[0/q] Salir / Exit"
    elif lang == "de":
        exit_desc = "[0/q] Beenden / Exit"
    else:
        exit_desc = "[0/q] Exit / Quit"
    help_desc = "[?] Ayuda" if lang == "es" else ("[?] Hilfe" if lang == "de" else "[?] Help")
    mode_desc = "[A] Modo" if lang == "es" else ("[A] Modus" if lang == "de" else "[A] Mode")
    l_foot = paint("  " + exit_desc, "warn", args)
    right_foot = mode_desc + "  " + help_desc + "  " if width >= 56 else "[A] [?]  "
    r_foot = paint(right_foot, "ok", args)
    lines.append(box_line(l_foot, r_foot))
    lines.append(paint(bot, "rule", args))
    lines.append("")

    for line in lines:
        emit(_truncate_visible(line, width))


def _menu_is_tty():
    """Return True when stdin is a TTY; never raises."""
    try:
        return bool(sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def _confirm_destructive(args, action):
    """Typed confirmation for destructive actions; True only on the exact action word."""
    prompt = t("menu_confirm_destructive").format(action=action)
    hint = t("menu_confirm_hint")
    try:
        raw = input(paint(prompt + " " + hint, "warn", args) + " ").strip()
    except EOFError:
        return False
    if raw != action:
        print(cwrap(t("menu_confirm_mismatch"), C_ERR, args))
        return False
    return True


def _menu_call_args(args, apply_mode, yes=None):
    """Namespace copy with explicit apply/dry-run/yes flags for one dispatch."""
    call_args = argparse.Namespace(**vars(args))
    call_args.apply = bool(apply_mode)
    call_args.dry_run = not bool(apply_mode)
    call_args.yes = bool(apply_mode) if yes is None else bool(yes)
    return call_args


def _menu_rollback_call_args(args, apply_mode):
    """Rollback args: --list in DRY-RUN, interactive backup pick in APPLY.

    Returns None when the user cancels or no backup exists.
    """
    call_args = _menu_call_args(args, apply_mode, yes=False)
    if not apply_mode:
        call_args.list = True
        call_args.to = ""
        return call_args
    backups = list_backups()
    if not backups:
        print(cwrap(t("menu_rollback_none"), C_ERR, args))
        _menu_pause_tty(args)
        return None
    for index, path in enumerate(backups, 1):
        emit("  " + paint("[" + str(index) + "]", "num", args) + " " + paint(str(path), "value", args))
    try:
        raw = input(paint(t("menu_rollback_select"), "title", args) + " ").strip()
    except EOFError:
        raw = ""
    if not raw.isdigit() or not 1 <= int(raw) <= len(backups):
        print(cwrap(t("menu_invalid"), C_ERR, args), file=sys.stderr)
        _menu_pause_tty(args)
        return None
    if not _confirm_destructive(args, "rollback"):
        print(cwrap(t("menu_cancelled"), C_ERR, args))
        _menu_pause_tty(args)
        return None
    call_args.to = str(backups[int(raw) - 1])
    call_args.list = False
    call_args.yes = True
    return call_args


def _print_help_screen(args, apply_mode=None):
    """Help screen: title, current mode, shortcuts/items, danger marks and return hint."""
    if apply_mode is None:
        apply_mode = _menu_apply_mode(args)
    apply_mode = bool(apply_mode)
    clear_screen(args)
    width = _menu_frame_width(args)
    chars = _box_chars()
    inner = max(1, width - 2)
    rule = chars["h"] * inner
    mode_txt = t("menu_mode_apply") if apply_mode else t("menu_mode_dry")
    danger = t("menu_help_danger")
    lines = [paint(chars["tl"] + rule + chars["tr"], "rule", args)]
    lines.append(_frame_line("  " + paint(t("menu_help_title"), "title", args), inner, args))
    lines.append(_frame_line("  " + paint(mode_txt, "ok" if apply_mode else "warn", args), inner, args))
    lines.append(paint(chars["div_l"] + rule + chars["div_r"], "rule", args))
    controls = "  [A] " + t("menu_mode_apply") + " / " + t("menu_mode_dry")
    controls += "   [?/h/H] " + t("menu_help_title") + "   [0/q]"
    lines.append(_frame_line(paint(controls, "section", args), inner, args))
    for chunk in wrap_text("[!] " + danger, max(8, inner - 2)):
        lines.append(_frame_line("  " + paint(chunk, "err", args), inner, args))
    lines.append(paint(chars["div_l"] + rule + chars["div_r"], "rule", args))
    for key, label in _menu_items():
        shortcut = _SHORTCUT_HINTS.get(label, "")
        item_w = max(12, inner - 6)
        marker = ""
        if label in _DESTRUCTIVE_ACTIONS:
            marker = "  " + paint("[!]", "err", args)
            item_w = max(12, inner - 6 - visible_len(marker))
        row = "  " + _format_item(key, label, shortcut, item_w, args) + marker
        lines.append(_frame_line(row, inner, args))
    lines.append(paint(chars["bl"] + rule + chars["br"], "rule", args))
    lines.append(_frame_line("  " + paint(t("menu_continue"), "muted", args), inner, args))
    for line in lines:
        emit(_truncate_visible(line, width))
    return _menu_pause_tty(args, show_prompt=False)


def _menu_first_run(args):
    """Guided first-run flow: dry-run plan first, write only after explicit confirmation.

    Returns None to continue into the menu, or an exit code to abort.
    """
    print(paint("\n" + "=" * 60, "rule", args))
    print(paint("  " + PROG + " " + VERSION + " - WireGuard Control Center", "title", args))
    print(paint("=" * 60, "rule", args))
    print(paint("\n  [!] " + t("first_run_notice"), "accent", args))
    print(paint("      " + t("first_run_prompt_help"), "value", args) + "\n")
    init_args = _menu_call_args(args, apply_mode=False)
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
    print(paint("\n  " + t("menu_first_run_plan"), "accent", args))
    try:
        answer = input(paint(t("menu_first_run_apply_prompt"), "title", args) + " ")
    except EOFError:
        answer = ""
    except KeyboardInterrupt:
        eprint(t("interrupted"))
        return 130
    if not is_yes(answer):
        print(paint("  " + t("menu_first_run_declined"), "warn", args))
        time.sleep(1.0)
        return None
    apply_args = _menu_call_args(args, apply_mode=True)
    try:
        res = cmd_init(apply_args)
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
    return None


def cmd_menu(args):
    apply_mode = _menu_apply_mode(args)
    # Guided first-run setup: uninitialized TTY users get a dry-run plan before any write.
    if _menu_is_tty() and not _is_initialized():
        code = _menu_first_run(args)
        if code is not None:
            return int(code)

    items = _menu_items() + [("0", "quit")]
    by_number = {key: label for key, label in items}
    by_label = {label.lower(): label for _key, label in items}
    by_label["reconfig"] = "reconfigure"
    by_label["init"] = "init"
    by_label["help"] = "help"
    by_label["ayuda"] = "help"
    flash = None
    while True:
        clear_screen(args)
        _print_menu_screen(args, flash=flash, apply_mode=apply_mode)
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
        if raw == "A":
            # Mode switch is interactive-only; never let a piped "A" trigger a write.
            if _menu_is_tty():
                apply_mode = not apply_mode
                if apply_mode:
                    flash = t("menu_mode_switch_note")
            continue
        low = raw.lower()
        hit = None
        if raw in by_number:
            hit = by_number[raw]
        elif low in by_label:
            hit = by_label[low]
        elif low in _SHORTCUTS:
            hit = _SHORTCUTS[low]
        if hit is None:
            print(cwrap(t("menu_invalid"), C_ERR, args), file=sys.stderr)
            if _menu_is_tty():
                time.sleep(1)
            continue
        if hit == "quit":
            return 0
        if hit == "help":
            help_code = _print_help_screen(args, apply_mode)
            if help_code:
                return int(help_code)
            continue
        ok = True
        try:
            if hit == "rollback":
                call_args = _menu_rollback_call_args(args, apply_mode)
                if call_args is None:
                    continue
            else:
                call_args = _menu_call_args(args, apply_mode)
                if apply_mode and hit in _DESTRUCTIVE_ACTIONS:
                    if not _confirm_destructive(args, hit):
                        if not _menu_is_tty():
                            return 0
                        flash = t("menu_cancelled")
                        _menu_pause_tty(args)
                        continue
                    call_args.yes = True
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
            desc_val = t(desc_key)
            if desc_val == desc_key:
                desc_val = hit
            flash = hit + ": " + desc_val
        code = _menu_pause_tty(args)
        if code != 0:
            return int(code)

