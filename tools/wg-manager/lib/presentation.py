# presentation.py
import os
import shutil
import sys

from .constants import (
    C_RESET,
    MARK,
    ROLES,
    TAG,
)
from .i18n import current_lang, is_no, is_yes, t


def color_enabled(args=None):
    """True when colors allowed: NO_COLOR unset, --no-color off, --color != never."""
    if "NO_COLOR" in os.environ:
        return False
    if args is not None and getattr(args, "no_color", False):
        return False
    mode = "auto"
    if args is not None:
        mode = str(getattr(args, "color", "auto") or "auto").lower()
    if mode == "never":
        return False
    if mode == "always":
        return True
    try:
        return bool(sys.stdout.isatty())
    except (OSError, ValueError):
        return False


def cwrap(text, code, args=None):
    """Wrap text in ANSI code when color_enabled, else plain."""
    if not color_enabled(args):
        return str(text)
    return str(code) + str(text) + C_RESET


def eprint(msg):
    print(msg, file=sys.stderr)



def term_width(args=None):
    """Visible output width: --width override, else terminal/COLUMNS, else 80."""
    override = getattr(args, "width", 0) if args is not None else 0
    try:
        override = int(override or 0)
    except (TypeError, ValueError):
        override = 0
    if override > 0:
        return max(40, min(override, 200))
    try:
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    except (OSError, ValueError):
        cols = 80
    return max(40, min(int(cols or 80), 200))


def paint(text, role="value", args=None):
    """Color gate: returns text unchanged when color is off. Never alters chars."""
    code = ROLES.get(role, "")
    if not code or not color_enabled(args):
        return str(text)
    return "\033[" + code + "m" + str(text) + C_RESET


def clip(text, cap):
    """ASCII middle-clip: head + ... + tail, preserving the tail (last 4 max)."""
    s = str(text)
    if cap < 8 or len(s) <= cap:
        return s
    right = min(4, (cap - 3) // 3)
    left = cap - 3 - right
    return s[:left] + MARK + s[-right:]


def wrap_text(text, avail):
    """Word-wrap; a single over-long token is middle-clipped."""
    avail = max(8, int(avail))
    out = []
    cur = ""
    for word in str(text).split(" "):
        if len(word) > avail:
            if cur:
                out.append(cur)
                cur = ""
            out.append(clip(word, avail))
            continue
        cand = word if not cur else cur + " " + word
        if len(cand) <= avail:
            cur = cand
        else:
            out.append(cur)
            cur = word
    if cur or not out:
        out.append(cur)
    return out


def banner(title, meta=(), args=None):
    """Title box plus optional label/value meta lines (width-safe)."""
    width = term_width(args)
    rule = "=" * width
    lines = [
        paint(rule, "rule", args),
        paint("  " + clip(str(title), max(8, width - 4)), "title", args),
    ]
    for pair in meta:
        label = "  " + str(pair[0]) + ":"
        avail = max(8, width - len(label) - 1)
        lines.append(paint(label, "label", args) + " " + paint(clip(str(pair[1]), avail), "accent", args))
    lines.append(paint(rule, "rule", args))
    return lines


def section(title, args=None):
    width = term_width(args)
    if not (args is not None and getattr(args, "width", 0)):
        width = min(width, 80)
    max_title = max(4, width - 8)
    t_str = " " + clip(str(title).upper(), max_title) + " "
    line_len = max(0, width - len(t_str) - 5)
    bar = "-" * line_len
    return paint("---[", "rule", args) + paint(t_str, "section", args) + paint("]" + bar, "rule", args)


def kv(pairs, args=None, indent=1, pad=0):
    """Grouped label/value block; long values wrap with an aligned continuation."""
    width = term_width(args)
    base = "  " * indent
    out = []
    for pair in pairs:
        label, value = str(pair[0]), pair[1]
        role = pair[2] if len(pair) > 2 else "value"
        if value is None or value == "":
            value = "-"
        lab = (label + ":").ljust(pad) if pad else (label + ":")
        avail = max(8, width - len(base) - len(lab) - 1)
        chunks = wrap_text(value, avail)
        out.append(base + paint(lab, "label", args) + " " + paint(chunks[0], role, args))
        cont = base + " " * (len(lab) + 1)
        for chunk in chunks[1:]:
            out.append(cont + paint(chunk, role, args))
    return out


def table(headers, rows, priority=None, caps=None, args=None, indent=1):
    """Aligned columns; drops lowest-priority columns to fit term_width."""
    width = term_width(args) - 2 * indent
    headers = [str(h) for h in headers]
    caps = caps or {}
    keep = list(range(len(headers)))

    def colw(idx):
        m = len(headers[idx])
        for row in rows:
            m = max(m, len(str(row[idx])))
        return min(m, caps.get(headers[idx], 24))

    low = list(reversed(priority)) if priority else list(reversed(headers))
    while len(keep) > 1:
        total = sum(colw(i) for i in keep) + 2 * (len(keep) - 1)
        if total <= width:
            break
        dropped = False
        for name in low:
            if name in headers:
                idx = headers.index(name)
                if idx in keep:
                    keep.remove(idx)
                    dropped = True
                    break
        if not dropped:
            keep.pop()
    ws = {i: colw(i) for i in keep}
    head = "  ".join(clip(headers[i], ws[i]).ljust(ws[i]) for i in keep).rstrip()
    out = ["  " * indent + paint(head, "section", args),
           "  " * indent + paint("-" * len(head), "rule", args)]
    for row in rows:
        cells = []
        for i in keep:
            val = str(row[i])
            c_val = clip(val, ws[i]).ljust(ws[i])
            h = headers[i].upper()
            if h in ("STATE", "ACTIVO", "STATUS", "ESTADO"):
                low_v = val.lower()
                if "active" in low_v or "si" in low_v or "yes" in low_v or "online" in low_v or low_v == "enabled":
                    cells.append(paint(c_val, "ok", args))
                elif "tombstone" in low_v or "no" in low_v or "down" in low_v or "expired" in low_v or "disabled" in low_v:
                    cells.append(paint(c_val, "destructive", args))
                else:
                    cells.append(paint(c_val, "muted", args))
            elif h in ("NAME", "NOMBRE"):
                cells.append(paint(c_val, "title", args))
            else:
                cells.append(c_val)
        out.append("  " * indent + "  ".join(cells).rstrip())
    return out


def note(text, role="info", args=None, indent=0, pad=0):
    """Tagged message: [tag] + wrapped text. Tag text always present, color optional."""
    tag = "[" + TAG.get(role, role) + "]"
    if pad:
        tag = tag.ljust(pad)
    base = "  " * indent
    avail = max(8, term_width(args) - len(base) - len(tag) - 1)
    chunks = wrap_text(text, avail)
    cont = base + " " * (len(tag) + 1)
    return "\n".join([base + paint(tag, role, args) + " " + str(chunks[0])]
                     + [cont + str(chunk) for chunk in chunks[1:]])


def hint(text, args=None, indent=0):
    base = "  " * indent
    avail = max(8, term_width(args) - len(base) - 6)
    chunks = wrap_text(text, avail)
    cont = base + " " * 6
    prefix = base + paint("hint:", "accent", args)
    return "\n".join([prefix + " " + paint(chunks[0], "muted", args)]
                     + [cont + paint(chunk, "muted", args) for chunk in chunks[1:]])


def items(entries, args=None, indent=1):
    """Bullet list; entries may be str or (text, role)."""
    out = []
    for entry in entries:
        text, role = entry if isinstance(entry, tuple) else (entry, "value")
        out.append("  " * indent + paint("- ", "muted", args) + paint(text, role, args))
    return out


def emit(lines, stream="out"):
    """The only writer for chrome. Verbatim render_* documents may still print()."""
    if isinstance(lines, str):
        lines = [lines]
    target = sys.stdout if stream == "out" else sys.stderr
    for line in lines:
        print(line, file=target)


def usage():
    return "Usage: wg-manager [--lang auto|en|es|de] [--color always|auto|never] [--no-color] [--width N] [--version] [--self-test] [--uninstall]\n       wg-manager <init|add|edit|delete|list|show|qr|purge|reclaim|reconfigure|reload|check|backup|rollback|menu|status|enable|disable|export|uninstall> [options]\n\nWireGuard native server manager. Dry-run by default; system writes need --apply --yes --sudo.\n"



def prompt_value(prompt, default=""):
    try:
        raw = input(prompt)
    except EOFError:
        return default
    raw = raw.strip()
    return raw if raw else default


def prompt_yesno(prompt_key, default=None):
    if default is True:
        lang = current_lang()
        hint = "[S/n]" if lang == "es" else ("[J/n]" if lang == "de" else "[Y/n]")
    elif default is False:
        lang = current_lang()
        hint = "[s/N]" if lang == "es" else ("[j/N]" if lang == "de" else "[y/N]")
    else:
        hint = t("confirm_hint")
    while True:
        try:
            raw = input(t(prompt_key).format(hint=hint))
        except EOFError:
            return bool(default) if default is not None else False
        if not raw.strip() and default is not None:
            return default
        if is_yes(raw):
            return True
        if is_no(raw):
            return False
        print(t("confirm_invalid"), file=sys.stderr)


def _stdin_isatty():
    """Audit fix: A6 - never let non-interactive input silently apply defaults."""
    try:
        return bool(sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def clear_screen(args=None):
    """Clear terminal screen if stdout and stdin are a TTY and color is enabled."""
    if color_enabled(args) and _stdin_isatty() and sys.stdout.isatty():
        sys.stdout.write("\033[H\033[2J")
        sys.stdout.flush()



