# cli.py
import argparse
import sys

from .commands import (
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
from .constants import PROG, VERSION
from .i18n import (
    detect_system_lang,
    resolve_auto_lang,
    set_language,
    t,
)
from .ipam import IPAMError
from .presentation import eprint, usage
from .selftest import cmd_self_test
from .tui import cmd_menu

_HANDLERS = {
    "init": cmd_init, "add": cmd_add, "edit": cmd_edit, "delete": cmd_delete,
    "list": cmd_list, "show": cmd_show, "qr": cmd_qr, "purge": cmd_purge,
    "reclaim": cmd_reclaim, "reconfigure": cmd_reconfigure, "reload": cmd_reload,
    "check": cmd_check, "backup": cmd_backup, "rollback": cmd_rollback,
    "menu": cmd_menu, "status": cmd_status, "enable": cmd_enable,
    "disable": cmd_disable, "export": cmd_export, "uninstall": cmd_uninstall
}

# ---------------------------------------------------------------- parser
_COMMON = (("--lang", {"default": "auto", "choices": ["auto", "en", "es", "de"]}), ("--color", {"default": "auto", "choices": ["always", "auto", "never"]}), ("--no-color", {"action": "store_true"}), ("--width", {"type": int, "default": 0}), ("--apply", {"action": "store_true"}), ("--yes", {"action": "store_true"}), ("--sudo", {"action": "store_true"}), ("--dry-run", {"action": "store_true"}), ("--show-secrets", {"action": "store_true"}))
_SUBS = {"init": (("name", {"nargs": "?", "default": ""}), ("--force", {"action": "store_true"}), ("--import-server-key", {"default": ""}), ("--set", {"action": "append", "default": None})), "add": (("--name", {"default": ""}), ("--kind", {"default": ""}), ("--infra-type", {"default": ""}), ("--pool", {"default": ""}), ("--traffic", {"default": ""}), ("--routes", {"default": ""}), ("--dns-scope", {"default": ""}), ("--keepalive", {"default": None}), ("--endpoint", {"default": ""}), ("--pubkey", {"default": ""}), ("--ip", {"default": ""}), ("--ip6", {"default": ""}), ("--psk", {"nargs": "?", "const": "generate", "default": None}), ("--no-psk", {"action": "store_true"}), ("--expires", {"default": ""})), "edit": (("name", {"nargs": "?", "default": ""}), ("--new-name", {"default": ""}), ("--endpoint", {"default": None}), ("--traffic", {"default": ""}), ("--routes", {"default": None}), ("--dns-scope", {"default": ""}), ("--keepalive", {"default": None}), ("--move-pool", {"default": ""}), ("--rotate-keys", {"action": "store_true"}), ("--keep-psk", {"action": "store_true"}), ("--reclaim-ip", {"action": "store_true"}), ("--pubkey", {"default": ""}), ("--expires", {"default": ""}), ("--enable", {"action": "store_true"}), ("--disable", {"action": "store_true"})), "delete": (("name", {"nargs": "?", "default": ""}),), "list": (), "show": (("name", {"nargs": "?", "default": ""}),), "qr": (("name", {"nargs": "?", "default": ""}),), "purge": (("--pool", {"default": ""}),), "reclaim": (("name", {"nargs": "?", "default": ""}),), "reconfigure": (("--ipv6-mode", {"default": ""}), ("--ipv6-prefix", {"default": ""}), ("--ipv6-wan", {"default": ""}), ("--wan", {"default": ""}), ("--endpoint", {"default": ""}), ("--port", {"default": None}), ("--mtu", {"default": None})), "reload": (("--backend", {"default": ""}), ("--firewall", {"default": ""})), "check": (), "backup": (("--output", {"default": ""}),), "rollback": (("--list", {"action": "store_true"}), ("--to", {"default": ""})), "menu": (), "status": (), "enable": (("name", {"nargs": "?", "default": ""}),), "disable": (("name", {"nargs": "?", "default": ""}),), "export": (("name", {"nargs": "?", "default": ""}), ("--all", {"action": "store_true"}), ("--out-dir", {"default": ""})), "uninstall": ()}
def add_common_flags(parser):
    for flag, kw in _COMMON:
        parser.add_argument(flag, **kw)
    return parser
def build_parser():
    parser = argparse.ArgumentParser(prog=PROG, description="WireGuard native server manager.")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    add_common_flags(parser)
    sub = parser.add_subparsers(dest="cmd")
    for name, spec in _SUBS.items():
        p = sub.add_parser(name)
        add_common_flags(p)
        for arg, kw in spec:
            p.add_argument(arg, **kw)
    return parser


def main(argv=None):
    global LANG
    if argv is None:
        argv = sys.argv[1:]
    # Fast paths for utilities CI contract.
    if "--version" in argv:
        print(PROG + " " + VERSION)
        return 0
    if "--self-test" in argv:
        # Resolve --lang for localized self-test output; auto never prompts.
        try:
            idx = argv.index("--lang")
            want = argv[idx + 1] if idx + 1 < len(argv) else "auto"
            if want in ("en", "es", "de"):
                LANG = want
            elif want == "auto":
                LANG = detect_system_lang()
            else:
                LANG = "en"
        except (ValueError, IndexError):
            LANG = detect_system_lang()
        return cmd_self_test()
    if "--help" in argv or "-h" in argv:
        print(usage(), end="")
        return 0
    if not argv:
        # Bare run in non-TTY exits 2; in TTY open the menu.
        try:
            is_tty = sys.stdin.isatty() and sys.stdout.isatty()
        except (OSError, ValueError):
            is_tty = False
        if not is_tty:
            LANG = detect_system_lang()
            eprint(usage())
            return 2
        LANG = "auto"
        resolve_auto_lang(True)
        args = argparse.Namespace(lang=LANG, color="auto", no_color=False, apply=False, yes=False, sudo=False, dry_run=False, show_secrets=False)
        return cmd_menu(args)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 on usage errors; keep that contract.
        return int(exc.code or 2)
    user_lang = getattr(args, "lang", "auto") or "auto"
    if user_lang == "auto" and "--lang" in argv:
        try:
            l_idx = argv.index("--lang")
            if l_idx + 1 < len(argv):
                user_lang = argv[l_idx + 1]
        except (ValueError, IndexError):
            pass
    if user_lang == "auto":
        for a in argv:
            if a.startswith("--lang="):
                user_lang = a.split("=", 1)[1]
                break
    if user_lang == "auto":
        try:
            is_tty = sys.stdin.isatty() and sys.stdout.isatty()
        except (OSError, ValueError):
            is_tty = False
        resolve_auto_lang(is_tty)
    else:
        set_language(user_lang)
    cmd = getattr(args, "cmd", None)
    if not cmd and getattr(args, "uninstall", False):
        cmd = "uninstall"
    if not cmd:
        eprint(usage())
        return 2
    func = _HANDLERS.get(cmd)
    if func is None:
        eprint(t("err_unknown_cmd").format(cmd=cmd))
        eprint(usage())
        return 2
    try:
        # Normalize keepalive to int when provided as string.
        if getattr(args, "keepalive", None) is not None and isinstance(args.keepalive, str):
            args.keepalive = int(args.keepalive)
    except (TypeError, ValueError):
        eprint(t("err_invalid_keepalive").format(value=getattr(args, "keepalive", "")))
        return 2
    try:
        return int(func(args) or 0)
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 1
    except ValueError as exc:
        eprint(str(exc))
        return 1
    except IPAMError as exc:
        eprint(str(exc))
        return 1
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 1
    except KeyboardInterrupt:
        eprint(t("interrupted"))
        return 130


