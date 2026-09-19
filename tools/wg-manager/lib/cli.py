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
from .errors import WgError
from .i18n import (
    current_lang,
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
    "disable": cmd_disable, "export": cmd_export, "uninstall": cmd_uninstall,
}

# ---------------------------------------------------------------- parser
COMMON_SPEC = (
    ("--lang", {"default": "auto", "choices": ["auto", "en", "es", "de"]}),
    ("--color", {"default": "auto", "choices": ["always", "auto", "never"]}),
    ("--no-color", {"action": "store_true"}),
    ("--width", {"type": int, "default": 0}),
    ("--apply", {"action": "store_true"}),
    ("--yes", {"action": "store_true"}),
    ("--sudo", {"action": "store_true"}),
    ("--dry-run", {"action": "store_true"}),
    ("--show-secrets", {"action": "store_true"}),
)

SUBCOMMAND_SPEC = {
    "init": (
        ("name", {"nargs": "?", "default": ""}),
        ("--force", {"action": "store_true"}),
        ("--import-server-key", {"default": ""}),
        ("--set", {"action": "append", "default": None}),
    ),
    "add": (
        ("--name", {"default": ""}),
        ("--kind", {"default": ""}),
        ("--infra-type", {"default": ""}),
        ("--pool", {"default": ""}),
        ("--traffic", {"default": ""}),
        ("--routes", {"default": ""}),
        ("--dns-scope", {"default": ""}),
        ("--keepalive", {"default": None}),
        ("--endpoint", {"default": ""}),
        ("--pubkey", {"default": ""}),
        ("--ip", {"default": ""}),
        ("--ip6", {"default": ""}),
        ("--psk", {"nargs": "?", "const": "generate", "default": None}),
        ("--no-psk", {"action": "store_true"}),
        ("--expires", {"default": ""}),
    ),
    "edit": (
        ("name", {"nargs": "?", "default": ""}),
        ("--new-name", {"default": ""}),
        ("--endpoint", {"default": None}),
        ("--traffic", {"default": ""}),
        ("--routes", {"default": None}),
        ("--dns-scope", {"default": ""}),
        ("--keepalive", {"default": None}),
        ("--move-pool", {"default": ""}),
        ("--rotate-keys", {"action": "store_true"}),
        ("--keep-psk", {"action": "store_true"}),
        ("--reclaim-ip", {"action": "store_true"}),
        ("--pubkey", {"default": ""}),
        ("--expires", {"default": ""}),
        ("--enable", {"action": "store_true"}),
        ("--disable", {"action": "store_true"}),
    ),
    "delete": (("name", {"nargs": "?", "default": ""}),),
    "list": (("--json", {"action": "store_true"}),),
    "show": (("name", {"nargs": "?", "default": ""}),),
    "qr": (("name", {"nargs": "?", "default": ""}),),
    "purge": (("--pool", {"default": ""}),),
    "reclaim": (("name", {"nargs": "?", "default": ""}),),
    "reconfigure": (
        ("--ipv6-mode", {"default": ""}),
        ("--ipv6-prefix", {"default": ""}),
        ("--ipv6-wan", {"default": ""}),
        ("--wan", {"default": ""}),
        ("--endpoint", {"default": ""}),
        ("--port", {"default": None}),
        ("--mtu", {"default": None}),
    ),
    "reload": (
        ("--backend", {"default": ""}),
        ("--firewall", {"default": ""}),
    ),
    "check": (("--json", {"action": "store_true"}),),
    "backup": (("--output", {"default": ""}),),
    "rollback": (
        ("--list", {"action": "store_true"}),
        ("--to", {"default": ""}),
    ),
    "menu": (),
    "status": (("--json", {"action": "store_true"}),),
    "enable": (("name", {"nargs": "?", "default": ""}),),
    "disable": (("name", {"nargs": "?", "default": ""}),),
    "export": (
        ("name", {"nargs": "?", "default": ""}),
        ("--all", {"action": "store_true"}),
        ("--out-dir", {"default": ""}),
    ),
    "uninstall": (),
}


def _common_parser(suppress_defaults):
    """One common flag set; subparsers suppress defaults so global values
    parsed before the subcommand are never clobbered by argparse."""
    parser = argparse.ArgumentParser(add_help=False)
    for flag, kw in COMMON_SPEC:
        kw = dict(kw)
        if suppress_defaults:
            kw["default"] = argparse.SUPPRESS
        parser.add_argument(flag, **kw)
    return parser


def build_parser():
    parser = argparse.ArgumentParser(prog=PROG, description="WireGuard native server manager.")
    for flag, kw in COMMON_SPEC:
        parser.add_argument(flag, **kw)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    common_sub = _common_parser(True)
    for name, spec in SUBCOMMAND_SPEC.items():
        p = sub.add_parser(name, parents=[common_sub])
        for arg, kw in spec:
            p.add_argument(arg, **kw)
    return parser


def _resolve_lang_for_self_test(rest):
    """Resolve --lang for the offline self-test without ever prompting."""
    for idx, token in enumerate(rest):
        if token == "--lang" and idx + 1 < len(rest) and rest[idx + 1] in ("en", "es", "de"):
            set_language(rest[idx + 1])
            return
        if token.startswith("--lang=") and token.split("=", 1)[1] in ("en", "es", "de"):
            set_language(token.split("=", 1)[1])
            return
    set_language(detect_system_lang())


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    # Fast paths for the utilities CI contract (first token only).
    if argv and argv[0] == "--version":
        print(PROG + " " + VERSION)
        return 0
    if argv and argv[0] == "--self-test":
        _resolve_lang_for_self_test(argv[1:])
        return cmd_self_test()
    if argv and argv[0] in ("--help", "-h"):
        # Keep the stable global usage text; subcommands use argparse help.
        print(usage(), end="")
        return 0
    if not argv:
        # Bare run in non-TTY exits 2; in TTY open the menu.
        try:
            is_tty = sys.stdin.isatty() and sys.stdout.isatty()
        except (OSError, ValueError):
            is_tty = False
        if not is_tty:
            set_language(detect_system_lang())
            eprint(usage())
            return 2
        resolve_auto_lang(True)
        args = argparse.Namespace(lang=current_lang(), color="auto", no_color=False,
                                  width=0, apply=False, yes=False, sudo=False,
                                  dry_run=False, show_secrets=False)
        return cmd_menu(args)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 0 for --help and 2 on usage errors; preserve both.
        return int(exc.code) if exc.code is not None else 2
    user_lang = getattr(args, "lang", "auto") or "auto"
    if user_lang == "auto":
        try:
            is_tty = sys.stdin.isatty() and sys.stdout.isatty()
        except (OSError, ValueError):
            is_tty = False
        resolve_auto_lang(is_tty)
    else:
        set_language(user_lang)
    if getattr(args, "version", False):
        print(PROG + " " + VERSION)
        return 0
    if getattr(args, "self_test", False):
        return cmd_self_test()
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
    except WgError as exc:
        eprint(str(exc))
        return exc.exit_code
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
