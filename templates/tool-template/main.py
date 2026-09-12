#!/usr/bin/env python3
"""__TOOL_NAME__ — one-line purpose. Requires Python >= 3.11."""
import sys

VERSION = "0.1.0"


def usage() -> str:
    return "Usage: __TOOL_NAME__ [--help] [--version]\n\nSmall description of what it does.\n"


def main(argv: list) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(usage(), end="")
        return 0 if argv else 2
    if argv[0] == "--version":
        print(f"__TOOL_NAME__ {VERSION}")
        return 0
    print(f"ERROR: unknown arg: {argv[0]}", file=sys.stderr)
    print(usage(), file=sys.stderr, end="")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
