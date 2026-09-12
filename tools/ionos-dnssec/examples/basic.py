#!/usr/bin/env python3
"""Minimal copy-paste example: offline checks, no API key, no network.

Real use is interactive and needs an IONOS API key:
    python3 tools/ionos-dnssec/main.py --lang en
"""
import subprocess
import sys
from pathlib import Path

ENTRY = Path(__file__).resolve().parent.parent / "main.py"


def run(*args):
    return subprocess.run([sys.executable, str(ENTRY), *args]).returncode


def main():
    print(f"$ {ENTRY} --version", flush=True)
    if run("--version") != 0:
        print("FAIL: --version", file=sys.stderr)
        return 1

    print(f"\n$ {ENTRY} --self-test", flush=True)
    if run("--self-test") != 0:
        print("FAIL: --self-test", file=sys.stderr)
        return 1

    print("\nOffline checks passed. For real use, launch it interactively:", flush=True)
    print(f"  {ENTRY} --lang en")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
