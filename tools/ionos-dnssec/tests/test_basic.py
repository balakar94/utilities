#!/usr/bin/env python3
"""Smoke test for a Python tool: <30s, no network, no sudo, stdlib only."""
import subprocess
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parent.parent
ENTRY = TOOL_ROOT / "main.py"


def run(*args):
    return subprocess.run(
        [sys.executable, str(ENTRY), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main():
    help_run = run("--help")
    if help_run.returncode != 0:
        fail("--help exit != 0")
    if "usage:" not in help_run.stdout.lower():
        fail("--help missing 'Usage:'")

    if run().returncode == 0:
        fail("no-arg run should fail")

    if run("--help").stdout != run("--help").stdout:
        fail("not idempotent")

    print(f"OK: {TOOL_ROOT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
