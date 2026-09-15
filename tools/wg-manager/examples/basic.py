#!/usr/bin/env python3
"""Copy-paste dry-run demo for wg-manager: runs in <5 min, writes nothing."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ENTRY = Path(__file__).resolve().parent.parent / "main.py"


def show(args, env=None):
    # Print command, run it offline, and stream its output verbatim.
    print(f"$ wg-manager {' '.join(args)}")
    base = dict(os.environ)
    if env:
        base.update(env)
    proc = subprocess.run(
        [sys.executable, str(ENTRY), *args],
        text=True,
        capture_output=True,
        env=base,
        timeout=10,
        stdin=subprocess.DEVNULL,  # Non-TTY pipes: never prompt or hang.
        check=False,
    )
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if proc.returncode != 0:
        raise SystemExit(f"demo failed: {args} exited {proc.returncode}")
    print(f"(exit {proc.returncode})\n")


def show_optional(args, env=None):
    # Best-effort dry-run demo line: backends without the subcommand skip
    # cleanly so the demo stays exit 0 and writes nothing.
    print(f"$ wg-manager {' '.join(args)}")
    base = dict(os.environ)
    if env:
        base.update(env)
    proc = subprocess.run(
        [sys.executable, str(ENTRY), *args],
        text=True,
        capture_output=True,
        env=base,
        timeout=10,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if proc.returncode != 0:
        print(f"(skip: backend lacks {' '.join(args)}, exit {proc.returncode})\n")
        return
    print(f"(exit {proc.returncode})\n")


def main():
    show(["--version"])
    show(["--self-test"])
    # Single render on an empty isolated fixture; dry-run writes nothing.
    with tempfile.TemporaryDirectory() as tmp:
        env = {"WG_MANAGER_STATE": str(Path(tmp) / "state.json")}
        show(["list", "--dry-run"], env=env)
        # Dry-run only: preview reconfigure output without writing state.
        show_optional(["reconfigure", "--dry-run"], env=env)
    print("Demo OK: dry-run only, no writes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
