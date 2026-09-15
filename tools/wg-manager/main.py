#!/usr/bin/env python3
"""wg-manager: native WireGuard server manager (dry-run by default, stdlib only, Python >= 3.11)."""

import sys
from pathlib import Path

# Ensure local lib/ package is importable both when running directly from repo and when packaged.
_REPO_DIR = Path(__file__).resolve().parent
if (_REPO_DIR / "lib").is_dir() and str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

from lib.cli import main

if __name__ == "__main__":
    sys.exit(main())
