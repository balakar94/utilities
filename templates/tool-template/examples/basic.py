#!/usr/bin/env python3
"""Minimal copy-paste example. Must run in <5 min."""
import subprocess
import sys
from pathlib import Path

ENTRY = Path(__file__).resolve().parent.parent / "main.py"
raise SystemExit(subprocess.call([sys.executable, str(ENTRY), "--help"]))
