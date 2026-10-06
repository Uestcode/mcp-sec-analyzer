"""Bridge module for optional Ghidra Headless integration."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
from typing import Any


def find_ghidra_headless() -> Path | None:
    """Locate analyzeHeadless executable in environment variables or system PATH."""
    env_vars = ["GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_PATH"]
    for var in env_vars:
        val = os.environ.get(var)
        if val:
            base = Path(val)
            for candidate in (
                base / "support" / "analyzeHeadless.bat",
                base / "support" / "analyzeHeadless",
                base / "analyzeHeadless.bat",
                base / "analyzeHeadless",
            ):
                if candidate.exists():
                    return candidate

    which_headless = shutil.which("analyzeHeadless.bat") or shutil.which("analyzeHeadless")
    if which_headless:
        return Path(which_headless)

    return None


def check_ghidra_status() -> dict[str, Any]:
    """Check whether Ghidra Headless is configured and operational."""
    headless_path = find_ghidra_headless()
    if not headless_path:
        return {
            "ghidra_installed": False,
            "status": "Ghidra not detected in GHIDRA_HOME or system PATH",
            "fallback_engine": "Native Capstone + Internal Pseudocode Engine active (Zero-latency fast path)",
            "setup_guide": "To enable Ghidra, install Ghidra and set environment variable GHIDRA_HOME=<path_to_ghidra>",
        }

    return {
        "ghidra_installed": True,
        "headless_path": str(headless_path),
        "status": "Ghidra Headless is available for deep whole-program decompilation",
    }
