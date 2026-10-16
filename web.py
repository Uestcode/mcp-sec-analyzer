"""Web Dashboard Server Launcher for Unified Cybersecurity MCP Hub."""

from __future__ import annotations

from pathlib import Path
import sys

# Ensure src is in sys.path
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from mcp_sec_analyzer.web.launcher import main

if __name__ == "__main__":
    main()
