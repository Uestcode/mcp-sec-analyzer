"""Entrypoint script for mcp-sec-analyzer."""

import sys
from pathlib import Path

# Ensure src is in sys.path regardless of directory path encoding on Windows
src_path = Path(__file__).resolve().parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from mcp_sec_analyzer.server import main

if __name__ == "__main__":
    main()
