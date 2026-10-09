"""Web Dashboard Server Launcher for Unified Cybersecurity MCP Hub."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import webbrowser

# Ensure src is in sys.path
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Ensure utf-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Launch Unified Cybersecurity MCP Hub Interactive Web Dashboard",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8000,
        help="Port number to bind (default: 8000)",
    )
    parser.add_argument(
        "--open",
        "-o",
        action="store_true",
        help="Automatically open web browser upon server start",
    )

    args = parser.parse_args()

    import uvicorn

    url = f"http://{args.host}:{args.port}"
    print("=" * 66)
    print(" 🛡️  UNIFIED CYBERSECURITY MCP HUB - WEB DASHBOARD")
    print("=" * 66)
    print(f" * Web Interface:    {url}")
    print(" * Active Tools:     36 Registered Tools across 8 Skills")
    print(" * Persistent Store: SQLite (.mcp_memory/unified_memory.db)")
    print(" * OSINT Engine:     Maigret v0.6.6 (3,000+ sites)")
    print("=" * 66)
    print(" Press Ctrl+C to stop the web server.\n")

    if args.open:
        # Open browser in a separate thread after a short delay
        import threading
        import time

        def _open():
            time.sleep(1.0)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        "mcp_sec_analyzer.web.api:app",
        host=args.host,
        port=args.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
