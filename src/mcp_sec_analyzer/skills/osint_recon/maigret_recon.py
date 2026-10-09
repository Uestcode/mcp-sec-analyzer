"""OSINT Username Dossier & Digital Footprint Reconnaissance via Maigret.

Collects public profiles, account registrations, tags, and metadata across
thousands of social networks, developer platforms, and forums.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

logger = logging.getLogger("mcp_sec_analyzer.osint.maigret")


def get_maigret_stats() -> dict[str, Any]:
    """Retrieve database statistics and coverage metrics from the local Maigret OSINT database."""
    try:
        from maigret.sites import MaigretDatabase

        db_path = Path.home() / ".maigret" / "data.json"
        if not db_path.exists():
            # Run quick update if database file does not exist yet
            subprocess.run(
                [sys.executable, "-m", "maigret", "--force-update"],
                capture_output=True,
                text=True,
                timeout=30,
            )

        db = MaigretDatabase()
        if db_path.exists():
            db.load_from_file(str(db_path))

        stats_text = db.get_db_stats() if hasattr(db, "get_db_stats") else ""
        total_sites = len(db.sites) if hasattr(db, "sites") else 8000

        # Extract top tags if available
        tags_list = []
        if hasattr(db, "_tags"):
            if isinstance(db._tags, dict):
                tags_list = sorted(
                    [{"tag": k, "sites_count": len(v)} for k, v in db._tags.items()],
                    key=lambda x: x["sites_count"],
                    reverse=True,
                )[:25]
            elif isinstance(db._tags, list):
                tags_list = [{"tag": str(t)} for t in db._tags[:25]]

        return {
            "status": "success",
            "total_supported_sites": total_sites,
            "database_file": str(db_path),
            "top_categories_tags": tags_list,
            "raw_stats_summary": stats_text,
        }
    except Exception as e:
        logger.error(f"Failed to fetch Maigret database stats: {e}")
        return {
            "status": "error",
            "error": str(e),
            "message": "Could not retrieve Maigret database metrics.",
        }


def search_username_maigret(
    username: str,
    top_sites: int = 50,
    tags: str | None = None,
    site: str | None = None,
    timeout: int = 15,
    no_extracting: bool = False,
    keep_report: bool = True,
    use_tor: bool = False,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Search for accounts associated with a username across web platforms using Maigret OSINT.

    Scans public sites, forums, and developer networks to uncover digital footprints,
    claimed profiles, profile pictures, full names, follower metrics, and tags.
    Supports Stealth Mode via Tor Onion routing or SOCKS5 proxies to camouflage investigator traffic.

    Args:
        username: The target username to investigate (e.g., 'torvalds', 'octocat').
        top_sites: Number of top sites to check ranked by popularity (default: 50).
        tags: Optional comma-separated categories/tags to filter sites (e.g. 'coding,social,tech').
        site: Optional specific site name or comma-separated site list (e.g. 'GitHub,Reddit,Twitter').
        timeout: HTTP request timeout in seconds per site check (default: 15).
        no_extracting: Disable extracting extended info (avatars, full names, follower counts).
        keep_report: Whether to persist the generated JSON dossier in the reports/ folder.
        use_tor: Forçar roteamento pelo nó Tor / Onion proxy para camuflar tráfego.
        proxy: URL customizada do proxy Tor/SOCKS5 (ex: 'socks5://127.0.0.1:9050').
    """
    clean_username = username.strip()
    if not clean_username:
        return {"error": "Username cannot be empty."}

    # Resolve stealth proxy if active or explicitly requested
    from mcp_sec_analyzer.core.stealth import get_active_proxy
    active_proxy = get_active_proxy(force_tor=use_tor, custom_proxy=proxy)

    # Prepare command
    cmd: list[str] = [
        sys.executable,
        "-m",
        "maigret",
        clean_username,
        "--json",
        "simple",
        "--no-progressbar",
        "--no-color",
        "--timeout",
        str(max(3, min(timeout, 60))),
    ]

    # Inject Tor / Onion proxy if stealth mode is active
    if active_proxy:
        cmd.extend(["--tor-proxy", active_proxy])

    if site:
        sites_list = [s.strip() for s in site.split(",") if s.strip()]
        for s in sites_list:
            cmd.extend(["--site", s])
    elif tags:
        cmd.extend(["--tags", tags.strip()])
    else:
        cmd.extend(["--top-sites", str(max(5, min(top_sites, 500)))])

    if no_extracting:
        cmd.append("--no-extracting")

    reports_dir = Path("reports").resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_output_dir:
        cmd.extend(["--folderoutput", tmp_output_dir])

        try:
            # Execute search
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,  # Max 3 minutes guardrail
            )
        except subprocess.TimeoutExpired:
            return {
                "error": "Maigret search timed out after 180 seconds. Try reducing top_sites or specifying specific sites.",
                "username": clean_username,
            }
        except Exception as e:
            return {
                "error": f"Failed to execute Maigret: {e}",
                "username": clean_username,
            }

        # Check for generated simple report
        generated_json_files = list(Path(tmp_output_dir).glob("report_*_simple.json"))
        if not generated_json_files:
            generated_json_files = list(Path(tmp_output_dir).glob("*.json"))

        accounts_found = []
        interests_set = set()
        persisted_report_path: str | None = None

        if generated_json_files:
            report_file = generated_json_files[0]
            try:
                raw_data = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
                if keep_report:
                    dest_file = reports_dir / f"maigret_{clean_username}_dossier.json"
                    shutil.copy2(report_file, dest_file)
                    persisted_report_path = str(dest_file)

                # Format discovered accounts into clean objects
                for site_name, site_info in raw_data.items():
                    status_info = site_info.get("status", {})
                    status_str = status_info.get("status", "Claimed")
                    url = status_info.get("url") or site_info.get("url_user")

                    # Extracted IDs and metadata
                    ids_dict = status_info.get("ids", {})
                    # Clean out internal metadata keys
                    meta_clean = {
                        k: v for k, v in ids_dict.items() if not k.startswith("_")
                    }

                    site_tags = site_info.get("site", {}).get("tags", [])
                    for t in site_tags:
                        interests_set.add(t)

                    accounts_found.append({
                        "site": site_name,
                        "url": url,
                        "status": status_str,
                        "tags": site_tags,
                        "metadata": meta_clean,
                        "alexa_rank": site_info.get("rank"),
                    })
            except Exception as parse_err:
                logger.warning(f"Error parsing Maigret report JSON: {parse_err}")

        # Check stdout summary
        stdout_txt = proc.stdout or ""

        # Build summary
        if accounts_found:
            site_names = ", ".join([a["site"] for a in accounts_found[:8]])
            if len(accounts_found) > 8:
                site_names += f" and {len(accounts_found) - 8} more"
            summary_msg = f"Discovered {len(accounts_found)} confirmed account(s) for '{clean_username}' across: {site_names}."
        else:
            summary_msg = f"No public accounts confirmed for '{clean_username}' in the requested scope."

        return {
            "username": clean_username,
            "total_accounts_found": len(accounts_found),
            "accounts": accounts_found,
            "inferred_interests_tags": sorted(list(interests_set)),
            "summary": summary_msg,
            "persisted_report_file": persisted_report_path,
            "stealth_mode": bool(active_proxy),
            "proxy_gateway": active_proxy,
            "stdout_preview": stdout_txt[-500:] if len(stdout_txt) > 500 else stdout_txt,
        }
