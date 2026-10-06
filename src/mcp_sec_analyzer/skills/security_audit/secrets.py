"""Secret and credential leakage scanner (Gitleaks equivalent)."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

# Rules for known credential and token formats
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": "High",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
        "severity": "Critical",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\\-_]{35})\b"),
        "severity": "High",
    },
    {
        "name": "Slack Webhook / Token",
        "pattern": re.compile(r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48})"),
        "severity": "High",
    },
    {
        "name": "Discord Webhook",
        "pattern": re.compile(r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{60,70})"),
        "severity": "Medium",
    },
    {
        "name": "Private Key Block",
        "pattern": re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"),
        "severity": "Critical",
    },
    {
        "name": "Generic Hardcoded Secret / Password",
        "pattern": re.compile(r"""(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|bearer[_-]?token|password|passwd|client[_-]?secret)\s*[:=]\s*["']([^"'\s]{8,})["']"""),
        "severity": "Medium",
    },
]

IGNORE_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".idea", ".vscode", ".mcp_memory"}
MAX_FILE_SIZE = 4 * 1024 * 1024  # 4MB


def redact_secret(val: str) -> str:
    """Mask secret value preserving prefix and suffix for identification."""
    if len(val) <= 8:
        return "********"
    return f"{val[:4]}{'*' * (len(val) - 8)}{val[-4:]}"


def scan_file_for_secrets(file_path: Path) -> list[dict[str, Any]]:
    """Scan a single file for exposed secrets and credentials."""
    findings: list[dict[str, Any]] = []

    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return []

        # Read as UTF-8 with fallback
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                # Avoid analyzing extremely long compiled lines (e.g. minified JS)
                if len(line) > 2000:
                    continue

                for rule in SECRET_PATTERNS:
                    match = rule["pattern"].search(line)
                    if match:
                        raw_match = match.group(1) if match.groups() else match.group(0)
                        findings.append({
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "file": str(file_path),
                            "line": line_no,
                            "snippet": redact_secret(raw_match),
                        })
    except Exception:
        pass

    return findings


def scan_secrets(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Scan a file or directory tree for hardcoded credentials, API keys, and secrets."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}

    all_findings: list[dict[str, Any]] = []
    scanned_files_count = 0

    if path.is_file():
        all_findings = scan_file_for_secrets(path)
        scanned_files_count = 1
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                f_path = Path(root) / f
                findings = scan_file_for_secrets(f_path)
                all_findings.extend(findings)
                scanned_files_count += 1
                if len(all_findings) >= max_findings:
                    break
            if len(all_findings) >= max_findings:
                break

    return {
        "target": str(path),
        "files_scanned": scanned_files_count,
        "secrets_detected": len(all_findings),
        "findings": all_findings[:max_findings],
    }
