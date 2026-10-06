"""Static application security testing (SAST) rule scanner."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

SAST_RULES = [
    {
        "id": "SEC-PY-001",
        "name": "Command Injection via Shell",
        "pattern": re.compile(r"""(?:subprocess\.(?:Popen|run|call)\([^)]*shell\s*=\s*True|os\.system\s*\()"""),
        "severity": "High",
        "languages": [".py"],
        "description": "Executing system shell commands with potential untrusted parameters.",
    },
    {
        "id": "SEC-PY-002",
        "name": "Insecure Deserialization (Pickle/YAML)",
        "pattern": re.compile(r"""(?:pickle\.loads?\s*\(|yaml\.load\s*\([^)]*(?!SafeLoader)[^)]*\))"""),
        "severity": "Critical",
        "languages": [".py"],
        "description": "Deserializing untrusted data can lead to arbitrary code execution.",
    },
    {
        "id": "SEC-PY-003",
        "name": "Dynamic Code Evaluation",
        "pattern": re.compile(r"""\b(?:eval|exec)\s*\("""),
        "severity": "High",
        "languages": [".py", ".js", ".ts"],
        "description": "Dynamic evaluation allows executing arbitrary strings as code.",
    },
    {
        "id": "SEC-PY-004",
        "name": "SQL String Formatting / Injection Risk",
        "pattern": re.compile(r"""(?:\.execute\s*\(\s*f["'].*SELECT|cursor\.execute\s*\(\s*["'].*%s.*SELECT)"""),
        "severity": "High",
        "languages": [".py"],
        "description": "Concatenating or formatting variables directly into SQL queries.",
    },
    {
        "id": "SEC-GEN-005",
        "name": "Weak / Deprecated Cryptographic Hash",
        "pattern": re.compile(r"""(?:hashlib\.md5\(|hashlib\.sha1\(|Crypto\.Cipher\.(?:DES|ARC4))"""),
        "severity": "Medium",
        "languages": [".py"],
        "description": "MD5/SHA1/DES are cryptographically broken; use SHA-256 or modern AEAD ciphers.",
    },
    {
        "id": "SEC-JS-001",
        "name": "DOM-Based XSS Sink",
        "pattern": re.compile(r"""(?:\.innerHTML\s*=|document\.write\s*\()"""),
        "severity": "Medium",
        "languages": [".js", ".jsx", ".ts", ".tsx"],
        "description": "Writing unescaped data to innerHTML or document.write creates XSS risks.",
    },
]

IGNORE_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".mcp_memory"}


def scan_source_file(file_path: Path) -> list[dict[str, Any]]:
    """Scan a source code file against SAST security rules."""
    ext = file_path.suffix.lower()
    applicable_rules = [r for r in SAST_RULES if ext in r["languages"]]
    if not applicable_rules:
        return []

    findings = []
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                if len(line) > 1000 or line.strip().startswith(("#", "//", "/*")):
                    continue
                for rule in applicable_rules:
                    if rule["pattern"].search(line):
                        findings.append({
                            "rule_id": rule["id"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "file": str(file_path),
                            "line": line_no,
                            "code_snippet": line.strip()[:150],
                            "description": rule["description"],
                        })
    except Exception:
        pass

    return findings


def run_sast_scan(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Execute static application security testing (SAST) on a repository or directory."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}

    all_findings = []
    files_scanned = 0

    if path.is_file():
        all_findings = scan_source_file(path)
        files_scanned = 1
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                f_path = Path(root) / f
                if f_path.suffix.lower() in (".py", ".js", ".ts", ".jsx", ".tsx"):
                    findings = scan_source_file(f_path)
                    all_findings.extend(findings)
                    files_scanned += 1
                    if len(all_findings) >= max_findings:
                        break
            if len(all_findings) >= max_findings:
                break

    return {
        "target": str(path),
        "source_files_scanned": files_scanned,
        "sast_issues_detected": len(all_findings),
        "findings": all_findings[:max_findings],
    }
