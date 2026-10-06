"""OWASP Top 10 and API Security Top 10 code audit engine."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

OWASP_TOP10_RULES = [
    {
        "category": "A01:2021-Broken Access Control",
        "name": "Potential IDOR / Direct Parameter Object Lookup",
        "pattern": re.compile(r"""(?:SELECT\s+.*FROM\s+\w+\s+WHERE\s+(?:id|user_id)\s*=\s*['"]?\s*\+\s*(?:req|request)|params\[['"]id['"]\])""", re.IGNORECASE),
        "severity": "High",
        "remediation": "Validate that the authenticated session owns the requested object ID before retrieval.",
    },
    {
        "category": "A02:2021-Cryptographic Failures",
        "name": "Insecure Pseudo-Random Number Generator for Security",
        "pattern": re.compile(r"""\b(?:random\.random\(\)|random\.randint\(|Math\.random\(\))\b"""),
        "severity": "Medium",
        "remediation": "Use cryptographically secure random number generators (secrets module in Python, crypto.getRandomValues in JS).",
    },
    {
        "category": "A03:2021-Injection",
        "name": "Server-Side Template Injection (SSTI)",
        "pattern": re.compile(r"""render_template_string\s*\("""),
        "severity": "Critical",
        "remediation": "Do not pass user-controlled input directly into template string renderers.",
    },
    {
        "category": "A05:2021-Security Misconfiguration",
        "name": "Production Debug Mode Enabled",
        "pattern": re.compile(r"""(?i)(?:app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)"""),
        "severity": "High",
        "remediation": "Disable debug mode in production to avoid exposing interactive debug consoles and stack traces.",
    },
    {
        "category": "A07:2021-Identification and Authentication Failures",
        "name": "JWT Signature Verification Disabled",
        "pattern": re.compile(r"""(?i)(?:jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[['"]none['"]\])"""),
        "severity": "Critical",
        "remediation": "Always verify JWT signatures and specify accepted secure signature algorithms (e.g. HS256, RS256).",
    },
    {
        "category": "A10:2021-Server-Side Request Forgery (SSRF)",
        "name": "Unvalidated Outbound Request from User Input",
        "pattern": re.compile(r"""(?:requests\.(?:get|post)\s*\(\s*(?:request|req)\.(?:args|params|body|GET)\[|fetch\s*\(\s*req\.(?:query|body)\.)"""),
        "severity": "High",
        "remediation": "Validate outbound URLs against a strict allowlist of domains and block private/internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
    },
]

OWASP_API_RULES = [
    {
        "category": "API1:2023-Broken Object Level Authorization",
        "name": "Unchecked Path Parameter Object Lookup",
        "pattern": re.compile(r"""(?:@(?:app|router)\.(?:get|post|put|delete)\(['"]/[^'"]*\{(?:id|user_id|doc_id)\}['"]|router\.(?:get|post)\(['"]/[^'"]*:(?:id|user_id)['"])"""),
        "severity": "Medium",
        "remediation": "Ensure route handler verifies the user has authorization for the exact entity identified by the path param.",
    },
    {
        "category": "API3:2023-Broken Object Property Level Authorization",
        "name": "Mass Assignment Vulnerability Risk",
        "pattern": re.compile(r"""(?:\.update\s*\(\s*request\.(?:json|POST)\)|\.create\s*\(\s*\*\*request\.json|new\s+\w+\s*\(\s*req\.body\s*\))"""),
        "severity": "High",
        "remediation": "Use explicit schema DTOs / Pydantic models to strictly whitelist allowed input fields.",
    },
    {
        "category": "API8:2023-Security Misconfiguration",
        "name": "Permissive Wildcard CORS Configuration",
        "pattern": re.compile(r"""(?i)(?:CORSMiddleware[^)]*allow_origins\s*=\s*\[['"]\*['"]\]|res\.setHeader\(['"]Access-Control-Allow-Origin['"],\s*['"]\*['"]\))"""),
        "severity": "Medium",
        "remediation": "Avoid wildcard CORS origins if the API handles authenticated user sessions or credentials.",
    },
]

IGNORE_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".mcp_memory"}
SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".php", ".java"}


def audit_owasp_top10(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Audit codebase against OWASP Top 10 (2021) web application security risks."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}

    findings = []
    files_scanned = 0

    def scan_file(f_path: Path):
        nonlocal files_scanned
        try:
            with f_path.open("r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    if len(line) > 1000 or line.strip().startswith(("#", "//", "/*")):
                        continue
                    for rule in OWASP_TOP10_RULES:
                        if rule["pattern"].search(line):
                            findings.append({
                                "category": rule["category"],
                                "name": rule["name"],
                                "severity": rule["severity"],
                                "file": str(f_path),
                                "line": line_no,
                                "snippet": line.strip()[:140],
                                "remediation": rule["remediation"],
                            })
            files_scanned += 1
        except Exception:
            pass

    if path.is_file():
        scan_file(path)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                f_path = Path(root) / f
                if f_path.suffix.lower() in SOURCE_EXTS:
                    scan_file(f_path)
                    if len(findings) >= max_findings:
                        break
            if len(findings) >= max_findings:
                break

    return {
        "target": str(path),
        "framework": "OWASP Top 10 (2021)",
        "files_scanned": files_scanned,
        "violations_found": len(findings),
        "findings": findings[:max_findings],
    }


def audit_api_security(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Audit API route handlers and endpoints against OWASP API Security Top 10."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}

    findings = []
    files_scanned = 0

    def scan_file(f_path: Path):
        nonlocal files_scanned
        try:
            with f_path.open("r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    if len(line) > 1000 or line.strip().startswith(("#", "//", "/*")):
                        continue
                    for rule in OWASP_API_RULES:
                        if rule["pattern"].search(line):
                            findings.append({
                                "category": rule["category"],
                                "name": rule["name"],
                                "severity": rule["severity"],
                                "file": str(f_path),
                                "line": line_no,
                                "snippet": line.strip()[:140],
                                "remediation": rule["remediation"],
                            })
            files_scanned += 1
        except Exception:
            pass

    if path.is_file():
        scan_file(path)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                f_path = Path(root) / f
                if f_path.suffix.lower() in SOURCE_EXTS:
                    scan_file(f_path)
                    if len(findings) >= max_findings:
                        break
            if len(findings) >= max_findings:
                break

    return {
        "target": str(path),
        "framework": "OWASP API Security Top 10 (2023)",
        "files_scanned": files_scanned,
        "violations_found": len(findings),
        "findings": findings[:max_findings],
    }
