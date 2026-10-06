"""AI and LLM application security audit (OWASP Top 10 for LLMs)."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

LLM_SEC_RULES = [
    {
        "category": "LLM01: Prompt Injection Risk",
        "name": "Direct User Input Concatenated into System Prompt",
        "pattern": re.compile(r"""(?:f["'].*(?:system|prompt).*\{[a-zA-Z0-9_]*(?:user|input|query|message)\}.*["']|\.system\s*\(\s*f["'].*\{)"""),
        "severity": "High",
        "remediation": "Separate system instructions and untrusted user input using clear message roles or strict XML/Markdown delimiters.",
    },
    {
        "category": "LLM02: Insecure Output Handling",
        "name": "Unvalidated LLM Output Passed to Execution Sinks",
        "pattern": re.compile(r"""(?:eval\s*\(\s*(?:response|completion|ai_output|llm_out)|subprocess\.(?:Popen|run)\s*\(\s*(?:response|completion|ai_output|llm_out))"""),
        "severity": "Critical",
        "remediation": "Treat LLM outputs as untrusted user input. Never execute raw model output directly in shell or eval.",
    },
    {
        "category": "LLM02: Insecure Output Handling (SQL Injection via LLM)",
        "name": "Raw LLM Output Executed Directly as SQL Query",
        "pattern": re.compile(r"""(?:cursor|db)\.execute\s*\(\s*(?:sql_query|generated_sql|response\.content|completion\.text)"""),
        "severity": "High",
        "remediation": "Validate and constrain AI-generated SQL using read-only database connections and query validation parsers.",
    },
]

IGNORE_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".mcp_memory"}


def audit_prompt_injection(target_path: str, max_findings: int = 50) -> dict[str, Any]:
    """Audit AI and LLM application codebase against prompt injection and output execution risks."""
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
                    if len(line) > 1000 or line.strip().startswith(("#", "//")):
                        continue
                    for rule in LLM_SEC_RULES:
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
                if f_path.suffix.lower() in (".py", ".js", ".ts"):
                    scan_file(f_path)
                    if len(findings) >= max_findings:
                        break
            if len(findings) >= max_findings:
                break

    return {
        "target": str(path),
        "framework": "OWASP Top 10 for Large Language Model Applications",
        "files_scanned": files_scanned,
        "violations_found": len(findings),
        "findings": findings[:max_findings],
    }
