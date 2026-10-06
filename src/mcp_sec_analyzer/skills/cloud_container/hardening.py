"""Container security (CIS Docker benchmark) and Cloud IAM policy hardening auditor."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any


def audit_dockerfile(dockerfile_path_or_content: str) -> dict[str, Any]:
    """Audit Dockerfile against container security and CIS benchmark hardening practices."""
    path = Path(dockerfile_path_or_content)
    if path.exists() and path.is_file():
        content = path.read_text(encoding="utf-8", errors="ignore")
        source_name = path.name
    else:
        content = dockerfile_path_or_content
        source_name = "raw_content"

    lines = content.splitlines()
    findings = []

    has_user_instruction = False
    has_healthcheck = False

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Check FROM latest or unpinned
        from_match = re.match(r"^FROM\s+([^\s]+)", line, re.IGNORECASE)
        if from_match:
            base_image = from_match.group(1)
            if ":latest" in base_image or ":" not in base_image:
                findings.append({
                    "rule": "Unpinned Base Image Tag",
                    "severity": "Medium",
                    "line": line_no,
                    "snippet": line,
                    "remediation": "Pin specific version tags or digests (e.g., python:3.11-slim@sha256:...)",
                })

        # Check USER directive
        if re.match(r"^USER\s+", line, re.IGNORECASE):
            if "root" in line.lower():
                findings.append({
                    "rule": "Container Configured Explicitly as Root",
                    "severity": "High",
                    "line": line_no,
                    "snippet": line,
                    "remediation": "Create and switch to a dedicated non-root user (e.g. USER appuser).",
                })
            else:
                has_user_instruction = True

        # Check HEALTHCHECK
        if re.match(r"^HEALTHCHECK\s+", line, re.IGNORECASE):
            has_healthcheck = True

        # Check for piped shell executions
        if re.search(r"(?:curl|wget)[^|]*\|\s*(?:sh|bash)", line, re.IGNORECASE):
            findings.append({
                "rule": "Blind Shell Execution via Pipe (curl|sh)",
                "severity": "High",
                "line": line_no,
                "snippet": line,
                "remediation": "Download, verify hash/signature, and execute scripts in separate steps.",
            })

        # Check for hardcoded secrets in ENV or ARG
        if re.match(r"^(?:ENV|ARG)\s+.*(?:password|secret|key|token|auth)\s*=", line, re.IGNORECASE):
            findings.append({
                "rule": "Potential Secret Baked into Image Metadata (ENV/ARG)",
                "severity": "Critical",
                "line": line_no,
                "snippet": line,
                "remediation": "Use Docker BuildKit secrets (--secret) or runtime secrets managers.",
            })

    if not has_user_instruction:
        findings.append({
            "rule": "Missing USER Instruction (Runs as Root by Default)",
            "severity": "High",
            "line": 0,
            "snippet": "No 'USER' directive found",
            "remediation": "Add 'USER nonroot' to avoid running processes with host root capabilities.",
        })

    if not has_healthcheck:
        findings.append({
            "rule": "Missing HEALTHCHECK Directive",
            "severity": "Low",
            "line": 0,
            "snippet": "No 'HEALTHCHECK' directive found",
            "remediation": "Define a container HEALTHCHECK to facilitate orchestration resilience.",
        })

    return {
        "source": source_name,
        "total_lines": len(lines),
        "issues_detected": len(findings),
        "findings": findings,
    }


def audit_iam_policy(policy_json_str: str) -> dict[str, Any]:
    """Audit Cloud / AWS IAM policy JSON for overly permissive wildcards and escalation risks."""
    try:
        if Path(policy_json_str).exists() and Path(policy_json_str).is_file():
            data = json.loads(Path(policy_json_str).read_text(encoding="utf-8"))
        else:
            data = json.loads(policy_json_str)
    except Exception as e:
        return {"error": f"Invalid JSON policy: {e}"}

    statements = data.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    findings = []

    ESCALATION_ACTIONS = {
        "iam:passrole": "Allows passing roles to services, potentially achieving privilege escalation.",
        "iam:createpolicyversion": "Allows modifying policies to grant unauthorized permissions.",
        "iam:attachrolepolicy": "Allows attaching administrative policies to existing roles.",
        "iam:putuserpolicy": "Allows inline policy injection to elevate user access.",
    }

    for idx, stmt in enumerate(statements, start=1):
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        # Check full wildcard admin: Action: * and Resource: *
        if "*" in actions and "*" in resources:
            findings.append({
                "statement_index": idx,
                "rule": "Full Administrative Wildcard (* on *)",
                "severity": "Critical",
                "description": "Statement allows unrestricted access to all API actions on all resources.",
            })

        # Check resource wildcard with broad action
        for act in actions:
            act_lower = act.lower()
            if act_lower.endswith(":*") and "*" in resources:
                findings.append({
                    "statement_index": idx,
                    "rule": f"Service-Wide Wildcard ({act}) on All Resources",
                    "severity": "High",
                    "description": f"Grants complete permissions across {act.split(':')[0]} without resource restriction.",
                })

            if act_lower in ESCALATION_ACTIONS:
                findings.append({
                    "statement_index": idx,
                    "rule": f"Privilege Escalation Risk ({act})",
                    "severity": "High",
                    "description": ESCALATION_ACTIONS[act_lower],
                })

    return {
        "statements_evaluated": len(statements),
        "risks_identified": len(findings),
        "findings": findings,
    }
