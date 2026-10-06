"""Software supply chain and dependency vulnerability auditor (Trivy / OSV equivalent)."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
import urllib.request


def query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list[dict[str, Any]]:
    """Query OSV.dev vulnerability database for a specific package and version."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "mcp-sec-analyzer/1.1.0"},
        )
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            parsed_vulns = []
            for v in vulns:
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id"))
                summary = v.get("summary") or v.get("details", "")[:120]
                
                # Determine severity
                severity = "Medium"
                for sev in v.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        score_str = sev.get("score", "")
                        if "CVSS:3" in score_str:
                            severity = "CVSS3"

                parsed_vulns.append({
                    "id": v.get("id"),
                    "cve": cve_id,
                    "summary": summary,
                    "published": v.get("published"),
                    "severity": severity,
                })
            return parsed_vulns
    except Exception:
        return []


def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse python package requirements with pinned versions (pkg==1.2.3)."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_\-]+)\s*==\s*([0-9a-zA-Z\.\-_]+)", line)
        if match:
            packages.append((match.group(1), match.group(2)))
    return packages


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """Parse npm package.json dependencies."""
    packages = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        combined = {**deps, **dev_deps}
        for pkg, ver in combined.items():
            # Clean semantic version prefixes (^, ~, >=)
            clean_ver = re.sub(r"^[~^>=<\s]+", "", ver)
            if clean_ver and re.match(r"^[0-9]", clean_ver):
                packages.append((pkg, clean_ver))
    except Exception:
        pass
    return packages


def audit_dependencies(target_path: str) -> dict[str, Any]:
    """Audit project dependencies for known vulnerabilities and CVEs via OSV.dev."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}

    manifests_found: list[Path] = []
    if path.is_file():
        manifests_found.append(path)
    else:
        for fname in ("requirements.txt", "package.json", "pyproject.toml"):
            cand = path / fname
            if cand.exists():
                manifests_found.append(cand)

    if not manifests_found:
        return {
            "target": str(path),
            "message": "No recognized dependency manifest found (checked requirements.txt, package.json).",
            "vulnerabilities_detected": 0,
        }

    results: list[dict[str, Any]] = []
    total_packages_checked = 0

    for manifest in manifests_found:
        content = manifest.read_text(encoding="utf-8", errors="ignore")
        if manifest.name == "requirements.txt":
            pkgs = parse_requirements_txt(content)
            for pkg_name, ver in pkgs:
                total_packages_checked += 1
                vulns = query_osv(pkg_name, ver, ecosystem="PyPI")
                if vulns:
                    results.append({
                        "manifest": manifest.name,
                        "ecosystem": "PyPI",
                        "package": pkg_name,
                        "installed_version": ver,
                        "vulnerabilities_count": len(vulns),
                        "cves": vulns[:5],
                    })
        elif manifest.name == "package.json":
            pkgs = parse_package_json(content)
            for pkg_name, ver in pkgs:
                total_packages_checked += 1
                vulns = query_osv(pkg_name, ver, ecosystem="npm")
                if vulns:
                    results.append({
                        "manifest": manifest.name,
                        "ecosystem": "npm",
                        "package": pkg_name,
                        "installed_version": ver,
                        "vulnerabilities_count": len(vulns),
                        "cves": vulns[:5],
                    })

    return {
        "target": str(path),
        "manifests_analyzed": [m.name for m in manifests_found],
        "packages_checked": total_packages_checked,
        "vulnerable_packages_found": len(results),
        "vulnerabilities": results,
    }
