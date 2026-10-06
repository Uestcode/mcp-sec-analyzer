"""Threat intelligence, MITRE ATT&CK framework mapping, and IOC defanging engine."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
import urllib.parse
import urllib.request

# Core Enterprise MITRE ATT&CK knowledge base mapping
MITRE_ATTACK_DB = [
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, cmd) to execute commands.",
        "mitigations": ["M1038 Execution Prevention (AppLocker, WDAC)", "M1047 Audit logging (ScriptBlock Logging)"],
        "keywords": ["powershell", "cmd", "bash", "sh", "script", "wscript", "cscript"],
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Privilege Escalation / Defense Evasion",
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "mitigations": ["M1040 Endpoint Detection & Response (EDR behavioral monitoring)", "M1026 Privileged Account Management"],
        "keywords": ["virtualalloc", "createremotethread", "writeprocessmemory", "ptrace", "dll injection", "hollowing"],
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries may attempt to dump credentials from the operating system memory, security accounts manager (SAM), or LSASS.",
        "mitigations": ["M1043 Credential Guard", "M1027 Password Policies", "M1017 User Training"],
        "keywords": ["lsass", "sam", "mimikatz", "shadow copy", "hash dump", "procdump"],
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or packing.",
        "mitigations": ["M1049 Antivirus/Antimalware with unpacking heuristics", "M1031 Network Intrusion Prevention"],
        "keywords": ["packer", "high entropy", "upx", "base64", "xor", "obfuscation"],
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries may send phishing messages with malicious attachments or links to gain initial access.",
        "mitigations": ["M1054 Software Configuration (SPF, DKIM, DMARC)", "M1017 User Training"],
        "keywords": ["phishing", "spearphishing", "email attachment", "malicious link"],
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources (Ransomware).",
        "mitigations": ["M1053 Data Backup (offline, immutable backups)", "M1028 Operating System Configuration"],
        "keywords": ["ransomware", "encrypt", "aes", "rsa", "shadow copy deletion", "vssadmin"],
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries may take advantage of a weakness in an Internet-facing computer or program to gain access.",
        "mitigations": ["M1051 Update Software (Prompt patching)", "M1030 Web Application Firewall (WAF)"],
        "keywords": ["public facing", "cve", "web vulnerability", "rce", "remote code execution"],
    },
]


def map_mitre_attack(query: str) -> dict[str, Any]:
    """Map security observations, APIs, or keywords to the MITRE ATT&CK framework."""
    q_clean = query.strip().lower()
    matches = []

    for item in MITRE_ATTACK_DB:
        score = 0
        if q_clean == item["id"].lower() or q_clean in item["name"].lower():
            score += 10
        for kw in item["keywords"]:
            if kw in q_clean or q_clean in kw:
                score += 5
        if q_clean in item["description"].lower():
            score += 2

        if score > 0:
            matches.append({
                "technique_id": item["id"],
                "name": item["name"],
                "tactic": item["tactic"],
                "platforms": item["platforms"],
                "description": item["description"],
                "defensive_mitigations": item["mitigations"],
                "match_score": score,
            })

    matches.sort(key=lambda x: x["match_score"], reverse=True)

    return {
        "query": query,
        "techniques_matched": len(matches),
        "results": matches[:5] if matches else [
            {
                "message": f"No direct technique mapped for '{query}'. Consult enterprise ATT&CK matrix.",
                "general_guidance": "Classify the observation under initial access, execution, persistence, or evasion.",
            }
        ],
    }


def analyze_ioc_indicator(indicator: str) -> dict[str, Any]:
    """Categorize, validate, and safely defang an Indicator of Compromise (IOC)."""
    val = indicator.strip()

    ioc_type = "Unknown"
    defanged = val

    # IPv4 check
    if re.match(r"^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$", val):
        ioc_type = "IPv4 Address"
        defanged = val.replace(".", "[.]")

    # Hash checks
    elif re.match(r"^[0-9a-fA-F]{32}$", val):
        ioc_type = "MD5 Hash"
    elif re.match(r"^[0-9a-fA-F]{40}$", val):
        ioc_type = "SHA-1 Hash"
    elif re.match(r"^[0-9a-fA-F]{64}$", val):
        ioc_type = "SHA-256 Hash"

    # URL check
    elif val.startswith(("http://", "https://")):
        ioc_type = "URL"
        defanged = val.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

    # Domain check
    elif re.match(r"^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+$", val):
        ioc_type = "Domain / FQDN"
        defanged = val.replace(".", "[.]")

    # CVE check
    elif re.match(r"^CVE-\d{4}-\d{4,8}$", val, re.IGNORECASE):
        ioc_type = "CVE Identifier"

    # Email check
    elif "@" in val and "." in val:
        ioc_type = "Email Address"
        defanged = val.replace("@", "[at]").replace(".", "[.]")

    # Defensive action advice
    hunting_advice = []
    if "Hash" in ioc_type:
        hunting_advice.append("Check EDR/SIEM process execution telemetry for matching hash.")
        hunting_advice.append("Add hash to blocklist on endpoint protection engines.")
    elif ioc_type in ("IPv4 Address", "Domain / FQDN", "URL"):
        hunting_advice.append("Query DNS / firewall / proxy logs for outbound network egress.")
        hunting_advice.append("Add indicator to boundary perimeter firewall / web proxy blocklist.")

    return {
        "raw_indicator": val,
        "type": ioc_type,
        "defanged_indicator": defanged,
        "hunting_and_containment_advice": hunting_advice,
    }


def lookup_cve_details(cve_id: str) -> dict[str, Any]:
    """Retrieve details and advisories for a specific CVE from the OSV open vulnerability database."""
    clean_cve = cve_id.strip().upper()
    if not clean_cve.startswith("CVE-"):
        return {"error": "Invalid format. CVE ID must start with 'CVE-' (e.g. CVE-2021-44228)."}

    url = f"https://api.osv.dev/v1/vulns/{clean_cve}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mcp-cve-lookup/1.0"})
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            data = json.loads(resp.read().decode())
            summary = data.get("summary") or (data.get("details", "")[:200] + "...")
            affected_pkgs = []
            for aff in data.get("affected", []):
                pkg_name = aff.get("package", {}).get("name", "Unknown")
                ecosystem = aff.get("package", {}).get("ecosystem", "Unknown")
                affected_pkgs.append(f"{ecosystem}:{pkg_name}")

            return {
                "cve_id": clean_cve,
                "summary": summary,
                "published": data.get("published"),
                "modified": data.get("modified"),
                "affected_packages": list(set(affected_pkgs))[:10],
                "references": [r.get("url") for r in data.get("references", [])[:5]],
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"cve_id": clean_cve, "status": "Not found in OSV database (may be private or reserved)."}
        return {"error": f"HTTP Error querying CVE: {e}"}
    except Exception as e:
        return {"error": f"Failed to retrieve CVE: {e}"}
