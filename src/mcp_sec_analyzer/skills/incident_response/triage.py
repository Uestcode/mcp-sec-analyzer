"""Incident response triage playbooks and security communication generator (NIST SP 800-61r2)."""

from __future__ import annotations

import datetime
from typing import Any


def triage_security_incident(
    incident_description: str,
    affected_assets: list[str] | str,
    observed_iocs: list[str] | str | None = None,
    data_exfiltration_suspected: bool = False,
) -> dict[str, Any]:
    """Execute structured incident triage, severity classification, and containment planning (NIST SP 800-61r2)."""
    assets = [affected_assets] if isinstance(affected_assets, str) else affected_assets
    iocs = [observed_iocs] if isinstance(observed_iocs, str) else (observed_iocs or [])

    desc_lower = incident_description.lower()

    # Determine Severity (P1 to P4)
    if data_exfiltration_suspected or any(k in desc_lower for k in ("ransomware", "domain controller", "database leak", "root compromise")):
        severity = "P1 - Critical"
        escalation_timeline = "Immediate (within 15 minutes). Notify CISO, legal, and executive team."
    elif any(k in desc_lower for k in ("privilege escalation", "lateral movement", "c2", "production down")):
        severity = "P2 - High"
        escalation_timeline = "Within 1 hour. Assemble active Incident Response War Room."
    elif any(k in desc_lower for k in ("phishing", "unauthorized login", "malware contained", "suspicious scan")):
        severity = "P3 - Medium"
        escalation_timeline = "Within 4 hours. Assign to security operations analyst."
    else:
        severity = "P4 - Low"
        escalation_timeline = "Within 24 hours. Standard ticket workflow."

    # Immediate Containment Checklist
    containment_actions = [
        "Isolate affected host(s) at network level (quarantine VLAN or host firewall rule).",
        "Revoke active sessions and force password/MFA reset for compromised user accounts.",
        "Add observed IOCs (IPs, domains, hashes) to perimeter firewall, EDR, and DNS blocklists.",
    ]
    if data_exfiltration_suspected:
        containment_actions.append("Halt unauthorized outbound data egress tunnels and restrict external API keys.")

    # Forensic Evidence Preservation
    evidence_checklist = [
        "Capture volatile memory (RAM dump) before rebooting or powering down the machine.",
        "Preserve snapshot or bit-stream forensic image of storage drives.",
        "Export and lock central logs (Windows Event Logs, syslog, cloud audit trails, firewall logs).",
        "Document chain of custody for all acquired artifacts with SHA-256 hashes.",
    ]

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "severity": severity,
        "escalation_sla": escalation_timeline,
        "affected_assets_count": len(assets),
        "affected_assets": assets,
        "iocs_recorded": iocs,
        "immediate_containment_playbook": containment_actions,
        "evidence_preservation_checklist": evidence_checklist,
        "next_phase": "Eradication & Root-Cause Investigation",
    }


def generate_incident_comms(
    incident_id: str,
    incident_summary: str,
    current_status: str = "Contained",
    audience: str = "technical",
) -> dict[str, Any]:
    """Generate professional security incident communications tailored by audience (Executive, Technical, Customer)."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    if audience.lower() == "executive":
        template = f"""# EXECUTIVE BRIEFING: Security Incident [{incident_id}]
**Date/Time:** {now_str}  
**Status:** {current_status}  

## 1. Executive Summary
{incident_summary}

## 2. Business Impact Assessment
- Operations: Systems isolated to protect core business workflows.
- Financial / Regulatory: Assessment underway regarding compliance notification obligations.

## 3. Current Mitigation Actions
- Threat contained by the Security Operations and Incident Response teams.
- Active investigation ongoing to verify complete eradication.

## 4. Next Milestone & Update
Next executive status update scheduled in 2 hours.
"""
    elif audience.lower() == "customer":
        template = f"""# CUSTOMER SECURITY ADVISORY: Notice Regarding Incident [{incident_id}]
**Date:** {now_str}  

Dear Valued Customers and Partners,

We are writing to provide a transparent update regarding a security event that our operations team recently identified and addressed.

**What Happened:**
{incident_summary}

**What We Did:**
Our security team took immediate corrective action to secure the affected environment, isolate impacted components, and enhance our monitoring controls. The situation is currently {current_status}.

**What You Should Do:**
As a standard security precaution, we recommend reviewing your account credentials and ensuring multi-factor authentication (MFA) remains enabled across all user profiles.

We maintain a strict commitment to data security and will provide further updates as our investigation concludes.
"""
    else:  # Technical post-mortem
        template = f"""# TECHNICAL POST-MORTEM & ROOT CAUSE ANALYSIS: [{incident_id}]
**Date:** {now_str} | **Status:** {current_status}  

## 1. Incident Overview & Technical Scope
{incident_summary}

## 2. Chronological Timeline of Events
- T0 (Detection): Anomaly triggered on telemetry stream.
- T1 (Triage): Incident severity classified; War Room formed.
- T2 (Containment): Compromised network interfaces and credentials isolated.
- T3 (Current): Post-incident eradication and system integrity verification.

## 3. Root Cause Analysis (RCA)
Detailed technical vector under examination. Evidence preserved for digital forensics.

## 4. Preventive & Corrective Actions
1. Deploy strict egress filtering and credential rotation.
2. Implement automated detection rules for observed behavior.
3. Review architectural trust boundaries to prevent recurrence.
"""

    return {
        "incident_id": incident_id,
        "audience": audience.lower(),
        "rendered_communication": template.strip(),
    }
