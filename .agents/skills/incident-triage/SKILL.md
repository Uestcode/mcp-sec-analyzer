---
name: incident-triage
description: Guides digital forensics and security incident response triage according to the NIST SP 800-61r2 lifecycle.
---

# Incident Response Triage (DFIR & NIST SP 800-61r2)

This skill guides security analysts through the triage, containment, and communication phases of a cybersecurity incident.

## Incident Response Lifecycle

### Phase 1: Triage & Severity Classification
- **P1 - Critical:** Active data exfiltration, ransomware encryption, or root domain controller compromise.
- **P2 - High:** Privilege escalation, internal lateral movement, active command-and-control beaconing.
- **P3 - Medium:** Contained malware infection, single unauthorized credential attempt, phishing click without execution.
- **P4 - Low:** Superficial port scans, automated web vulnerability probes blocked by firewall.

### Phase 2: Containment & Evidence Preservation
1. **Network Quarantine:** Isolate the compromised host at the switch/VLAN level or host firewall.
2. **Credential Invalidation:** Revoke active OAuth/session tokens and force password/MFA resets.
3. **Forensic Capture:** Dump volatile RAM before powering down the machine; take storage snapshots.
4. **Log Retention:** Freeze audit logs (syslog, Windows Event ID 4624/4688, EDR telemetry).

### Phase 3: Stakeholder Communication
- Prepare tailored briefings for technical teams, executives, and affected customers.

## Executable MCP Tools Available:
- `triage_security_incident`: Generates severity score, containment playbook, and forensic checklists.
- `generate_incident_comms`: Drafts professional technical post-mortems and executive briefings.
