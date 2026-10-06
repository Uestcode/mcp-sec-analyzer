"""Multi-Skill MCP Server: General Security & Software Analysis Hub."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from .core.decorator import skill_tool
from .skills.memory_skill import (
    clear_memory as _clear_memory,
    export_investigation_report as _export_investigation_report,
    get_timeline as _get_timeline,
    recall as _recall,
    remember as _remember,
)
from .skills.rea.asar import extract_asar_archive, inspect_asar
from .skills.rea.call_graph import build_call_graph
from .skills.rea.disassembler import disassemble_window
from .skills.rea.dotnet import inspect_dotnet_assembly
from .skills.rea.framework_detector import detect_framework as _detect_framework
from .skills.rea.ghidra_bridge import check_ghidra_status
from .skills.rea.pseudocode import generate_pseudocode
from .skills.rea.session import active_session
from .skills.rea.strings_analyzer import analyze_strings as _analyze_strings
from .skills.rea.triage import triage_file as _triage_file
from .skills.rea.xrefs import find_xrefs_to_name as _find_xrefs_to_name
from .skills.security_audit.dependencies import audit_dependencies as _audit_dependencies
from .skills.security_audit.sast import run_sast_scan as _run_sast_scan
from .skills.security_audit.secrets import scan_secrets as _scan_secrets
from .skills.osint_recon.surface import (
    inspect_http_headers as _inspect_http_headers,
    inspect_tls_certificate as _inspect_tls_certificate,
    lookup_dns_records as _lookup_dns_records,
)
from .skills.threat_intel.intel import (
    map_mitre_attack as _map_mitre_attack,
    analyze_ioc_indicator as _analyze_ioc_indicator,
    lookup_cve_details as _lookup_cve_details,
)
from .skills.cloud_container.hardening import (
    audit_dockerfile as _audit_dockerfile,
    audit_iam_policy as _audit_iam_policy,
)
from .skills.appsec.owasp import (
    audit_owasp_top10 as _audit_owasp_top10,
    audit_api_security as _audit_api_security,
)
from .skills.appsec.llm_sec import audit_prompt_injection as _audit_prompt_injection
from .skills.incident_response.triage import (
    triage_security_incident as _triage_security_incident,
    generate_incident_comms as _generate_incident_comms,
)

# Initialize MCP Server instance
server = MCPServer(
    name="mcp-sec-analyzer",
    version="3.0.0",
    description="Unified Cybersecurity Hub: REA, AppSec, OWASP, Cloud Hardening, Threat Intel, and Incident Response",
)

# ============================================================================
# META-SKILL: SKILL CATALOG
# ============================================================================

@server.tool()
def list_skills() -> dict[str, Any]:
    """List available skills, active capabilities, and architecture modules in this MCP server."""
    return {
        "platform": "Unified Cybersecurity MCP Hub",
        "total_active_skills": 8,
        "active_skills": [
            {
                "id": "memory",
                "name": "Universal Persistent Context & Investigation Memory",
                "status": "active",
                "description": "Local SQLite-backed timeline and knowledge store preventing context loss across sessions.",
                "tools": ["remember", "recall", "get_timeline", "export_investigation_report", "clear_memory"],
            },
            {
                "id": "rea",
                "name": "Reverse Engineer Anything (REA Toolkit)",
                "status": "active",
                "description": "Native binary disassembly, call-graph, pseudocode, XREFs, Electron ASAR, and .NET triage.",
                "tools": [
                    "open_binary", "binary_overview", "search_strings", "list_procedures",
                    "read_function_instructions", "get_call_graph", "procedure_pseudo_code",
                    "find_xrefs_to_name", "detect_framework", "inspect_electron_asar",
                    "inspect_dotnet", "rea_doctor",
                ],
            },
            {
                "id": "security_audit",
                "name": "Defensive Security Audit & Hygiene (Gitleaks / Trivy SAST)",
                "status": "active",
                "description": "Secret leakage detection, supply chain / CVE dependency audit via OSV.dev, and SAST code rules.",
                "tools": ["scan_secrets", "audit_dependencies", "run_sast_scan"],
            },
            {
                "id": "appsec",
                "name": "Application Security & OWASP / LLM Audit (Bri Russell Skills)",
                "status": "active",
                "description": "OWASP Top 10 code assessment, REST/GraphQL API security review, and LLM prompt injection safeguards.",
                "tools": ["audit_owasp_top10", "audit_api_security", "audit_prompt_injection"],
            },
            {
                "id": "osint_recon",
                "name": "Passive Reconnaissance & Surface Posture (OSINT)",
                "status": "active",
                "description": "HTTP security headers review, SSL/TLS certificate analysis, and DNS/SPF/DMARC email posture.",
                "tools": ["inspect_http_headers", "inspect_tls_certificate", "lookup_dns_records"],
            },
            {
                "id": "threat_intel",
                "name": "Threat Intelligence & MITRE ATT&CK Defense",
                "status": "active",
                "description": "MITRE ATT&CK technique mapping, IOC validation/defanging, and CVE vulnerability lookup.",
                "tools": ["map_mitre_attack", "analyze_ioc_indicator", "lookup_cve_details"],
            },
            {
                "id": "cloud_container",
                "name": "Cloud Security & Container Hardening",
                "status": "active",
                "description": "Dockerfile CIS benchmark auditing and Cloud/AWS IAM policy least-privilege analysis.",
                "tools": ["audit_dockerfile", "audit_iam_policy"],
            },
            {
                "id": "incident_response",
                "name": "Digital Forensics & Incident Response (DFIR / NIST SP 800-61r2)",
                "status": "active",
                "description": "Rapid triage of security events, containment planning, evidence preservation, and audience communication.",
                "tools": ["triage_security_incident", "generate_incident_comms"],
            },
        ],
        "extensibility": "Modular architecture allows adding new security domains in skills/ effortlessly.",
    }


# ============================================================================
# SKILL: UNIVERSAL INVESTIGATION MEMORY
# ============================================================================

@server.tool()
def remember(
    title: str,
    content: str,
    category: str = "finding",
    tags: list[str] | str | None = None,
    skill: str = "general",
    target_ref: str | None = None,
) -> dict[str, Any]:
    """Save an observation, insight, hypothesis, IOC, or note into persistent memory."""
    return _remember(
        title=title,
        content=content,
        category=category,
        tags=tags,
        skill=skill,
        target_ref=target_ref,
    )


@server.tool()
def recall(
    query: str | None = None,
    skill: str | None = None,
    tag: str | None = None,
    category: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Search and recall past findings, notes, and context from persistent memory."""
    return _recall(
        query=query,
        skill=skill,
        tag=tag,
        category=category,
        limit=limit,
    )


@server.tool()
def get_timeline(
    skill: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieve chronological history of actions executed across any or all skills."""
    return _get_timeline(skill=skill, limit=limit)


@server.tool()
def export_investigation_report(
    skill: str | None = None,
) -> str:
    """Generate and export a comprehensive Markdown investigation dossier and report."""
    return _export_investigation_report(skill=skill)


@server.tool()
def clear_memory(
    confirm: bool = False,
    skill: str | None = None,
) -> dict[str, str]:
    """Purge memory records for a specific skill or entire database."""
    return _clear_memory(confirm=confirm, skill=skill)


# ============================================================================
# SKILL: REA (REVERSE ENGINEER ANYTHING)
# ============================================================================

@server.tool()
@skill_tool(skill="rea")
def open_binary(file_path: str) -> dict[str, Any]:
    """Open and register a target binary into the active analysis session."""
    try:
        return active_session.load(file_path)
    except Exception as e:
        return {"error": str(e)}


@server.tool()
@skill_tool(skill="rea")
def binary_overview(file_path: str | None = None) -> dict[str, Any]:
    """Provide a comprehensive structural overview of the binary (REA binary_overview)."""
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "No binary specified and no active binary session. Run 'open_binary' first."}
    return _triage_file(target)


@server.tool()
@skill_tool(skill="rea")
def search_strings(
    query: str | None = None,
    category: str = "all",
    min_length: int = 5,
    max_results: int = 100,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Search and heuristically classify strings inside the binary (REA search_strings)."""
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "No binary specified and no active binary session. Run 'open_binary' first."}
    return _analyze_strings(
        target_path=target,
        min_length=min_length,
        category=category,
        search_filter=query,
        max_results=max_results,
    )


@server.tool()
@skill_tool(skill="rea")
def list_procedures(filter_name: str | None = None, limit: int = 100) -> dict[str, Any]:
    """List discovered procedures, functions, exports, and imports in the active binary."""
    if not active_session.is_loaded():
        return {"error": "No binary currently loaded. Use 'open_binary' first."}

    procs = list(active_session.procedures.values())
    if filter_name:
        fn_lower = filter_name.lower()
        procs = [p for p in procs if fn_lower in p["name"].lower()]

    return {
        "binary": active_session.file_path.name if active_session.file_path else "",
        "total_discovered": len(active_session.procedures),
        "returned_count": min(len(procs), limit),
        "procedures": procs[:limit],
    }


@server.tool()
@skill_tool(skill="rea")
def read_function_instructions(
    procedure_or_address: str,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Fast-path instruction disassembly for a procedure or address (REA read_function_instructions)."""
    return disassemble_window(
        session=active_session,
        target=procedure_or_address,
        instruction_offset=offset,
        limit=limit,
    )


@server.tool()
@skill_tool(skill="rea")
def get_call_graph(procedure_or_address: str, depth: int = 1) -> dict[str, Any]:
    """Reconstruct callers and callees for a procedure (REA get_call_graph)."""
    return build_call_graph(
        session=active_session,
        target=procedure_or_address,
        depth=depth,
    )


@server.tool()
@skill_tool(skill="rea")
def procedure_pseudo_code(procedure_or_address: str) -> dict[str, Any]:
    """Generate high-level C-like pseudocode for a procedure (REA procedure_pseudo_code)."""
    return generate_pseudocode(
        session=active_session,
        target=procedure_or_address,
    )


@server.tool()
@skill_tool(skill="rea")
def find_xrefs_to_name(target_name: str, max_results: int = 50) -> dict[str, Any]:
    """Find all code cross-references (xrefs) to a function, string, or address (REA find_xrefs_to_name)."""
    return _find_xrefs_to_name(
        session=active_session,
        target_name=target_name,
        max_results=max_results,
    )


@server.tool()
@skill_tool(skill="rea")
def detect_framework(target_path: str) -> dict[str, Any]:
    """Detect application technology stack, runtime environment, and compiler framework."""
    return _detect_framework(target_path)


@server.tool()
@skill_tool(skill="rea")
def inspect_electron_asar(
    asar_path: str,
    output_dir: str | None = None,
    filter_pattern: str | None = None,
) -> dict[str, Any]:
    """Inspect or extract an Electron ASAR archive to recover JavaScript code and source maps."""
    if output_dir:
        return extract_asar_archive(
            asar_path_str=asar_path,
            output_dir_str=output_dir,
            filter_pattern=filter_pattern,
        )
    return inspect_asar(asar_path)


@server.tool()
@skill_tool(skill="rea")
def inspect_dotnet(file_path: str | None = None) -> dict[str, Any]:
    """Inspect managed PE / .NET assembly headers, CLI metadata streams, and User Strings (#US)."""
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "No binary specified and no active binary session. Run 'open_binary' first."}
    return inspect_dotnet_assembly(target)


@server.tool()
@skill_tool(skill="rea")
def rea_doctor() -> dict[str, Any]:
    """Run environment diagnostic checks for reverse engineering capabilities (REA doctor)."""
    ghidra_info = check_ghidra_status()
    return {
        "status": "operational",
        "engine": "REA-Equivalent Agentic Reverse Engineering Suite",
        "fast_path_disassembly": "Capstone Engine v5.0 (Active)",
        "supported_architectures": ["x86 (32-bit)", "x64 (AMD64)", "ARM", "ARM64"],
        "supported_formats": ["PE (Windows EXE/DLL)", "ELF (Linux)", "Mach-O (macOS)", "Electron ASAR", ".NET CLI"],
        "ghidra_headless": ghidra_info,
    }


# ============================================================================
# SKILL: DEFENSIVE SECURITY AUDIT & HYGIENE (FuzzingLabs / Gitleaks / Trivy SAST)
# ============================================================================

@server.tool()
@skill_tool(skill="security_audit")
def scan_secrets(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Scan files or directories for leaked API keys, tokens, and hardcoded secrets (Gitleaks equivalent).

    Detects AWS keys, GitHub tokens, Google API keys, Slack/Discord webhooks, private keys,
    and high-entropy hardcoded credentials with safe redaction.

    Args:
        target_path: Path to file or folder to audit for credential leakage.
        max_findings: Maximum findings to return (default: 100).
    """
    return _scan_secrets(target_path=target_path, max_findings=max_findings)


@server.tool()
@skill_tool(skill="security_audit")
def audit_dependencies(target_path: str) -> dict[str, Any]:
    """Audit project dependencies for known vulnerabilities and CVEs via OSV.dev (Trivy equivalent).

    Inspects requirements.txt, package.json, and pyproject.toml against the open-source
    vulnerability database (OSV) to identify vulnerable components and CVE advisories.

    Args:
        target_path: Path to directory or manifest file to audit.
    """
    return _audit_dependencies(target_path=target_path)


@server.tool()
@skill_tool(skill="security_audit")
def run_sast_scan(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Run static application security testing (SAST) for insecure coding patterns.

    Detects command injection, insecure deserialization (Pickle/YAML), dynamic eval/exec,
    SQL string concatenation, weak crypto, and DOM XSS sinks.

    Args:
        target_path: Path to source file or repository directory to analyze.
        max_findings: Maximum issues to return (default: 100).
    """
    return _run_sast_scan(target_path=target_path, max_findings=max_findings)


# ============================================================================
# SKILL: PASSIVE RECONNAISSANCE & SURFACE POSTURE (OSINT)
# ============================================================================

@server.tool()
@skill_tool(skill="osint_recon")
def inspect_http_headers(url: str) -> dict[str, Any]:
    """Inspect HTTP security headers and identify missing browser protections or info leaks.

    Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    and flags server banner disclosure (Server, X-Powered-By).

    Args:
        url: Target web URL or domain (e.g. 'https://example.com').
    """
    return _inspect_http_headers(target_url=url)


@server.tool()
@skill_tool(skill="osint_recon")
def inspect_tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    """Inspect SSL/TLS certificate validity, expiration, issuer, SANs, and protocol version.

    Args:
        hostname: Domain name or host to inspect (e.g. 'example.com').
        port: Port number (default: 443).
    """
    return _inspect_tls_certificate(hostname=hostname, port=port)


@server.tool()
@skill_tool(skill="osint_recon")
def lookup_dns_records(domain: str) -> dict[str, Any]:
    """Lookup DNS records and audit SPF and DMARC email spoofing defense posture.

    Args:
        domain: Target domain name (e.g. 'example.com').
    """
    return _lookup_dns_records(domain=domain)


# ============================================================================
# SKILL: THREAT INTELLIGENCE & MITRE ATT&CK DEFENSE
# ============================================================================

@server.tool()
@skill_tool(skill="threat_intel")
def map_mitre_attack(query: str) -> dict[str, Any]:
    """Map security observations, APIs, or behaviors to the MITRE ATT&CK framework.

    Returns tactics, technique IDs, descriptions, and defensive mitigations.

    Args:
        query: Technique name, ID, or behavior keyword (e.g. 'process injection', 'T1059', 'mimikatz').
    """
    return _map_mitre_attack(query=query)


@server.tool()
@skill_tool(skill="threat_intel")
def analyze_ioc_indicator(indicator: str) -> dict[str, Any]:
    """Categorize, validate, and safely defang an Indicator of Compromise (IOC).

    Validates IPv4, IPv6, MD5, SHA-256, URL, domain, or email, defanging it for safe documentation
    and suggesting threat hunting/containment steps.

    Args:
        indicator: Raw indicator string (e.g., '192.168.1.1', 'http://malicious.test', 'd41d8cd98f...').
    """
    return _analyze_ioc_indicator(indicator=indicator)


@server.tool()
@skill_tool(skill="threat_intel")
def lookup_cve_details(cve_id: str) -> dict[str, Any]:
    """Retrieve details and advisories for a specific CVE from the OSV open vulnerability database.

    Args:
        cve_id: Standard CVE identifier (e.g., 'CVE-2021-44228', 'CVE-2023-38606').
    """
    return _lookup_cve_details(cve_id=cve_id)


# ============================================================================
# SKILL: CLOUD SECURITY & CONTAINER HARDENING
# ============================================================================

@server.tool()
@skill_tool(skill="cloud_container")
def audit_dockerfile(dockerfile_path_or_content: str) -> dict[str, Any]:
    """Audit Dockerfile against CIS container benchmarks and security best practices.

    Flags root execution, unpinned base images, missing healthchecks, curl|sh pipes,
    and hardcoded secrets.

    Args:
        dockerfile_path_or_content: Path to Dockerfile or raw Dockerfile string.
    """
    return _audit_dockerfile(dockerfile_path_or_content=dockerfile_path_or_content)


@server.tool()
@skill_tool(skill="cloud_container")
def audit_iam_policy(policy_json_str: str) -> dict[str, Any]:
    """Audit Cloud / AWS IAM policy JSON for overly permissive wildcards and escalation risks.

    Args:
        policy_json_str: IAM policy JSON string or path to policy JSON file.
    """
    return _audit_iam_policy(policy_json_str=policy_json_str)


# ============================================================================
# SKILL: APPLICATION SECURITY & OWASP / LLM AUDIT (Bri Russell Skills)
# ============================================================================

@server.tool()
@skill_tool(skill="appsec")
def audit_owasp_top10(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Audit codebase against OWASP Top 10 (2021) web application security risks.

    Detects broken access control, cryptographic failures, injection, security misconfigurations,
    and server-side request forgery (SSRF).

    Args:
        target_path: Path to source code directory or file to audit.
        max_findings: Maximum issues to return (default: 100).
    """
    return _audit_owasp_top10(target_path=target_path, max_findings=max_findings)


@server.tool()
@skill_tool(skill="appsec")
def audit_api_security(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Audit API route handlers and endpoints against OWASP API Security Top 10.

    Detects BOLA/IDOR patterns, mass assignment risk, and permissive wildcard CORS.

    Args:
        target_path: Path to API source directory or router file.
        max_findings: Maximum issues to return (default: 100).
    """
    return _audit_api_security(target_path=target_path, max_findings=max_findings)


@server.tool()
@skill_tool(skill="appsec")
def audit_prompt_injection(target_path: str, max_findings: int = 50) -> dict[str, Any]:
    """Audit AI and LLM application codebase against prompt injection and output execution risks.

    Checks OWASP Top 10 for LLMs: prompt concatenation, unvalidated execution sinks, and SQL generation.

    Args:
        target_path: Path to AI application directory or source file.
        max_findings: Maximum issues to return (default: 50).
    """
    return _audit_prompt_injection(target_path=target_path, max_findings=max_findings)


# ============================================================================
# SKILL: DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR / NIST SP 800-61r2)
# ============================================================================

@server.tool()
@skill_tool(skill="incident_response")
def triage_security_incident(
    incident_description: str,
    affected_assets: list[str] | str,
    observed_iocs: list[str] | str | None = None,
    data_exfiltration_suspected: bool = False,
) -> dict[str, Any]:
    """Execute structured incident triage, severity classification, and containment planning.

    Adheres to NIST SP 800-61r2 framework, producing severity score (P1-P4), immediate containment actions,
    and evidence preservation checklists.

    Args:
        incident_description: Summary of observed anomalous activity or breach.
        affected_assets: Hostnames, IP addresses, or services impacted.
        observed_iocs: List of suspected indicators of compromise (hashes, IPs, domains).
        data_exfiltration_suspected: Flag if sensitive data exfiltration is suspected.
    """
    return _triage_security_incident(
        incident_description=incident_description,
        affected_assets=affected_assets,
        observed_iocs=observed_iocs,
        data_exfiltration_suspected=data_exfiltration_suspected,
    )


@server.tool()
@skill_tool(skill="incident_response")
def generate_incident_comms(
    incident_id: str,
    incident_summary: str,
    current_status: str = "Contained",
    audience: str = "technical",
) -> dict[str, Any]:
    """Generate professional security incident communications tailored by audience (Executive, Technical, Customer).

    Args:
        incident_id: Tracking ID for the incident (e.g., 'INC-2026-0042').
        incident_summary: Executive or technical summary of the event.
        current_status: Current incident lifecycle status (e.g. 'Investigating', 'Contained', 'Resolved').
        audience: Target audience: 'executive', 'technical', or 'customer'.
    """
    return _generate_incident_comms(
        incident_id=incident_id,
        incident_summary=incident_summary,
        current_status=current_status,
        audience=audience,
    )


def main() -> None:
    """Run MCP server over standard I/O."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
