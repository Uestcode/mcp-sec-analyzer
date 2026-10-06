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

# Initialize MCP Server instance
server = MCPServer(
    name="mcp-sec-analyzer",
    version="1.2.0",
    description="Multi-Skill Security, Reverse Engineering, and Auditing Platform with Universal Persistent Memory",
)

# ============================================================================
# META-SKILL: SKILL CATALOG
# ============================================================================

@server.tool()
def list_skills() -> dict[str, Any]:
    """List available skills, active capabilities, and architecture modules in this MCP server."""
    return {
        "platform": "Multi-Skill Security & Reverse Engineering MCP Hub",
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
                "name": "Defensive Security Audit & Hygiene (FuzzingLabs / Gitleaks / Trivy SAST)",
                "status": "active",
                "description": "Secret leakage detection, supply chain / CVE dependency audit via OSV.dev, and SAST code rules.",
                "tools": ["scan_secrets", "audit_dependencies", "run_sast_scan"],
            },
        ],
        "extensibility": "New skills can be dropped into the skills directory and registered seamlessly.",
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


def main() -> None:
    """Run MCP server over standard I/O."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
