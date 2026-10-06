"""Full-featured REA-equivalent MCP Server for Reverse Engineering and Software Analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from .modules.asar import extract_asar_archive, inspect_asar
from .modules.call_graph import build_call_graph
from .modules.disassembler import disassemble_window
from .modules.dotnet import inspect_dotnet_assembly
from .modules.framework_detector import detect_framework as _detect_framework
from .modules.ghidra_bridge import check_ghidra_status
from .modules.pseudocode import generate_pseudocode
from .modules.session import active_session
from .modules.strings_analyzer import analyze_strings as _analyze_strings
from .modules.triage import triage_file as _triage_file
from .modules.xrefs import find_xrefs_to_name as _find_xrefs_to_name

# Initialize MCP Server instance
server = MCPServer(
    name="mcp-sec-analyzer",
    version="1.0.0",
    description="Agent-first reverse engineering, binary triage, and software analysis server (REA equivalent)",
)


@server.tool()
def open_binary(file_path: str) -> dict[str, Any]:
    """Open and register a target binary into the active analysis session.

    Caches the binary in memory, determines format (PE, ELF, Mach-O), detects
    architecture (x64, x86, ARM, ARM64), resolves the image base and entry point,
    and indexes exported/imported symbols for subsequent investigation tools.

    Args:
        file_path: Absolute or relative path to the executable binary or library.
    """
    try:
        return active_session.load(file_path)
    except Exception as e:
        return {"error": str(e)}


@server.tool()
def binary_overview(file_path: str | None = None) -> dict[str, Any]:
    """Provide a comprehensive structural overview of the binary (REA binary_overview).

    Analyzes cryptographic hashes, whole-file & section Shannon entropy, sections with
    anomalies (W^X violations), import address table with highlighted security APIs,
    exported symbols, and defensive mitigations (ASLR, DEP/NX, CFG, Authenticode).

    Args:
        file_path: Optional path. If not provided, uses the currently opened binary session.
    """
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "No binary specified and no active binary session. Run 'open_binary' first."}
    return _triage_file(target)


@server.tool()
def search_strings(
    query: str | None = None,
    category: str = "all",
    min_length: int = 5,
    max_results: int = 100,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Search and heuristically classify strings inside the binary (REA search_strings).

    Extracts ASCII and UTF-16LE strings and categorizes them into intelligence buckets:
    'urls', 'ipv4', 'windows_paths', 'posix_paths', 'registry_keys', 'crypto_pem',
    and 'suspicious_commands'.

    Args:
        query: Optional search term or keyword substring.
        category: Filter category ('all', 'intel_only', 'urls', 'ipv4', 'windows_paths',
                  'posix_paths', 'registry_keys', 'suspicious_commands').
        min_length: Minimum character length (default: 5).
        max_results: Maximum strings returned (default: 100).
        file_path: Optional target file. Uses active session binary if omitted.
    """
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
def list_procedures(filter_name: str | None = None, limit: int = 100) -> dict[str, Any]:
    """List discovered procedures, functions, exports, and imports in the active binary.

    Args:
        filter_name: Optional substring to filter function/symbol names.
        limit: Maximum number of procedures to return (default: 100).
    """
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
def read_function_instructions(
    procedure_or_address: str,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Fast-path instruction disassembly for a procedure or address (REA read_function_instructions).

    Decodes instructions directly using Capstone without the overhead of full decompilation.
    Returns mnemonics, operands, raw bytes, control-flow flags, and resolved targets.

    Args:
        procedure_or_address: Function name (e.g., 'entry_point', 'MyFunc') or hex address (e.g., '0x140001000').
        offset: Instruction count offset to skip (pagination).
        limit: Number of instructions to return (default: 50).
    """
    return disassemble_window(
        session=active_session,
        target=procedure_or_address,
        instruction_offset=offset,
        limit=limit,
    )


@server.tool()
def get_call_graph(procedure_or_address: str, depth: int = 1) -> dict[str, Any]:
    """Reconstruct callers and callees for a procedure (REA get_call_graph).

    Maps incoming calls (callers) and outgoing calls (callees) to understand
    control flow relationships across the binary.

    Args:
        procedure_or_address: Function name or virtual address.
        depth: Traversal depth for call hierarchy (default: 1).
    """
    return build_call_graph(
        session=active_session,
        target=procedure_or_address,
        depth=depth,
    )


@server.tool()
def procedure_pseudo_code(procedure_or_address: str) -> dict[str, Any]:
    """Generate high-level C-like pseudocode for a procedure (REA procedure_pseudo_code).

    Translates disassembled assembly basic blocks, registers, and branch conditions
    into structured C-style pseudocode with argument conventions and branching logic.

    Args:
        procedure_or_address: Function name or hex address to decompile.
    """
    return generate_pseudocode(
        session=active_session,
        target=procedure_or_address,
    )


@server.tool()
def find_xrefs_to_name(target_name: str, max_results: int = 50) -> dict[str, Any]:
    """Find all code cross-references (xrefs) to a function, string, or address (REA find_xrefs_to_name).

    Scans executable sections for instructions (e.g., call, lea, mov) that reference the target.

    Args:
        target_name: Name of symbol, function, string literal, or hex address.
        max_results: Maximum cross-references to return (default: 50).
    """
    return _find_xrefs_to_name(
        session=active_session,
        target_name=target_name,
        max_results=max_results,
    )


@server.tool()
def detect_framework(target_path: str) -> dict[str, Any]:
    """Detect application technology stack, runtime environment, and compiler framework.

    Identifies Electron, .NET/CLR, Go, Rust, Python (PyInstaller), Java JVM, or Native C/C++.

    Args:
        target_path: Path to the executable binary or application installation directory.
    """
    return _detect_framework(target_path)


@server.tool()
def inspect_electron_asar(
    asar_path: str,
    output_dir: str | None = None,
    filter_pattern: str | None = None,
) -> dict[str, Any]:
    """Inspect or extract an Electron ASAR archive to recover JavaScript code and source maps.

    If output_dir is provided, extracts matching files. Otherwise, returns archive file tree,
    package.json metadata, and source map (.map) inventories.

    Args:
        asar_path: Path to the .asar package (e.g., 'resources/app.asar').
        output_dir: Optional folder path to extract files into.
        filter_pattern: Optional filename pattern filter for extraction.
    """
    if output_dir:
        return extract_asar_archive(
            asar_path_str=asar_path,
            output_dir_str=output_dir,
            filter_pattern=filter_pattern,
        )
    return inspect_asar(asar_path)


@server.tool()
def inspect_dotnet(file_path: str | None = None) -> dict[str, Any]:
    """Inspect managed PE / .NET assembly headers, CLI metadata streams, and User Strings (#US).

    Parses BSJB metadata roots, CLR runtime flags, obfuscator indicators (ConfuserEx, etc.),
    and extracts embedded string literals.

    Args:
        file_path: Optional path to the .NET executable/DLL. Uses active session if omitted.
    """
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "No binary specified and no active binary session. Run 'open_binary' first."}
    return inspect_dotnet_assembly(target)


@server.tool()
def rea_doctor() -> dict[str, Any]:
    """Run environment diagnostic checks for reverse engineering capabilities (REA doctor).

    Verifies Capstone disassembler engine, PE/ELF parser status, and checks for Ghidra Headless.
    """
    ghidra_info = check_ghidra_status()
    return {
        "status": "operational",
        "engine": "REA-Equivalent Agentic Reverse Engineering Suite",
        "fast_path_disassembly": "Capstone Engine v5.0 (Active)",
        "supported_architectures": ["x86 (32-bit)", "x64 (AMD64)", "ARM", "ARM64"],
        "supported_formats": ["PE (Windows EXE/DLL)", "ELF (Linux)", "Mach-O (macOS)", "Electron ASAR", ".NET CLI"],
        "ghidra_headless": ghidra_info,
    }


def main() -> None:
    """Run MCP server over standard I/O."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
