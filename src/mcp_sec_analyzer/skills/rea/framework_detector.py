"""Application runtime and framework detector module."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .strings_analyzer import extract_raw_strings


def detect_framework(target_path: str) -> dict[str, Any]:
    """Detect application technology stack, runtime environment, and compiler framework.
    
    Identifies whether the target is Electron, .NET/CLR, Go, Rust, Python-packed, Java, or Native C/C++.
    """
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}

    # Handle directory (e.g. installed app directory) or file
    is_dir = path.is_dir()
    findings: list[dict[str, str]] = []
    recommended_workflow: list[str] = []

    # 1. Electron / Node.js detection
    if is_dir:
        asar_files = list(path.rglob("*.asar"))
        if asar_files:
            findings.append({
                "framework": "Electron / Chromium",
                "confidence": "High",
                "details": f"Found Electron ASAR package(s): {[f.name for f in asar_files]}",
            })
            recommended_workflow.append("Unpack ASAR archives using 'npx asar extract' to inspect JavaScript/TypeScript sources and source maps.")
    else:
        # Check if file itself is an ASAR file
        if path.suffix.lower() == ".asar":
            findings.append({
                "framework": "Electron ASAR Archive",
                "confidence": "High",
                "details": "Direct Electron resource package",
            })
            recommended_workflow.append("Extract with ASAR extractor to recover source code directly.")

    # 2. Binary inspection for executables/libraries
    target_file = path if not is_dir else None
    if is_dir:
        # Look for the primary .exe or main binary
        exes = list(path.glob("*.exe"))
        if exes:
            target_file = exes[0]

    if target_file and target_file.is_file():
        try:
            with target_file.open("rb") as f:
                header = f.read(4096)
                # Read sample for string matching (first 4MB)
                f.seek(0)
                sample = f.read(4 * 1024 * 1024)

            raw_strings = extract_raw_strings(sample, min_length=4)
            joined_strings = " ".join(raw_strings)

            # PyInstaller detection
            if b"MEI\x0c\x0b\x0a\x0b" in sample or "pyi-runtime-tmpdir" in joined_strings or "_MEIPASS2" in joined_strings:
                findings.append({
                    "framework": "Python (PyInstaller Executable)",
                    "confidence": "High",
                    "details": "Compiled Python executable bundle (PyInstaller archive)",
                })
                recommended_workflow.append("Extract bundled bytecode using pyinstxtractor, then decompile with uncompyle6 / pycdc.")

            # .NET / CLR detection
            if "mscoree.dll" in joined_strings or "_CorExeMain" in joined_strings or "_CorDllMain" in joined_strings:
                findings.append({
                    "framework": ".NET / CLR Assembly (C#/F#/VB)",
                    "confidence": "High",
                    "details": "Managed Common Intermediate Language (CIL) binary",
                })
                recommended_workflow.append("Decompile directly to high-level C# source code using ILSpy, dnSpy, or dotPeek.")

            # Go (Golang) detection
            if "runtime.buildVersion" in joined_strings or "runtime.gopanic" in joined_strings or "runtime.main" in joined_strings:
                # Try to extract Go version
                go_version = "Unknown"
                for s in raw_strings:
                    if s.startswith("go1."):
                        go_version = s
                        break
                findings.append({
                    "framework": "Go (Golang)",
                    "confidence": "High",
                    "details": f"Statically linked Go executable (Compiler: {go_version})",
                })
                recommended_workflow.append("Use Go symbol recovery tools (e.g. GoReSym / redress) to restore function names and types before decompilation.")

            # Rust detection
            if "rust_panic" in joined_strings or "core::panicking" in joined_strings or "/rustc/" in joined_strings:
                findings.append({
                    "framework": "Rust",
                    "confidence": "High",
                    "details": "Compiled Rust binary with standard library symbols",
                })
                recommended_workflow.append("Demangle Rust symbols using rustfilt or Ghidra Rust plugins.")

            # Java / Kotlin JAR
            if header.startswith(b"PK\x03\x04") and (target_file.suffix.lower() in (".jar", ".apk", ".war")):
                findings.append({
                    "framework": "Java / Kotlin (JVM)",
                    "confidence": "High",
                    "details": "JVM Bytecode Archive",
                })
                recommended_workflow.append("Decompile bytecode to Java source code using Jadx or CFR.")

        except Exception as e:
            findings.append({
                "framework": "Unknown",
                "confidence": "Low",
                "details": f"Analysis encountered error: {e}",
            })

    if not findings:
        findings.append({
            "framework": "Native C/C++ or Unrecognized",
            "confidence": "Medium",
            "details": "No managed runtime signatures found; likely standard compiled native machine code.",
        })
        recommended_workflow.append("Disassemble with Ghidra, IDA Pro, or Capstone for native control-flow analysis.")

    return {
        "target": str(path),
        "detected_frameworks": findings,
        "recommended_investigation_steps": recommended_workflow,
    }
