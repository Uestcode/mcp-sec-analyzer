"""Binary triage and structural inspection module."""

from __future__ import annotations

import datetime
import hashlib
import math
import os
from pathlib import Path
from typing import Any


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a given byte sequence (range: 0.0 - 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    frequencies: dict[int, int] = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_hashes(file_path: Path) -> dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 for a file."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
    }


def identify_magic(file_path: Path) -> dict[str, Any]:
    """Detect file format based on magic bytes."""
    with file_path.open("rb") as f:
        header = f.read(64)

    if len(header) < 4:
        return {"format": "Unknown", "description": "File too small"}

    if header.startswith(b"MZ"):
        return {"format": "PE", "description": "Windows Portable Executable (EXE/DLL/SYS)"}
    if header.startswith(b"\x7fELF"):
        return {"format": "ELF", "description": "Linux Executable and Linkable Format"}
    if header[:4] in (b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return {"format": "Mach-O", "description": "Apple Mach-O Binary or Java Bytecode"}
    if header.startswith(b"PK\x03\x04"):
        return {"format": "ZIP", "description": "ZIP Archive / JAR / APK / Office OpenXML"}
    if header.startswith(b"dex\n"):
        return {"format": "DEX", "description": "Android Dalvik Executable"}
    if header.startswith(b"\x1f\x8b"):
        return {"format": "GZIP", "description": "Gzip Compressed Archive"}
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return {"format": "7Z", "description": "7-Zip Archive"}

    return {"format": "Generic", "description": "Unknown or raw binary/text format"}


# Notable security-relevant APIs to highlight during import analysis
SECURITY_INTEREST_APIS = {
    "Process Injection / Memory": {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection", "ZwMapViewOfSection"
    },
    "Process Execution / Shell": {
        "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
        "WinExec", "system", "popen", "execve"
    },
    "Network / Communications": {
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW", "socket", "connect", "WSAStartup"
    },
    "Persistence / Registry": {
        "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
        "RegDeleteValueA", "RegDeleteValueW"
    },
    "Cryptography / Token": {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
        "BCryptEncrypt", "BCryptDecrypt", "LogonUserA", "LogonUserW", "AdjustTokenPrivileges"
    },
}


def analyze_pe(file_path: Path) -> dict[str, Any]:
    """Parse PE structure, headers, sections, imports, exports, and security mitigations."""
    import pefile

    pe = pefile.PE(str(file_path))

    # Architecture mapping
    machine_type = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, f"Unknown ({hex(pe.FILE_HEADER.Machine)})")

    # Subsystem mapping
    subsystem = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})")

    # Timestamp
    try:
        timestamp_dt = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=datetime.timezone.utc)
        timestamp_str = timestamp_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        timestamp_str = f"Raw: {pe.FILE_HEADER.TimeDateStamp}"

    # Sections Analysis
    sections = []
    suspicious_sections = []
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
        entropy = calculate_entropy(section.get_data())
        is_readable = bool(section.Characteristics & 0x40000000)
        is_writable = bool(section.Characteristics & 0x80000000)
        is_executable = bool(section.Characteristics & 0x20000000)

        anomalies = []
        if is_writable and is_executable:
            anomalies.append("Writable and Executable (W^X violation / potential packer or shellcode buffer)")
        if entropy > 7.1:
            anomalies.append("High entropy (> 7.1) indicating compression, packing, or encryption")

        sec_info = {
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
            "permissions": {
                "readable": is_readable,
                "writable": is_writable,
                "executable": is_executable,
            },
            "anomalies": anomalies,
        }
        sections.append(sec_info)
        if anomalies:
            suspicious_sections.append({"section": name, "anomalies": anomalies, "entropy": entropy})

    # Imports Analysis
    imports: dict[str, list[str]] = {}
    flagged_apis: dict[str, list[str]] = {}
    total_imports = 0

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
            funcs = []
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="ignore")
                    funcs.append(func_name)
                    # Check for security relevance
                    for category, api_list in SECURITY_INTEREST_APIS.items():
                        if func_name in api_list:
                            flagged_apis.setdefault(category, []).append(f"{dll_name}!{func_name}")
                elif imp.ordinal:
                    funcs.append(f"Ordinal#{imp.ordinal}")
            imports[dll_name] = funcs[:10]  # Sample first 10 per DLL to avoid massive output

    # Exports Analysis
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal#{exp.ordinal}"
            exports.append({
                "name": exp_name,
                "ordinal": exp.ordinal,
                "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address) if exp.address else "0x0",
            })

    # Security Mitigations (DllCharacteristics & Directories)
    dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
    mitigations = {
        "aslr": bool(dll_char & 0x0040),  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        "high_entropy_va": bool(dll_char & 0x0020),  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (64-bit ASLR)
        "dep_nx": bool(dll_char & 0x0100),  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        "cfg": bool(dll_char & 0x4000),  # IMAGE_DLLCHARACTERISTICS_GUARD_CF (Control Flow Guard)
        "seh": not bool(dll_char & 0x0400),  # IMAGE_DLLCHARACTERISTICS_NO_SEH (false if NO_SEH is set)
        "authenticode_signed": False,
    }

    # Digital signature presence
    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
            mitigations["authenticode_signed"] = True
    except Exception:
        pass

    # Check for .NET / CLR
    is_dotnet = False
    try:
        com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
        if com_dir.VirtualAddress > 0 and com_dir.Size > 0:
            is_dotnet = True
    except Exception:
        pass

    pe.close()

    return {
        "architecture": machine_type,
        "subsystem": subsystem,
        "compilation_time": timestamp_str,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "is_dotnet": is_dotnet,
        "security_mitigations": mitigations,
        "sections": sections,
        "suspicious_sections": suspicious_sections,
        "imports_summary": {
            "total_dlls": len(imports),
            "total_imported_functions": total_imports,
            "sample_imports": imports,
            "flagged_security_apis": flagged_apis,
        },
        "exports_count": len(exports),
        "exports_sample": exports[:20],
    }


def analyze_elf(file_path: Path) -> dict[str, Any]:
    """Parse ELF structure, segments, dynamic libraries, and hardening flags using pyelftools."""
    from elftools.elf.elffile import ELFFile

    with file_path.open("rb") as f:
        elf = ELFFile(f)

        header = elf.header
        arch = header.e_machine
        elf_class = elf.elfclass
        endian = "Little" if elf.little_endian else "Big"
        elf_type = header.e_type

        # Check segments for NX / GNU_STACK
        nx_enabled = False
        has_gnu_stack = False
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_GNU_STACK":
                has_gnu_stack = True
                # Flags: 1=X, 2=W, 4=R
                flags = segment.header.p_flags
                if not (flags & 1):  # No Executable bit
                    nx_enabled = True

        # Check PIE (Position Independent Executable)
        is_pie = elf_type == "ET_DYN"

        # Check RELRO (PT_GNU_RELRO)
        has_relro = False
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_GNU_RELRO":
                has_relro = True

        # Sections
        sections = []
        needed_libs = []
        for sec in elf.iter_sections():
            sec_name = sec.name
            sec_size = sec.data_size
            sec_addr = hex(sec["sh_addr"])
            sections.append({
                "name": sec_name or "[anonymous]",
                "size": sec_size,
                "address": sec_addr,
                "type": sec["sh_type"],
            })

            # Check dynamic section for DT_NEEDED
            if sec["sh_type"] == "SHT_DYNAMIC":
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed_libs.append(tag.needed)

        return {
            "architecture": f"Machine {arch} ({elf_class}-bit, {endian} Endian)",
            "type": elf_type,
            "entry_point": hex(header.e_entry),
            "security_mitigations": {
                "nx": nx_enabled,
                "has_gnu_stack": has_gnu_stack,
                "pie": is_pie,
                "relro": has_relro,
            },
            "shared_libraries": needed_libs,
            "sections_count": len(sections),
            "sections": sections[:25],
        }


def triage_file(target_path: str) -> dict[str, Any]:
    """Execute high-level file triage, hashing, entropy, and structural format analysis."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"error": f"Path not found: {target_path}"}
    if not path.is_file():
        return {"error": f"Target is not a file: {target_path}"}

    file_size = path.stat().st_size
    hashes = calculate_hashes(path)
    magic = identify_magic(path)

    # Calculate overall file entropy
    with path.open("rb") as f:
        # Read up to 2MB for whole-file entropy calculation
        sample_data = f.read(2 * 1024 * 1024)
        overall_entropy = calculate_entropy(sample_data)

    result: dict[str, Any] = {
        "file_name": path.name,
        "file_path": str(path),
        "file_size_bytes": file_size,
        "file_size_human": f"{file_size / (1024 * 1024):.2f} MB" if file_size >= 1048576 else f"{file_size / 1024:.2f} KB",
        "hashes": hashes,
        "overall_entropy": overall_entropy,
        "entropy_assessment": (
            "Very High (>7.2) - High probability of packer, compression, or encryption"
            if overall_entropy > 7.2
            else "Standard (4.5 - 7.0) - Likely typical compiled code or text data"
        ),
        "format": magic["format"],
        "description": magic["description"],
    }

    # Format specific deep-dive
    if magic["format"] == "PE":
        try:
            result["pe_analysis"] = analyze_pe(path)
        except Exception as e:
            result["pe_analysis_error"] = str(e)
    elif magic["format"] == "ELF":
        try:
            result["elf_analysis"] = analyze_elf(path)
        except Exception as e:
            result["elf_analysis_error"] = str(e)

    return result
