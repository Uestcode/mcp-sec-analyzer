"""Managed PE / .NET Assembly and CLI triage module."""

from __future__ import annotations

from pathlib import Path
import struct
from typing import Any
import pefile


def inspect_dotnet_assembly(file_path_str: str) -> dict[str, Any]:
    """Inspect managed PE / .NET assembly headers, CLI metadata streams, and User Strings (#US)."""
    path = Path(file_path_str).resolve()
    if not path.exists() or not path.is_file():
        return {"error": f"File not found: {file_path_str}"}

    try:
        pe = pefile.PE(str(path))
    except Exception as e:
        return {"error": f"Failed to parse PE file: {e}"}

    # Verify CLR header
    com_dir_entry = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
    com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_dir_entry]
    if com_dir.VirtualAddress == 0 or com_dir.Size == 0:
        pe.close()
        return {
            "file": path.name,
            "is_dotnet": False,
            "message": "File is a native PE, not a managed .NET assembly.",
        }

    # Read CLR header bytes
    clr_header_rva = com_dir.VirtualAddress
    clr_data = pe.get_data(clr_header_rva, min(com_dir.Size, 72))

    # Parse IMAGE_COR20_HEADER
    # cb(4), MajorRuntimeVersion(2), MinorRuntimeVersion(2), MetaData RVA(4), MetaData Size(4), Flags(4), EntryPointToken(4)
    cb, major_rt, minor_rt, md_rva, md_size, flags, entry_token = struct.unpack("<IIIIIII", clr_data[:28])

    flags_desc = []
    if flags & 0x1:
        flags_desc.append("ILONLY")
    if flags & 0x2:
        flags_desc.append("32BITREQUIRED")
    if flags & 0x8:
        flags_desc.append("STRONGNAMESIGNED")
    if flags & 0x10:
        flags_desc.append("NATIVE_ENTRYPOINT")

    # Read Metadata Root (BSJB header)
    streams: dict[str, dict[str, int]] = {}
    user_strings: list[str] = []
    framework_version = "Unknown"

    try:
        md_data = pe.get_data(md_rva, md_size)
        if md_data.startswith(b"BSJB"):
            # BSJB signature (4), MajorVersion (2), MinorVersion (2), Reserved (4), VersionStringLength (4)
            sig, md_maj, md_min, reserved, ver_len = struct.unpack("<IHHII", md_data[:16])
            ver_bytes = md_data[16 : 16 + ver_len].split(b"\x00")[0]
            framework_version = ver_bytes.decode("utf-8", errors="ignore")

            # Offset after version string
            pos = 16 + ver_len
            flags_val, num_streams = struct.unpack("<HH", md_data[pos : pos + 4])
            pos += 4

            # Enumerate streams (#~, #Strings, #US, #GUID, #Blob)
            for _ in range(num_streams):
                stream_offset, stream_size = struct.unpack("<II", md_data[pos : pos + 8])
                pos += 8
                name_bytes = b""
                while pos < len(md_data) and md_data[pos] != 0:
                    name_bytes += bytes([md_data[pos]])
                    pos += 1
                # 4-byte aligned stream name
                pos += 1
                while pos % 4 != 0:
                    pos += 1

                stream_name = name_bytes.decode("utf-8", errors="ignore")
                streams[stream_name] = {"offset": stream_offset, "size": stream_size}

            # Parse User Strings (#US stream) if present
            if "#US" in streams:
                us_info = streams["#US"]
                us_data = md_data[us_info["offset"] : us_info["offset"] + us_info["size"]]
                # In #US, strings are length-prefixed UTF-16LE followed by a terminal byte
                u_pos = 1  # 0 is always an empty string
                while u_pos < len(us_data):
                    length_byte = us_data[u_pos]
                    u_pos += 1
                    if length_byte == 0:
                        continue
                    if length_byte & 0x80:
                        # Multi-byte compressed integer
                        if u_pos >= len(us_data):
                            break
                        length_byte = ((length_byte & 0x3F) << 8) | us_data[u_pos]
                        u_pos += 1

                    str_len = length_byte - 1  # Last byte is terminal flag
                    if str_len > 0 and u_pos + str_len <= len(us_data):
                        raw_str = us_data[u_pos : u_pos + str_len].decode("utf-16le", errors="ignore").strip()
                        if len(raw_str) >= 3:
                            user_strings.append(raw_str)
                    u_pos += length_byte
    except Exception:
        pass

    pe.close()

    # Detect common .NET protectors / obfuscators from User Strings or sections
    obfuscator_hints = []
    joined_us = " ".join(user_strings)
    if "ConfuserEx" in joined_us:
        obfuscator_hints.append("ConfuserEx detected")
    if "SmartAssembly" in joined_us:
        obfuscator_hints.append("SmartAssembly detected")
    if "Dotfuscator" in joined_us:
        obfuscator_hints.append("Dotfuscator detected")
    if ".NET Reactor" in joined_us:
        obfuscator_hints.append(".NET Reactor detected")

    return {
        "file": path.name,
        "is_dotnet": True,
        "clr_version": f"{major_rt}.{minor_rt}",
        "metadata_framework_version": framework_version,
        "entry_point_token": hex(entry_token),
        "flags": flags_desc,
        "streams": list(streams.keys()),
        "obfuscator_indicators": obfuscator_hints or ["None detected (Standard Assembly)"],
        "user_strings_count": len(user_strings),
        "user_strings_sample": user_strings[:40],
        "recommended_tools": [
            "ILSpy (Open-source C# decompiler: ilspycmd)",
            "dnSpy (Interactive assembly editor and debugger)",
            "de4dot (Deobfuscator for protected .NET assemblies)",
        ],
    }
