"""Electron ASAR archive inspection and extraction module."""

from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any


def parse_asar_header(asar_path: Path) -> tuple[dict[str, Any], int]:
    """Parse Electron ASAR binary header and extract JSON filesystem tree."""
    with asar_path.open("rb") as f:
        magic_bytes = f.read(16)
        if len(magic_bytes) < 16:
            raise ValueError("File too small to be a valid ASAR archive.")

        # Header format: [4 bytes header_size, 4 bytes payload_size, 4 bytes string_size]
        u1, header_size, payload_size, string_size = struct.unpack("<IIII", magic_bytes)
        if u1 != 4:
            raise ValueError("Invalid ASAR magic identifier.")

        header_json_bytes = f.read(string_size)
        header_tree = json.loads(header_json_bytes.decode("utf-8"))

        # Base offset where raw file payload begins
        base_payload_offset = 16 + (payload_size - string_size) + string_size

    return header_tree, base_payload_offset


def flatten_asar_tree(node: dict[str, Any], current_path: str = "") -> list[dict[str, Any]]:
    """Recursively flatten ASAR directory hierarchy into a list of file entries."""
    files: list[dict[str, Any]] = []

    if "files" in node:
        for name, child in node["files"].items():
            child_path = f"{current_path}/{name}" if current_path else name
            if "files" in child:
                files.extend(flatten_asar_tree(child, child_path))
            else:
                files.append({
                    "path": child_path,
                    "size": child.get("size", 0),
                    "offset": int(child.get("offset", 0)),
                    "unpacked": child.get("unpacked", False),
                })

    return files


def inspect_asar(asar_path_str: str) -> dict[str, Any]:
    """Inspect Electron ASAR archive: enumerate files, discover source-maps, and inspect package.json."""
    path = Path(asar_path_str).resolve()
    if not path.exists() or not path.is_file():
        return {"error": f"ASAR archive not found: {asar_path_str}"}

    try:
        tree, base_offset = parse_asar_header(path)
    except Exception as e:
        return {"error": f"Failed to parse ASAR header: {e}"}

    file_entries = flatten_asar_tree(tree)

    # Search for critical investigation files
    has_source_maps = [f["path"] for f in file_entries if f["path"].endswith(".map")]
    package_json_entry = next((f for f in file_entries if f["path"] in ("package.json", "app/package.json")), None)
    config_files = [f["path"] for f in file_entries if any(sub in f["path"].lower() for sub in ("config", "secret", ".env", "auth"))]

    package_json_content = None
    if package_json_entry:
        try:
            with path.open("rb") as f:
                f.seek(base_offset + package_json_entry["offset"])
                data = f.read(package_json_entry["size"])
                package_json_content = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    return {
        "asar_file": path.name,
        "total_files": len(file_entries),
        "total_unpacked_size_bytes": sum(f["size"] for f in file_entries),
        "has_source_maps": len(has_source_maps) > 0,
        "source_maps_count": len(has_source_maps),
        "source_maps_sample": has_source_maps[:10],
        "interesting_configs": config_files[:15],
        "package_json": package_json_content,
        "files_sample": [f["path"] for f in file_entries[:30]],
    }


def extract_asar_archive(
    asar_path_str: str,
    output_dir_str: str,
    filter_pattern: str | None = None,
) -> dict[str, Any]:
    """Extract files from Electron ASAR archive to a destination directory."""
    asar_path = Path(asar_path_str).resolve()
    out_dir = Path(output_dir_str).resolve()

    if not asar_path.exists() or not asar_path.is_file():
        return {"error": f"ASAR file not found: {asar_path_str}"}

    try:
        tree, base_offset = parse_asar_header(asar_path)
    except Exception as e:
        return {"error": f"Failed to parse ASAR header: {e}"}

    file_entries = flatten_asar_tree(tree)
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted_count = 0
    extracted_paths = []

    with asar_path.open("rb") as f:
        for entry in file_entries:
            rel_path = entry["path"]
            if filter_pattern and filter_pattern.lower() not in rel_path.lower():
                continue

            target_dest = out_dir / rel_path.replace("/", "\\")
            target_dest.parent.mkdir(parents=True, exist_ok=True)

            if not entry.get("unpacked", False) and entry["size"] > 0:
                f.seek(base_offset + entry["offset"])
                file_bytes = f.read(entry["size"])
                with target_dest.open("wb") as out_f:
                    out_f.write(file_bytes)
                extracted_count += 1
                if len(extracted_paths) < 20:
                    extracted_paths.append(rel_path)

    return {
        "status": "success",
        "destination": str(out_dir),
        "files_extracted": extracted_count,
        "sample_extracted_files": extracted_paths,
    }
