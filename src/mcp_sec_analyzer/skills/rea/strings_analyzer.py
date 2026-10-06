"""String extraction and heuristic classification module."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Regex patterns for intelligence extraction
PATTERNS = {
    "urls": re.compile(r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{4,}", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "windows_paths": re.compile(r"[a-zA-Z]:\\(?:[a-zA-Z0-9_.\- ]+\\)+[a-zA-Z0-9_.\- ]+", re.IGNORECASE),
    "posix_paths": re.compile(r"/(?:bin|etc|usr|var|tmp|home|opt|dev)/[a-zA-Z0-9_.\-/]+"),
    "registry_keys": re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU)\\[a-zA-Z0-9_\\]+", re.IGNORECASE),
    "guid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "crypto_pem": re.compile(r"-----BEGIN [A-Z0-9_-]+-----"),
    "suspicious_commands": re.compile(r"\b(?:powershell(?:\.exe)?|cmd\.exe|wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|vssadmin|whoami|net user)\b", re.IGNORECASE),
}


def extract_raw_strings(data: bytes, min_length: int = 5) -> list[str]:
    """Extract both ASCII and UTF-16LE printable strings from raw bytes."""
    # ASCII regex: sequences of printable characters
    ascii_re = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    ascii_matches = [m.group(0).decode("ascii", errors="ignore") for m in ascii_re.finditer(data)]

    # UTF-16LE regex: characters followed by null bytes
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}")
    utf16_matches = [m.group(0).decode("utf-16le", errors="ignore") for m in utf16_re.finditer(data)]

    # Deduplicate while preserving order
    seen: set[str] = set()
    results: list[str] = []
    for item in ascii_matches + utf16_matches:
        cleaned = item.strip()
        if len(cleaned) >= min_length and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)

    return results


def analyze_strings(
    target_path: str,
    min_length: int = 5,
    category: str = "all",
    search_filter: str | None = None,
    max_results: int = 100,
) -> dict[str, Any]:
    """Analyze strings inside a target binary or file with heuristic categorization."""
    path = Path(target_path).resolve()
    if not path.exists() or not path.is_file():
        return {"error": f"File not found: {target_path}"}

    # Read binary content (cap reading to 16MB for responsive analysis)
    max_read_size = 16 * 1024 * 1024
    with path.open("rb") as f:
        data = f.read(max_read_size)

    extracted = extract_raw_strings(data, min_length=min_length)

    # Classify strings into categories
    categorized: dict[str, list[str]] = {
        "urls": [],
        "ipv4": [],
        "windows_paths": [],
        "posix_paths": [],
        "registry_keys": [],
        "guids": [],
        "crypto_pem": [],
        "suspicious_commands": [],
        "other": [],
    }

    for s in extracted:
        matched = False
        if PATTERNS["urls"].search(s):
            categorized["urls"].append(s)
            matched = True
        if PATTERNS["ipv4"].search(s):
            categorized["ipv4"].append(s)
            matched = True
        if PATTERNS["windows_paths"].search(s):
            categorized["windows_paths"].append(s)
            matched = True
        if PATTERNS["posix_paths"].search(s):
            categorized["posix_paths"].append(s)
            matched = True
        if PATTERNS["registry_keys"].search(s):
            categorized["registry_keys"].append(s)
            matched = True
        if PATTERNS["guid"].search(s):
            categorized["guids"].append(s)
            matched = True
        if PATTERNS["crypto_pem"].search(s):
            categorized["crypto_pem"].append(s)
            matched = True
        if PATTERNS["suspicious_commands"].search(s):
            categorized["suspicious_commands"].append(s)
            matched = True

        if not matched:
            categorized["other"].append(s)

    # Prepare response according to requested category and search filter
    counts = {k: len(v) for k, v in categorized.items()}
    total_found = len(extracted)

    if category != "all" and category in categorized:
        selected_strings = categorized[category]
    elif category == "intel_only":
        # Aggregate all intelligence items except 'other'
        selected_strings = []
        for k in categorized:
            if k != "other":
                selected_strings.extend(categorized[k])
    else:
        # Default: provide prioritized intelligence first, then others
        selected_strings = (
            categorized["suspicious_commands"]
            + categorized["urls"]
            + categorized["ipv4"]
            + categorized["registry_keys"]
            + categorized["windows_paths"]
            + categorized["posix_paths"]
            + categorized["crypto_pem"]
            + categorized["guids"]
            + categorized["other"]
        )

    # Apply search filter if specified
    if search_filter:
        regex_filter = re.compile(re.escape(search_filter), re.IGNORECASE)
        selected_strings = [s for s in selected_strings if regex_filter.search(s)]

    return {
        "file": path.name,
        "total_unique_strings": total_found,
        "category_counts": counts,
        "requested_category": category,
        "filter_applied": search_filter,
        "results_returned": min(len(selected_strings), max_results),
        "strings": selected_strings[:max_results],
    }
