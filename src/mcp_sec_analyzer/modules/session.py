"""Binary analysis session state and address mapping manager."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import pefile

from .triage import identify_magic


class AnalysisSession:
    """Manages an active binary analysis session with cached metadata and memory mappings."""

    def __init__(self) -> None:
        self.file_path: Path | None = None
        self.file_bytes: bytes = b""
        self.format: str = "Unknown"
        self.pe: pefile.PE | None = None
        self.image_base: int = 0
        self.arch: str = "x64"  # Default assumption, updated on load
        self.entry_point_va: int = 0
        self.procedures: dict[int, dict[str, Any]] = {}  # VA -> info
        self.name_to_va: dict[str, int] = {}

    def is_loaded(self) -> bool:
        return self.file_path is not None and len(self.file_bytes) > 0

    def load(self, target_path: str) -> dict[str, Any]:
        """Load a target binary file into memory and initialize analysis structures."""
        path = Path(target_path).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Binary file not found: {target_path}")

        self.file_path = path
        with path.open("rb") as f:
            self.file_bytes = f.read()

        magic = identify_magic(path)
        self.format = magic["format"]
        self.procedures.clear()
        self.name_to_va.clear()

        if self.format == "PE":
            self._load_pe()
        elif self.format == "ELF":
            self._load_elf()
        else:
            self.image_base = 0x10000000
            self.entry_point_va = self.image_base

        return {
            "file_name": self.file_path.name,
            "file_path": str(self.file_path),
            "format": self.format,
            "architecture": self.arch,
            "image_base": hex(self.image_base),
            "entry_point": hex(self.entry_point_va),
            "procedures_discovered": len(self.procedures),
            "file_size": len(self.file_bytes),
        }

    def _load_pe(self) -> None:
        self.pe = pefile.PE(data=self.file_bytes)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point_va = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        machine = self.pe.FILE_HEADER.Machine
        if machine == 0x8664:
            self.arch = "x64"
        elif machine == 0x14C:
            self.arch = "x86"
        elif machine in (0xAA64, 0x1C4):
            self.arch = "arm64"
        elif machine in (0x1C0, 0x1C2):
            self.arch = "arm"
        else:
            self.arch = "x64"

        # Register entry point as a procedure
        self.procedures[self.entry_point_va] = {
            "name": "entry_point",
            "address": hex(self.entry_point_va),
            "va": self.entry_point_va,
            "type": "entry",
        }
        self.name_to_va["entry_point"] = self.entry_point_va

        # Register exports
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
                va = self.image_base + exp.address
                self.procedures[va] = {
                    "name": name,
                    "address": hex(va),
                    "va": va,
                    "type": "export",
                    "ordinal": exp.ordinal,
                }
                self.name_to_va[name] = va

        # Register imported functions
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp_entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = imp_entry.dll.decode("utf-8", errors="ignore").lower()
                for imp in imp_entry.imports:
                    if imp.name:
                        imp_name = imp.name.decode("utf-8", errors="ignore")
                        full_name = f"{dll}!{imp_name}"
                        va = imp.address
                        self.procedures[va] = {
                            "name": full_name,
                            "address": hex(va),
                            "va": va,
                            "type": "import",
                        }
                        self.name_to_va[imp_name] = va
                        self.name_to_va[full_name] = va

    def _load_elf(self) -> None:
        from elftools.elf.elffile import ELFFile
        import io

        elf = ELFFile(io.BytesIO(self.file_bytes))
        self.image_base = 0x400000
        self.entry_point_va = elf.header.e_entry
        self.arch = "x64" if elf.elfclass == 64 else "x86"

        self.procedures[self.entry_point_va] = {
            "name": "entry_point",
            "address": hex(self.entry_point_va),
            "va": self.entry_point_va,
            "type": "entry",
        }
        self.name_to_va["entry_point"] = self.entry_point_va

        # Load symbols
        for section in elf.iter_sections():
            if section["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM"):
                for sym in section.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] > 0:
                        name = sym.name
                        va = sym["st_value"]
                        self.procedures[va] = {
                            "name": name,
                            "address": hex(va),
                            "va": va,
                            "size": sym["st_size"],
                            "type": "function",
                        }
                        self.name_to_va[name] = va

    def resolve_target_va(self, target: str | int) -> int:
        """Resolve a procedure name, symbol, or hex address string to its Virtual Address."""
        if isinstance(target, int):
            return target

        s = str(target).strip()
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except ValueError:
                pass

        if s in self.name_to_va:
            return self.name_to_va[s]

        # Case-insensitive search
        for name, va in self.name_to_va.items():
            if name.lower() == s.lower():
                return va

        try:
            return int(s, 16)
        except ValueError:
            raise ValueError(f"Could not resolve procedure or address: '{target}'")

    def va_to_offset(self, va: int) -> int | None:
        """Convert a Virtual Address (VA) to a raw file offset."""
        if self.pe:
            rva = va - self.image_base
            for section in self.pe.sections:
                sec_va = section.VirtualAddress
                sec_vsize = section.Misc_VirtualSize
                sec_rsize = section.SizeOfRawData
                sec_size = max(sec_vsize, sec_rsize)

                if sec_va <= rva < sec_va + sec_size:
                    offset = section.PointerToRawData + (rva - sec_va)
                    if offset < len(self.file_bytes):
                        return offset
            return None

        # Fallback for ELF / raw
        if va >= self.image_base:
            offset = va - self.image_base
            if 0 <= offset < len(self.file_bytes):
                return offset
        return None

    def read_bytes_at_va(self, va: int, length: int) -> bytes:
        """Read a slice of bytes from a virtual address."""
        offset = self.va_to_offset(va)
        if offset is None or offset >= len(self.file_bytes):
            return b""
        return self.file_bytes[offset : offset + length]


# Global session instance
active_session = AnalysisSession()
