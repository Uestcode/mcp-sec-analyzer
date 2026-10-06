"""Cross-reference (XREF) discovery engine."""

from __future__ import annotations

from typing import Any
import capstone

from .session import AnalysisSession
from .disassembler import get_capstone_engine


def find_xrefs_to_name(
    session: AnalysisSession,
    target_name: str,
    max_results: int = 50,
) -> dict[str, Any]:
    """Find all code cross-references (xrefs) to a function, string, symbol, or address."""
    if not session.is_loaded() or not session.pe:
        return {"error": "No binary loaded or binary is not in PE format. Use 'open_binary' first."}

    # Resolve target to address if possible
    target_va: int | None = None
    try:
        target_va = session.resolve_target_va(target_name)
    except Exception:
        pass

    # If target is not a known symbol or address, search binary bytes for target as string
    string_vas: list[int] = []
    if target_va is None:
        target_bytes = target_name.encode("utf-8")
        idx = session.file_bytes.find(target_bytes)
        while idx != -1:
            # Convert raw offset to VA
            for sec in session.pe.sections:
                if sec.PointerToRawData <= idx < sec.PointerToRawData + sec.SizeOfRawData:
                    s_rva = sec.VirtualAddress + (idx - sec.PointerToRawData)
                    string_vas.append(session.image_base + s_rva)
                    break
            idx = session.file_bytes.find(target_bytes, idx + 1)
            if len(string_vas) >= 10:
                break

    all_target_vas = set()
    if target_va is not None:
        all_target_vas.add(target_va)
    for sva in string_vas:
        all_target_vas.add(sva)

    if not all_target_vas:
        return {
            "target": target_name,
            "message": f"Could not find address or string matches for '{target_name}'",
            "xrefs_found": 0,
            "xrefs": [],
        }

    cs = get_capstone_engine(session.arch)
    results = []

    # Scan executable sections
    for sec in session.pe.sections:
        if bool(sec.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            sec_va = session.image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            if not sec_data:
                continue

            for insn in cs.disasm(sec_data, sec_va):
                ref_found = False

                # 1. RIP-relative memory addressing (common in x64: lea rcx, [rip + disp])
                if insn.operands:
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_MEM:
                            mem = op.mem
                            if mem.base == capstone.x86.X86_REG_RIP:
                                resolved_addr = insn.address + insn.size + mem.disp
                                if resolved_addr in all_target_vas:
                                    ref_found = True
                                    break
                        elif op.type == capstone.x86.X86_OP_IMM:
                            if op.imm in all_target_vas:
                                ref_found = True
                                break

                if ref_found:
                    # Find nearest preceding procedure
                    enclosing = session.procedures.get(insn.address, {}).get("name")
                    if not enclosing:
                        # Find closest procedure VA <= insn.address
                        candidates = [va for va in session.procedures if va <= insn.address]
                        if candidates:
                            closest_va = max(candidates)
                            enclosing = session.procedures[closest_va].get("name")

                    results.append({
                        "referrer_address": hex(insn.address),
                        "instruction": f"{insn.mnemonic} {insn.op_str}",
                        "enclosing_procedure": enclosing or "sub_" + hex(insn.address),
                        "target": target_name,
                    })

                    if len(results) >= max_results:
                        break

    return {
        "target": target_name,
        "matched_addresses": [hex(v) for v in all_target_vas],
        "xrefs_found": len(results),
        "xrefs": results,
    }
