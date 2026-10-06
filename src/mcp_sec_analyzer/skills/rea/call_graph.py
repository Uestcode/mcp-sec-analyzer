"""Call graph analysis: callers and callees reconstruction."""

from __future__ import annotations

from typing import Any
import capstone

from .session import AnalysisSession
from .disassembler import get_capstone_engine, get_procedure_instructions


def extract_procedure_callees(session: AnalysisSession, target_va: int) -> list[dict[str, Any]]:
    """Extract all outgoing function calls made by a procedure."""
    instructions = get_procedure_instructions(session, target_va, max_instructions=200)
    callees: list[dict[str, Any]] = []
    seen: set[str] = set()

    for insn in instructions:
        if insn.mnemonic.lower() in ("call", "bl", "blr"):
            target_desc = insn.op_str
            resolved_name = None
            resolved_va = None

            # 1. Direct immediate call (e.g. call 0x140001000)
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                resolved_va = insn.operands[0].imm
                resolved_name = session.procedures.get(resolved_va, {}).get("name", hex(resolved_va))

            # 2. RIP-relative memory call to IAT (e.g. call qword ptr [rip + 0x2450])
            elif insn.operands and insn.operands[0].type == capstone.x86.X86_OP_MEM:
                mem = insn.operands[0].mem
                if mem.base == capstone.x86.X86_REG_RIP:
                    target_iat_va = insn.address + insn.size + mem.disp
                    resolved_va = target_iat_va
                    resolved_name = session.procedures.get(target_iat_va, {}).get("name", f"IAT_{hex(target_iat_va)}")

            call_entry = {
                "call_site": hex(insn.address),
                "operand": target_desc,
                "target_address": hex(resolved_va) if resolved_va else None,
                "target_name": resolved_name or target_desc,
            }

            key = f"{call_entry['target_address']}_{call_entry['target_name']}"
            if key not in seen:
                seen.add(key)
                callees.append(call_entry)

    return callees


def find_procedure_callers(session: AnalysisSession, target_va: int, max_callers: int = 50) -> list[dict[str, Any]]:
    """Scan code sections to discover callers that invoke the target address."""
    if not session.is_loaded() or not session.pe:
        return []

    cs = get_capstone_engine(session.arch)
    callers: list[dict[str, Any]] = []

    # Find executable sections
    for sec in session.pe.sections:
        if bool(sec.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            sec_va = session.image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            if not sec_data:
                continue

            for insn in cs.disasm(sec_data, sec_va):
                if insn.mnemonic.lower() in ("call", "bl") and insn.operands:
                    # Check direct call
                    if insn.operands[0].type == capstone.x86.X86_OP_IMM and insn.operands[0].imm == target_va:
                        # Find enclosing function
                        caller_proc = session.procedures.get(insn.address, {}).get("name")
                        callers.append({
                            "caller_address": hex(insn.address),
                            "enclosing_symbol": caller_proc or "sub_" + hex(insn.address),
                            "instruction": f"{insn.mnemonic} {insn.op_str}",
                        })
                        if len(callers) >= max_callers:
                            return callers

    return callers


def build_call_graph(
    session: AnalysisSession,
    target: str | int,
    depth: int = 1,
) -> dict[str, Any]:
    """Reconstruct callers and callees for a given procedure."""
    if not session.is_loaded():
        return {"error": "No binary currently loaded. Use 'open_binary' first."}

    try:
        start_va = session.resolve_target_va(target)
    except Exception as e:
        return {"error": str(e)}

    proc_name = session.procedures.get(start_va, {}).get("name", hex(start_va))
    callees = extract_procedure_callees(session, start_va)
    callers = find_procedure_callers(session, start_va)

    graph_nodes = {
        "id": hex(start_va),
        "name": proc_name,
        "callees": callees,
        "callers": callers,
    }

    # Recursive expansion for depth > 1
    if depth > 1:
        nested_callees = []
        for callee in callees:
            if callee.get("target_address"):
                try:
                    c_va = int(callee["target_address"], 16)
                    nested = extract_procedure_callees(session, c_va)
                    nested_callees.append({
                        "procedure": callee["target_name"],
                        "address": callee["target_address"],
                        "callees": nested,
                    })
                except Exception:
                    pass
        graph_nodes["nested_callees"] = nested_callees

    return {
        "target": str(target),
        "procedure_name": proc_name,
        "address": hex(start_va),
        "total_callees": len(callees),
        "total_callers": len(callers),
        "graph": graph_nodes,
    }
