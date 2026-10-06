"""Fast-path disassembly and instruction decoding module using Capstone."""

from __future__ import annotations

from typing import Any
import capstone

from .session import AnalysisSession, active_session


def get_capstone_engine(arch: str) -> capstone.Cs:
    """Initialize a Capstone engine configured for the target architecture."""
    if arch == "x64":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif arch == "x86":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif arch == "arm64":
        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif arch == "arm":
        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    cs.detail = True
    return cs


def disassemble_window(
    session: AnalysisSession,
    target: str | int,
    instruction_offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Execute fast-path instruction reading from a function or virtual address."""
    if not session.is_loaded():
        return {"error": "No binary currently loaded. Use 'open_binary' first."}

    try:
        start_va = session.resolve_target_va(target)
    except Exception as e:
        return {"error": str(e)}

    # Read an initial buffer of code bytes from the file (up to 4096 bytes)
    buffer_size = max(1024, limit * 15)
    code_bytes = session.read_bytes_at_va(start_va, buffer_size)
    if not code_bytes:
        return {"error": f"Unable to read executable bytes at address {hex(start_va)}"}

    cs = get_capstone_engine(session.arch)
    instructions = []
    skipped = 0

    for insn in cs.disasm(code_bytes, start_va):
        if skipped < instruction_offset:
            skipped += 1
            continue

        if len(instructions) >= limit:
            break

        # Identify control-flow metadata
        mnemonic = insn.mnemonic.lower()
        is_call = mnemonic in ("call", "bl", "blr")
        is_return = mnemonic in ("ret", "retn", "bx lr")
        is_jump = mnemonic.startswith("j") or mnemonic in ("b", "bx")

        # Try to resolve call / jump destination symbol
        target_info = None
        if (is_call or is_jump) and insn.operands:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM if session.arch in ("x86", "x64") else False:
                    imm_va = op.imm
                    symbol = session.procedures.get(imm_va, {}).get("name")
                    target_info = {"address": hex(imm_va), "symbol": symbol}
                    break

        instructions.append({
            "address": hex(insn.address),
            "offset_from_start": insn.address - start_va,
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
            "bytes": insn.bytes.hex(" "),
            "is_call": is_call,
            "is_jump": is_jump,
            "is_return": is_return,
            "target": target_info,
        })

    target_name = session.procedures.get(start_va, {}).get("name", hex(start_va))

    return {
        "target": str(target),
        "resolved_procedure": target_name,
        "start_address": hex(start_va),
        "architecture": session.arch,
        "instruction_offset": instruction_offset,
        "instructions_returned": len(instructions),
        "instructions": instructions,
    }


def get_procedure_instructions(
    session: AnalysisSession,
    target: str | int,
    max_instructions: int = 150,
) -> list[capstone.CsInsn]:
    """Retrieve raw decoded instruction objects for an entire procedure until return/terminator."""
    start_va = session.resolve_target_va(target)
    code_bytes = session.read_bytes_at_va(start_va, max_instructions * 15)
    if not code_bytes:
        return []

    cs = get_capstone_engine(session.arch)
    insns: list[capstone.CsInsn] = []

    for insn in cs.disasm(code_bytes, start_va):
        insns.append(insn)
        if len(insns) >= max_instructions:
            break
        # Stop at unconditional return or terminator if past start
        if insn.mnemonic in ("ret", "retn", "ud2") and len(insns) > 1:
            break

    return insns
