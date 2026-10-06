"""Pseudocode decompiler module producing high-level C-like representation."""

from __future__ import annotations

import re
from typing import Any
import capstone

from .session import AnalysisSession
from .disassembler import get_procedure_instructions


def generate_pseudocode(session: AnalysisSession, target: str | int) -> dict[str, Any]:
    """Generate structured C-like pseudocode from raw assembly instructions."""
    if not session.is_loaded():
        return {"error": "No binary currently loaded. Use 'open_binary' first."}

    try:
        start_va = session.resolve_target_va(target)
    except Exception as e:
        return {"error": str(e)}

    proc_name = session.procedures.get(start_va, {}).get("name", f"func_{hex(start_va)}")
    instructions = get_procedure_instructions(session, start_va, max_instructions=250)

    if not instructions:
        return {"error": f"No instructions found at {hex(start_va)}"}

    lines: list[str] = []
    lines.append(f"// Decompiled pseudocode for: {proc_name} ({hex(start_va)})")
    lines.append(f"// Architecture: {session.arch} | Total instructions analyzed: {len(instructions)}")
    lines.append("")

    # Determine signature and arguments based on architecture convention
    if session.arch == "x64":
        lines.append(f"int64_t {proc_name}(int64_t a1_rcx, int64_t a2_rdx, int64_t a3_r8, int64_t a4_r9) {{")
    elif session.arch == "x86":
        lines.append(f"int32_t __stdcall {proc_name}(void) {{")
    else:
        lines.append(f"int64_t {proc_name}(...) {{")

    # Local state tracking
    last_cmp: str | None = None
    indent = "    "

    for insn in instructions:
        mnemonic = insn.mnemonic.lower()
        op_str = insn.op_str
        addr_hex = hex(insn.address)

        # Skip prologue / stack frames
        if mnemonic == "push" and op_str in ("rbp", "ebp", "rsi", "rdi", "rbx"):
            continue
        if mnemonic == "mov" and op_str in ("rbp, rsp", "ebp, esp"):
            continue
        if mnemonic == "sub" and re.match(r"(?:rsp|esp),\s*0x[0-9a-fA-F]+", op_str):
            alloc_size = op_str.split(",")[1].strip()
            lines.append(f"{indent}// [stack frame allocated: {alloc_size}]")
            continue

        # Comparisons
        if mnemonic in ("cmp", "test"):
            ops = [op.strip() for op in op_str.split(",", 1)]
            if len(ops) == 2:
                if mnemonic == "test" and ops[0] == ops[1]:
                    last_cmp = f"({ops[0]} == 0)"
                elif mnemonic == "test":
                    last_cmp = f"({ops[0]} & {ops[1]})"
                else:
                    last_cmp = f"({ops[0]} == {ops[1]})"
            continue

        # Conditional branches
        if mnemonic.startswith("j") and mnemonic not in ("jmp",):
            condition = last_cmp or "condition"
            if mnemonic in ("je", "jz"):
                cond_str = f"if ({condition})"
            elif mnemonic in ("jne", "jnz"):
                cond_str = f"if (!{condition})"
            elif mnemonic in ("jl", "jb"):
                cond_str = f"if ({condition} < 0)"
            elif mnemonic in ("jg", "ja"):
                cond_str = f"if ({condition} > 0)"
            elif mnemonic in ("jle", "jbe"):
                cond_str = f"if ({condition} <= 0)"
            elif mnemonic in ("jge", "jae"):
                cond_str = f"if ({condition} >= 0)"
            else:
                cond_str = f"if ({mnemonic})"

            lines.append(f"{indent}{cond_str} goto loc_{op_str}; /* {addr_hex} */")
            last_cmp = None
            continue

        # Unconditional Jump
        if mnemonic == "jmp":
            lines.append(f"{indent}goto loc_{op_str}; /* {addr_hex} */")
            continue

        # Calls
        if mnemonic in ("call", "bl", "blr"):
            # Resolve target symbol if possible
            target_name = op_str
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                target_name = session.procedures.get(insn.operands[0].imm, {}).get("name", op_str)

            if session.arch == "x64":
                lines.append(f"{indent}rax = {target_name}(rcx, rdx, r8, r9); /* {addr_hex} */")
            else:
                lines.append(f"{indent}eax = {target_name}(); /* {addr_hex} */")
            continue

        # Return
        if mnemonic in ("ret", "retn", "bx lr"):
            ret_reg = "rax" if session.arch == "x64" else "eax"
            lines.append(f"{indent}return {ret_reg}; /* {addr_hex} */")
            continue

        # Assignments & Arithmetic
        if mnemonic == "mov":
            ops = [op.strip() for op in op_str.split(",", 1)]
            if len(ops) == 2:
                lines.append(f"{indent}{ops[0]} = {ops[1]};")
                continue
        elif mnemonic == "lea":
            ops = [op.strip() for op in op_str.split(",", 1)]
            if len(ops) == 2:
                lines.append(f"{indent}{ops[0]} = &({ops[1]});")
                continue
        elif mnemonic == "xor":
            ops = [op.strip() for op in op_str.split(",", 1)]
            if len(ops) == 2 and ops[0] == ops[1]:
                lines.append(f"{indent}{ops[0]} = 0;")
                continue
            elif len(ops) == 2:
                lines.append(f"{indent}{ops[0]} ^= {ops[1]};")
                continue
        elif mnemonic == "add":
            ops = [op.strip() for op in op_str.split(",", 1)]
            if len(ops) == 2:
                lines.append(f"{indent}{ops[0]} += {ops[1]};")
                continue
        elif mnemonic == "sub":
            ops = [op.strip() for op in op_str.split(",", 1)]
            if len(ops) == 2:
                lines.append(f"{indent}{ops[0]} -= {ops[1]};")
                continue

        # Fallback raw line
        lines.append(f"{indent}__asm(\"{mnemonic} {op_str}\"); /* {addr_hex} */")

    lines.append("}")

    return {
        "procedure_name": proc_name,
        "address": hex(start_va),
        "total_lines": len(lines),
        "code": "\n".join(lines),
    }
