"""
Lua 5.1 bytecode disassembler.

Converts bytecode to human-readable instruction listings.
"""

from typing import Optional, TextIO
from io import StringIO

from .bytecode.proto import Proto, format_constant
from .bytecode.instruction import Instruction, is_k, index_k
from .bytecode.opcodes import (
    OpCode, OpMode, OPCODE_INFO, BINARY_OPERATORS, UNARY_OPERATORS,
    COMPARISON_OPERATORS, INVERTED_COMPARISON_OPERATORS, LFIELDS_PER_FLUSH,
    get_opcode_name
)


def disassemble(proto: Proto, name: str = "0", process_sub: bool = True,
                output: Optional[TextIO] = None) -> str:
    """
    Disassemble a Proto to human-readable instruction listing.

    Args:
        proto: Function prototype to disassemble
        name: Function name/number for display
        process_sub: Whether to also disassemble nested functions
        output: Optional output stream (default: StringIO)

    Returns:
        Disassembled instruction listing
    """
    if output is None:
        output = StringIO()
        return_string = True
    else:
        return_string = False

    _disassemble_function(proto, name, process_sub, output)

    if return_string:
        return output.getvalue()
    return ""


def _disassemble_function(proto: Proto, name: str, process_sub: bool,
                          output: TextIO) -> None:
    """Disassemble a single function."""
    # Print function header
    output.write(f"; Function:        {name}\n")
    output.write(f"; Defined at line: {proto.linedefined}\n")
    output.write(f"; #Upvalues:       {proto.nups}\n")
    output.write(f"; #Parameters:     {proto.numparams}\n")
    output.write(f"; Is_vararg:       {proto.is_vararg}\n")
    output.write(f"; Max Stack Size:  {proto.maxstacksize}\n")
    output.write("\n")

    # Disassemble instructions
    skip_next = 0
    for pc in range(proto.sizecode):
        if skip_next > 0:
            skip_next -= 1
            raw = proto.code[pc]
            output.write(f"{pc:5d} [-]: {raw}\n")
            continue

        inst = Instruction.decode(proto.code[pc])
        line, comment, skip = _disassemble_instruction(proto, pc, inst)
        skip_next = skip

        op_name = get_opcode_name(inst.op)
        output.write(f"{pc:5d} [-]: {op_name:9s} {line:13s}; {comment}\n")

    output.write("\n\n")

    # Process nested functions
    if process_sub and proto.sizep > 0:
        for i, child in enumerate(proto.p):
            child_name = f"{name}_{i}" if name else str(i)
            _disassemble_function(child, child_name, process_sub, output)


def _disassemble_instruction(proto: Proto, pc: int,
                             inst: Instruction) -> tuple:
    """
    Disassemble a single instruction.

    Returns (args_string, comment_string, skip_count).
    """
    a, b, c = inst.a, inst.b, inst.c
    bx, sbx = inst.bx, inst.sbx
    op = inst.op

    line = ""
    comment = ""
    skip = 0

    if op == OpCode.MOVE:
        line = f"R{a} R{b}"
        comment = f"R{a} := R{b}"

    elif op == OpCode.LOADK:
        line = f"R{a} K{bx}"
        const = _get_constant_str(proto, bx)
        comment = f"R{a} := {const}"

    elif op == OpCode.LOADBOOL:
        line = f"R{a} {b} {c}"
        bool_val = "true" if b else "false"
        if c:
            comment = f"R{a} := {bool_val}; goto {pc + 2}"
        else:
            comment = f"R{a} := {bool_val}"

    elif op == OpCode.LOADNIL:
        line = f"R{a} R{b}"
        if b > a:
            comment = f"R{a} to R{b} := nil"
        else:
            comment = f"R{a} := nil"

    elif op == OpCode.GETUPVAL:
        line = f"R{a} U{b}"
        comment = f"R{a} := U{b}"

    elif op == OpCode.GETGLOBAL:
        line = f"R{a} K{bx}"
        const = _get_constant_str(proto, bx)
        comment = f"R{a} := {const}"

    elif op == OpCode.GETTABLE:
        cc, cv = _rk_char(c), _rk_val(c)
        line = f"R{a} R{b} {cc}{cv}"
        key = _get_rk_str(proto, c)
        comment = f"R{a} := R{b}[{key}]"

    elif op == OpCode.SETGLOBAL:
        line = f"R{a} K{bx}"
        const = _get_constant_str(proto, bx)
        comment = f"{const} := R{a}"

    elif op == OpCode.SETUPVAL:
        line = f"R{a} U{b}"
        comment = f"U{b} := R{a}"

    elif op == OpCode.SETTABLE:
        cb, cvb = _rk_char(b), _rk_val(b)
        cc, cvc = _rk_char(c), _rk_val(c)
        line = f"R{a} {cb}{cvb} {cc}{cvc}"
        key = _get_rk_str(proto, b)
        val = _get_rk_str(proto, c)
        comment = f"R{a}[{key}] := {val}"

    elif op == OpCode.NEWTABLE:
        line = f"R{a} {b} {c}"
        comment = f"R{a} := {{}} (size = {b},{c})"

    elif op == OpCode.SELF:
        cc, cv = _rk_char(c), _rk_val(c)
        line = f"R{a} R{b} {cc}{cv}"
        key = _get_rk_str(proto, c)
        comment = f"R{a + 1} := R{b}; R{a} := R{b}[{key}]"

    elif op in BINARY_OPERATORS:
        cb, cvb = _rk_char(b), _rk_val(b)
        cc, cvc = _rk_char(c), _rk_val(c)
        line = f"R{a} {cb}{cvb} {cc}{cvc}"
        left = _get_rk_str(proto, b)
        right = _get_rk_str(proto, c)
        op_str = BINARY_OPERATORS[op]
        comment = f"R{a} := {left} {op_str} {right}"

    elif op in UNARY_OPERATORS:
        line = f"R{a} R{b}"
        op_str = UNARY_OPERATORS[op]
        comment = f"R{a} := {op_str}R{b}"

    elif op == OpCode.CONCAT:
        line = f"R{a} R{b} R{c}"
        comment = f"R{a} := concat(R{b} to R{c})"

    elif op == OpCode.JMP:
        dest = pc + sbx + 1
        line = f"{sbx}"
        comment = f"PC += {sbx} (goto {dest})"

    elif op in (OpCode.EQ, OpCode.LT, OpCode.LE):
        cb, cvb = _rk_char(b), _rk_val(b)
        cc, cvc = _rk_char(c), _rk_val(c)
        line = f"{a} {cb}{cvb} {cc}{cvc}"
        left = _get_rk_str(proto, b)
        right = _get_rk_str(proto, c)
        if a:
            op_str = INVERTED_COMPARISON_OPERATORS[op]
        else:
            op_str = COMPARISON_OPERATORS[op]
        # Get jump destination from next instruction
        if pc + 1 < proto.sizecode:
            next_inst = Instruction.decode(proto.code[pc + 1])
            if next_inst.op == OpCode.JMP:
                dest = next_inst.sbx + pc + 2
                comment = f"if {left} {op_str} {right} then goto {pc + 2} else goto {dest}"
            else:
                comment = f"if {left} {op_str} {right} then pc++"
        else:
            comment = f"if {left} {op_str} {right} then pc++"

    elif op == OpCode.TEST:
        line = f"R{a} {c}"
        if pc + 1 < proto.sizecode:
            next_inst = Instruction.decode(proto.code[pc + 1])
            if next_inst.op == OpCode.JMP:
                dest = next_inst.sbx + pc + 2
                not_str = "not " if c else ""
                comment = f"if {not_str}R{a} then goto {pc + 2} else goto {dest}"
            else:
                not_str = "not " if c else ""
                comment = f"if {not_str}R{a} then pc++"
        else:
            not_str = "not " if c else ""
            comment = f"if {not_str}R{a} then pc++"

    elif op == OpCode.TESTSET:
        line = f"R{a} R{b} {c}"
        if pc + 1 < proto.sizecode:
            next_inst = Instruction.decode(proto.code[pc + 1])
            if next_inst.op == OpCode.JMP:
                dest = next_inst.sbx + pc + 2
                not_str = "" if c else "not "
                comment = f"if {not_str}R{b} then R{a} := R{b}; goto {dest} else goto {pc + 2}"
            else:
                not_str = "" if c else "not "
                comment = f"if {not_str}R{b} then R{a} := R{b} else pc++"
        else:
            not_str = "" if c else "not "
            comment = f"if {not_str}R{b} then R{a} := R{b} else pc++"

    elif op in (OpCode.CALL, OpCode.TAILCALL):
        line = f"R{a} {b} {c}"
        # Format arguments
        if b > 2:
            args = f"R{a + 1} to R{a + b - 1}"
        elif b == 2:
            args = f"R{a + 1}"
        elif b == 1:
            args = ""
        else:
            args = f"R{a + 1} to top"

        # Format returns
        if c > 2:
            rets = f"R{a} to R{a + c - 2}"
        elif c == 2:
            rets = f"R{a}"
        elif c == 1:
            rets = ""
        else:
            rets = f"R{a} to top"

        comment = f"{rets} := R{a}({args})"

    elif op == OpCode.RETURN:
        line = f"R{a} {b}"
        if b > 2:
            comment = f"return R{a} to R{a + b - 2}"
        elif b == 2:
            comment = f"return R{a}"
        elif b == 1:
            comment = "return"
        else:
            comment = f"return R{a} to top"

    elif op == OpCode.FORLOOP:
        dest = pc + sbx + 1
        line = f"R{a} {sbx}"
        comment = f"R{a} += R{a + 2}; if R{a} <= R{a + 1} then R{a + 3} := R{a}; PC += {sbx}, goto {dest} end"

    elif op == OpCode.FORPREP:
        line = f"R{a} {sbx}"
        comment = f"R{a} -= R{a + 2}; pc += {sbx} (goto {pc + sbx + 1})"

    elif op == OpCode.TFORLOOP:
        line = f"R{a} {c}"
        if c == 1:
            rets = f"R{a + 3}"
        elif c > 1:
            rets = f"R{a + 3} to R{a + c + 2}"
        else:
            rets = "ERROR c=0"
        comment = f"{rets} := R{a}(R{a + 1},R{a + 2}); if R{a + 3} ~= nil then R{a + 2} := R{a + 3} else goto {pc + 2}"

    elif op == OpCode.SETLIST:
        line = f"R{a} {b} {c}"
        realc = c
        if c == 0:
            # Next instruction contains the real C value
            if pc + 1 < proto.sizecode:
                realc = proto.code[pc + 1]
                skip = 1
        start_idx = (realc - 1) * LFIELDS_PER_FLUSH if realc else 0
        if b == 0:
            comment = f"R{a}[{start_idx}] to R{a}[top] := R{a + 1} to top"
        elif b == 1:
            comment = f"R{a}[{start_idx}] := R{a + 1}"
        else:
            comment = f"R{a}[{start_idx}] to R{a}[{start_idx + b - 1}] := R{a + 1} to R{a + b}"

    elif op == OpCode.CLOSE:
        line = f"R{a}"
        comment = f"close all upvalues in R{a} to top"

    elif op == OpCode.CLOSURE:
        line = f"R{a} {bx}"
        if name:
            comment = f"R{a} := closure(Function #{name}_{bx})"
        else:
            comment = f"R{a} := closure(Function #{bx})"

    elif op == OpCode.VARARG:
        line = f"R{a} {b}"
        if b > 2:
            comment = f"R{a} to R{a + b - 2} := ..."
        elif b == 2:
            comment = f"R{a} := ..."
        elif b == 0:
            comment = f"R{a} to top := ..."
        else:
            comment = ""

    else:
        line = f"{a} {b} {c}"
        comment = "unknown opcode"

    return line, comment, skip


def _rk_char(rk: int) -> str:
    """Get character for RK value ('K' for constant, 'R' for register)."""
    return 'K' if is_k(rk) else 'R'


def _rk_val(rk: int) -> int:
    """Get value from RK (constant index or register number)."""
    return index_k(rk) if is_k(rk) else rk


def _get_rk_str(proto: Proto, rk: int) -> str:
    """Get string representation of RK value."""
    if is_k(rk):
        return _get_constant_str(proto, index_k(rk))
    return f"R{rk}"


def _get_constant_str(proto: Proto, idx: int) -> str:
    """Get string representation of constant at index."""
    if 0 <= idx < len(proto.k):
        return format_constant(proto.k[idx])
    return f"K{idx}"


def print_function_tree(proto: Proto, name: str = "0", indent: int = 0,
                       output: Optional[TextIO] = None) -> str:
    """
    Print the function tree (function numbers and locations).

    Args:
        proto: Root function prototype
        name: Function name/number
        indent: Indentation level
        output: Optional output stream

    Returns:
        Function tree listing
    """
    if output is None:
        output = StringIO()
        return_string = True
    else:
        return_string = False

    prefix = "  " * indent
    output.write(f"{prefix}{name}: line {proto.linedefined}-{proto.lastlinedefined}, "
                f"{proto.sizecode} instructions, {proto.sizek} constants, "
                f"{proto.sizep} functions\n")

    for i, child in enumerate(proto.p):
        child_name = f"{name}_{i}" if name else str(i)
        print_function_tree(child, child_name, indent + 1, output)

    if return_string:
        return output.getvalue()
    return ""
