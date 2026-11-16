"""
Lua 5.1 Opcode definitions and related constants.
"""

from enum import IntEnum
from typing import NamedTuple


class OpMode(IntEnum):
    """Instruction format modes."""
    iABC = 0   # A, B, C registers
    iABx = 1   # A register, Bx unsigned
    iAsBx = 2  # A register, sBx signed


class OpArgMask(IntEnum):
    """Operand argument types."""
    OpArgN = 0  # Not used
    OpArgU = 1  # Used
    OpArgR = 2  # Register or jump offset
    OpArgK = 3  # Constant or register/constant


class OpCode(IntEnum):
    """
    Lua 5.1 opcodes (38 total).

    Each opcode has a specific instruction format:
    - iABC: Uses A, B, C arguments
    - iABx: Uses A and unsigned 18-bit Bx
    - iAsBx: Uses A and signed 18-bit sBx
    """
    # Load/Move operations
    MOVE = 0        # R(A) := R(B)
    LOADK = 1       # R(A) := Kst(Bx)
    LOADBOOL = 2    # R(A) := (Bool)B; if (C) pc++
    LOADNIL = 3     # R(A) := ... := R(B) := nil

    # Upvalue operations
    GETUPVAL = 4    # R(A) := UpValue[B]

    # Global operations (Lua 5.1 specific)
    GETGLOBAL = 5   # R(A) := Gbl[Kst(Bx)]

    # Table operations
    GETTABLE = 6    # R(A) := R(B)[RK(C)]
    SETGLOBAL = 7   # Gbl[Kst(Bx)] := R(A)
    SETUPVAL = 8    # UpValue[B] := R(A)
    SETTABLE = 9    # R(A)[RK(B)] := RK(C)
    NEWTABLE = 10   # R(A) := {} (size = B,C)

    # Method call setup
    SELF = 11       # R(A+1) := R(B); R(A) := R(B)[RK(C)]

    # Arithmetic operations
    ADD = 12        # R(A) := RK(B) + RK(C)
    SUB = 13        # R(A) := RK(B) - RK(C)
    MUL = 14        # R(A) := RK(B) * RK(C)
    DIV = 15        # R(A) := RK(B) / RK(C)
    MOD = 16        # R(A) := RK(B) % RK(C)
    POW = 17        # R(A) := RK(B) ^ RK(C)

    # Unary operations
    UNM = 18        # R(A) := -R(B)
    NOT = 19        # R(A) := not R(B)
    LEN = 20        # R(A) := length of R(B)

    # String concatenation
    CONCAT = 21     # R(A) := R(B).. ... ..R(C)

    # Jump
    JMP = 22        # pc += sBx

    # Comparison operations
    EQ = 23         # if ((RK(B) == RK(C)) ~= A) then pc++
    LT = 24         # if ((RK(B) <  RK(C)) ~= A) then pc++
    LE = 25         # if ((RK(B) <= RK(C)) ~= A) then pc++

    # Test operations
    TEST = 26       # if not (R(A) <=> C) then pc++
    TESTSET = 27    # if (R(B) <=> C) then R(A) := R(B) else pc++

    # Function calls
    CALL = 28       # R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1))
    TAILCALL = 29   # return R(A)(R(A+1), ... ,R(A+B-1))
    RETURN = 30     # return R(A), ... ,R(A+B-2)

    # Loop operations
    FORLOOP = 31    # R(A)+=R(A+2); if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }
    FORPREP = 32    # R(A)-=R(A+2); pc+=sBx
    TFORLOOP = 33   # R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2)); if R(A+3) ~= nil then R(A+2)=R(A+3) else pc++

    # List/Table operations
    SETLIST = 34    # R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B

    # Close/Closure
    CLOSE = 35      # close all variables in the stack up to (>=) R(A)
    CLOSURE = 36    # R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))

    # Vararg
    VARARG = 37     # R(A), R(A+1), ..., R(A+B-2) = vararg


class OpcodeInfo(NamedTuple):
    """Information about an opcode."""
    name: str
    mode: OpMode
    b_mode: OpArgMask
    c_mode: OpArgMask
    test_flag: bool  # Is this a test instruction (followed by JMP)?


# Opcode information table (from lopcodes.c)
OPCODE_INFO = {
    OpCode.MOVE:     OpcodeInfo("MOVE",     OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.LOADK:    OpcodeInfo("LOADK",    OpMode.iABx,  OpArgMask.OpArgK, OpArgMask.OpArgN, False),
    OpCode.LOADBOOL: OpcodeInfo("LOADBOOL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False),
    OpCode.LOADNIL:  OpcodeInfo("LOADNIL",  OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.GETUPVAL: OpcodeInfo("GETUPVAL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False),
    OpCode.GETGLOBAL:OpcodeInfo("GETGLOBAL",OpMode.iABx,  OpArgMask.OpArgK, OpArgMask.OpArgN, False),
    OpCode.GETTABLE: OpcodeInfo("GETTABLE", OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgK, False),
    OpCode.SETGLOBAL:OpcodeInfo("SETGLOBAL",OpMode.iABx,  OpArgMask.OpArgK, OpArgMask.OpArgN, False),
    OpCode.SETUPVAL: OpcodeInfo("SETUPVAL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False),
    OpCode.SETTABLE: OpcodeInfo("SETTABLE", OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.NEWTABLE: OpcodeInfo("NEWTABLE", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False),
    OpCode.SELF:     OpcodeInfo("SELF",     OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgK, False),
    OpCode.ADD:      OpcodeInfo("ADD",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.SUB:      OpcodeInfo("SUB",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.MUL:      OpcodeInfo("MUL",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.DIV:      OpcodeInfo("DIV",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.MOD:      OpcodeInfo("MOD",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.POW:      OpcodeInfo("POW",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False),
    OpCode.UNM:      OpcodeInfo("UNM",      OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.NOT:      OpcodeInfo("NOT",      OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.LEN:      OpcodeInfo("LEN",      OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.CONCAT:   OpcodeInfo("CONCAT",   OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgR, False),
    OpCode.JMP:      OpcodeInfo("JMP",      OpMode.iAsBx, OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.EQ:       OpcodeInfo("EQ",       OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, True),
    OpCode.LT:       OpcodeInfo("LT",       OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, True),
    OpCode.LE:       OpcodeInfo("LE",       OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, True),
    OpCode.TEST:     OpcodeInfo("TEST",     OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgU, True),
    OpCode.TESTSET:  OpcodeInfo("TESTSET",  OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgU, True),
    OpCode.CALL:     OpcodeInfo("CALL",     OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False),
    OpCode.TAILCALL: OpcodeInfo("TAILCALL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False),
    OpCode.RETURN:   OpcodeInfo("RETURN",   OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False),
    OpCode.FORLOOP:  OpcodeInfo("FORLOOP",  OpMode.iAsBx, OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.FORPREP:  OpcodeInfo("FORPREP",  OpMode.iAsBx, OpArgMask.OpArgR, OpArgMask.OpArgN, False),
    OpCode.TFORLOOP: OpcodeInfo("TFORLOOP", OpMode.iABC,  OpArgMask.OpArgN, OpArgMask.OpArgU, True),
    OpCode.SETLIST:  OpcodeInfo("SETLIST",  OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False),
    OpCode.CLOSE:    OpcodeInfo("CLOSE",    OpMode.iABC,  OpArgMask.OpArgN, OpArgMask.OpArgN, False),
    OpCode.CLOSURE:  OpcodeInfo("CLOSURE",  OpMode.iABx,  OpArgMask.OpArgU, OpArgMask.OpArgN, False),
    OpCode.VARARG:   OpcodeInfo("VARARG",   OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False),
}


# Operator strings for binary operations
BINARY_OPERATORS = {
    OpCode.ADD: "+",
    OpCode.SUB: "-",
    OpCode.MUL: "*",
    OpCode.DIV: "/",
    OpCode.MOD: "%",
    OpCode.POW: "^",
    OpCode.CONCAT: "..",
}

# Operator strings for unary operations
UNARY_OPERATORS = {
    OpCode.UNM: "-",
    OpCode.NOT: "not ",
    OpCode.LEN: "#",
}

# Comparison operators
COMPARISON_OPERATORS = {
    OpCode.EQ: "==",
    OpCode.LT: "<",
    OpCode.LE: "<=",
}

# Inverted comparison operators (for when A=1)
INVERTED_COMPARISON_OPERATORS = {
    OpCode.EQ: "~=",
    OpCode.LT: ">=",
    OpCode.LE: ">",
}

# Operator priority for proper parenthesization (lower = higher priority)
# Based on Lua operator precedence
OPERATOR_PRIORITY = {
    OpCode.POW: 1,      # ^ (right associative, highest)
    OpCode.UNM: 2,      # unary -
    OpCode.NOT: 2,      # not
    OpCode.LEN: 2,      # #
    OpCode.MUL: 3,      # *
    OpCode.DIV: 3,      # /
    OpCode.MOD: 3,      # %
    OpCode.ADD: 4,      # +
    OpCode.SUB: 4,      # -
    OpCode.CONCAT: 5,   # .. (right associative)
    OpCode.EQ: 6,       # == ~=
    OpCode.LT: 6,       # < >
    OpCode.LE: 6,       # <= >=
    # and = 7, or = 8 (handled specially)
}


# Lua reserved words (for identifier validation)
LUA_KEYWORDS = frozenset([
    "and", "break", "do", "else", "elseif", "end",
    "false", "for", "function", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while"
])


# Fields per flush for SETLIST
LFIELDS_PER_FLUSH = 50


def get_opcode_name(op: OpCode) -> str:
    """Get the name of an opcode."""
    return OPCODE_INFO[op].name


def get_opcode_mode(op: OpCode) -> OpMode:
    """Get the instruction mode of an opcode."""
    return OPCODE_INFO[op].mode


def is_test_opcode(op: OpCode) -> bool:
    """Check if an opcode is a test instruction (followed by JMP)."""
    return OPCODE_INFO[op].test_flag


def is_comparison_opcode(op: OpCode) -> bool:
    """Check if an opcode is a comparison (EQ, LT, LE)."""
    return op in (OpCode.EQ, OpCode.LT, OpCode.LE)


def is_binary_opcode(op: OpCode) -> bool:
    """Check if an opcode is a binary arithmetic operation."""
    return op in BINARY_OPERATORS


def is_unary_opcode(op: OpCode) -> bool:
    """Check if an opcode is a unary operation."""
    return op in UNARY_OPERATORS
