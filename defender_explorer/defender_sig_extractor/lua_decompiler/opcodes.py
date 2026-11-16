"""
Lua 5.1 Opcode Definitions

All 38 Lua 5.1 VM instructions with their encoding formats and semantics.
"""

from enum import IntEnum
from dataclasses import dataclass
from typing import NamedTuple


class OpMode(IntEnum):
    """Instruction argument modes."""
    iABC = 0   # A, B, C arguments (8, 9, 9 bits)
    iABx = 1   # A, Bx arguments (8, 18 bits)
    iAsBx = 2  # A, sBx arguments (8, signed 18 bits)


class OpArgMask(IntEnum):
    """Argument type masks."""
    OpArgN = 0  # Not used
    OpArgU = 1  # Used
    OpArgR = 2  # Register or jump offset
    OpArgK = 3  # Constant or register/constant


class Opcode(IntEnum):
    """
    Lua 5.1 opcodes (38 total).

    Instruction format (32 bits):
    - Bits 0-5: Opcode (6 bits)
    - Bits 6-13: A register (8 bits)
    - For iABC mode:
      - Bits 14-22: B register (9 bits)
      - Bits 23-31: C register (9 bits)
    - For iABx mode:
      - Bits 14-31: Bx unsigned (18 bits)
    - For iAsBx mode:
      - Bits 14-31: sBx signed (18 bits, bias = 131071)
    """

    # Load/Store operations
    MOVE = 0       # R(A) := R(B)
    LOADK = 1      # R(A) := Kst(Bx)
    LOADBOOL = 2   # R(A) := (Bool)B; if (C) pc++
    LOADNIL = 3    # R(A) := ... := R(B) := nil

    # Upvalue operations
    GETUPVAL = 4   # R(A) := UpValue[B]
    GETGLOBAL = 5  # R(A) := Gbl[Kst(Bx)]
    GETTABLE = 6   # R(A) := R(B)[RK(C)]

    SETGLOBAL = 7  # Gbl[Kst(Bx)] := R(A)
    SETUPVAL = 8   # UpValue[B] := R(A)
    SETTABLE = 9   # R(A)[RK(B)] := RK(C)

    # Table operations
    NEWTABLE = 10  # R(A) := {} (size = B,C)
    SELF = 11      # R(A+1) := R(B); R(A) := R(B)[RK(C)]

    # Arithmetic operations
    ADD = 12       # R(A) := RK(B) + RK(C)
    SUB = 13       # R(A) := RK(B) - RK(C)
    MUL = 14       # R(A) := RK(B) * RK(C)
    DIV = 15       # R(A) := RK(B) / RK(C)
    MOD = 16       # R(A) := RK(B) % RK(C)
    POW = 17       # R(A) := RK(B) ^ RK(C)
    UNM = 18       # R(A) := -R(B)
    NOT = 19       # R(A) := not R(B)
    LEN = 20       # R(A) := length of R(B)

    # String operations
    CONCAT = 21    # R(A) := R(B).. ... ..R(C)

    # Jump operations
    JMP = 22       # pc += sBx

    # Comparison operations
    EQ = 23        # if ((RK(B) == RK(C)) ~= A) then pc++
    LT = 24        # if ((RK(B) <  RK(C)) ~= A) then pc++
    LE = 25        # if ((RK(B) <= RK(C)) ~= A) then pc++

    # Test operations
    TEST = 26      # if not (R(A) <=> C) then pc++
    TESTSET = 27   # if (R(B) <=> C) then R(A) := R(B) else pc++

    # Call operations
    CALL = 28      # R(A), ..., R(A+C-2) := R(A)(R(A+1), ..., R(A+B-1))
    TAILCALL = 29  # return R(A)(R(A+1), ..., R(A+B-1))
    RETURN = 30    # return R(A), ..., R(A+B-2)

    # Loop operations
    FORLOOP = 31   # R(A) += R(A+2); if R(A) <?= R(A+1) then { pc += sBx; R(A+3) = R(A) }
    FORPREP = 32   # R(A) -= R(A+2); pc += sBx

    TFORLOOP = 33  # R(A+3), ..., R(A+2+C) := R(A)(R(A+1), R(A+2)); if R(A+3) ~= nil then R(A+2) = R(A+3) else pc++

    SETLIST = 34   # R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B

    # Closure operations
    CLOSE = 35     # close all upvalues >= R(A)
    CLOSURE = 36   # R(A) := closure(KPROTO[Bx], R(A), ..., R(A+n))

    # Vararg operation
    VARARG = 37    # R(A), R(A+1), ..., R(A+B-1) = vararg


# Opcode metadata
@dataclass
class OpcodeInfo:
    """Information about an opcode."""
    name: str
    mode: OpMode
    arg_b: OpArgMask
    arg_c: OpArgMask
    is_test: bool  # True if instruction is a test (next must be JMP)
    sets_a: bool   # True if instruction sets register A


# Opcode information table
OPCODE_INFO = {
    Opcode.MOVE:     OpcodeInfo("MOVE",     OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.LOADK:    OpcodeInfo("LOADK",    OpMode.iABx,  OpArgMask.OpArgK, OpArgMask.OpArgN, False, True),
    Opcode.LOADBOOL: OpcodeInfo("LOADBOOL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False, True),
    Opcode.LOADNIL:  OpcodeInfo("LOADNIL",  OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.GETUPVAL: OpcodeInfo("GETUPVAL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False, True),
    Opcode.GETGLOBAL:OpcodeInfo("GETGLOBAL",OpMode.iABx,  OpArgMask.OpArgK, OpArgMask.OpArgN, False, True),
    Opcode.GETTABLE: OpcodeInfo("GETTABLE", OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgK, False, True),
    Opcode.SETGLOBAL:OpcodeInfo("SETGLOBAL",OpMode.iABx,  OpArgMask.OpArgK, OpArgMask.OpArgN, False, False),
    Opcode.SETUPVAL: OpcodeInfo("SETUPVAL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False, False),
    Opcode.SETTABLE: OpcodeInfo("SETTABLE", OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, False),
    Opcode.NEWTABLE: OpcodeInfo("NEWTABLE", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False, True),
    Opcode.SELF:     OpcodeInfo("SELF",     OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgK, False, True),
    Opcode.ADD:      OpcodeInfo("ADD",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, True),
    Opcode.SUB:      OpcodeInfo("SUB",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, True),
    Opcode.MUL:      OpcodeInfo("MUL",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, True),
    Opcode.DIV:      OpcodeInfo("DIV",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, True),
    Opcode.MOD:      OpcodeInfo("MOD",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, True),
    Opcode.POW:      OpcodeInfo("POW",      OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, False, True),
    Opcode.UNM:      OpcodeInfo("UNM",      OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.NOT:      OpcodeInfo("NOT",      OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.LEN:      OpcodeInfo("LEN",      OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.CONCAT:   OpcodeInfo("CONCAT",   OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgR, False, True),
    Opcode.JMP:      OpcodeInfo("JMP",      OpMode.iAsBx, OpArgMask.OpArgR, OpArgMask.OpArgN, False, False),
    Opcode.EQ:       OpcodeInfo("EQ",       OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, True,  False),
    Opcode.LT:       OpcodeInfo("LT",       OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, True,  False),
    Opcode.LE:       OpcodeInfo("LE",       OpMode.iABC,  OpArgMask.OpArgK, OpArgMask.OpArgK, True,  False),
    Opcode.TEST:     OpcodeInfo("TEST",     OpMode.iABC,  OpArgMask.OpArgN, OpArgMask.OpArgU, True,  False),
    Opcode.TESTSET:  OpcodeInfo("TESTSET",  OpMode.iABC,  OpArgMask.OpArgR, OpArgMask.OpArgU, True,  True),
    Opcode.CALL:     OpcodeInfo("CALL",     OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False, True),
    Opcode.TAILCALL: OpcodeInfo("TAILCALL", OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False, True),
    Opcode.RETURN:   OpcodeInfo("RETURN",   OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False, False),
    Opcode.FORLOOP:  OpcodeInfo("FORLOOP",  OpMode.iAsBx, OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.FORPREP:  OpcodeInfo("FORPREP",  OpMode.iAsBx, OpArgMask.OpArgR, OpArgMask.OpArgN, False, True),
    Opcode.TFORLOOP: OpcodeInfo("TFORLOOP", OpMode.iABC,  OpArgMask.OpArgN, OpArgMask.OpArgU, True,  False),
    Opcode.SETLIST:  OpcodeInfo("SETLIST",  OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgU, False, False),
    Opcode.CLOSE:    OpcodeInfo("CLOSE",    OpMode.iABC,  OpArgMask.OpArgN, OpArgMask.OpArgN, False, False),
    Opcode.CLOSURE:  OpcodeInfo("CLOSURE",  OpMode.iABx,  OpArgMask.OpArgU, OpArgMask.OpArgN, False, True),
    Opcode.VARARG:   OpcodeInfo("VARARG",   OpMode.iABC,  OpArgMask.OpArgU, OpArgMask.OpArgN, False, True),
}


class Instruction(NamedTuple):
    """Decoded Lua instruction."""
    opcode: Opcode
    a: int      # A field (8 bits)
    b: int      # B field (9 bits) or Bx/sBx (18 bits)
    c: int      # C field (9 bits)
    raw: int    # Original 32-bit instruction

    @property
    def bx(self) -> int:
        """Get Bx (unsigned 18-bit) value."""
        return (self.raw >> 14) & 0x3FFFF

    @property
    def sbx(self) -> int:
        """Get sBx (signed 18-bit) value."""
        return self.bx - 131071  # MAXARG_sBx = (MAXARG_Bx >> 1) = 131071

    @property
    def info(self) -> OpcodeInfo:
        """Get opcode metadata."""
        return OPCODE_INFO.get(self.opcode)

    def __str__(self) -> str:
        info = self.info
        if info is None:
            return f"UNKNOWN({self.opcode}) A={self.a} B={self.b} C={self.c}"

        if info.mode == OpMode.iABC:
            return f"{info.name} {self.a} {self.b} {self.c}"
        elif info.mode == OpMode.iABx:
            return f"{info.name} {self.a} {self.bx}"
        else:  # iAsBx
            return f"{info.name} {self.a} {self.sbx}"


def decode_instruction(raw: int) -> Instruction:
    """Decode a 32-bit Lua instruction."""
    opcode = Opcode(raw & 0x3F)
    a = (raw >> 6) & 0xFF
    c = (raw >> 14) & 0x1FF
    b = (raw >> 23) & 0x1FF

    return Instruction(opcode=opcode, a=a, b=b, c=c, raw=raw)


def is_rk_constant(rk: int) -> bool:
    """Check if RK value refers to constant (high bit set)."""
    return rk >= 256


def rk_to_constant_index(rk: int) -> int:
    """Convert RK value to constant index."""
    return rk - 256


def constant_to_rk(k: int) -> int:
    """Convert constant index to RK value."""
    return k + 256


# Operator strings for code generation
BINOP_STRINGS = {
    Opcode.ADD: "+",
    Opcode.SUB: "-",
    Opcode.MUL: "*",
    Opcode.DIV: "/",
    Opcode.MOD: "%",
    Opcode.POW: "^",
    Opcode.CONCAT: "..",
}

COMPARE_STRINGS = {
    Opcode.EQ: "==",
    Opcode.LT: "<",
    Opcode.LE: "<=",
}

# Fields Per Flush for SETLIST
LFIELDS_PER_FLUSH = 50
