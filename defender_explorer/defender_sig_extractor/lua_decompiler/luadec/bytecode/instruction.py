"""
Lua 5.1 instruction decoding.

Lua 5.1 instruction format (32 bits):
- Bits 0-5:   OpCode (6 bits, 0-63)
- Bits 6-13:  A (8 bits, 0-255)
- Bits 14-22: C (9 bits, 0-511)
- Bits 23-31: B (9 bits, 0-511)

Alternative formats:
- Bx: Bits 14-31 (18 bits, 0-262143) - combines B and C
- sBx: Signed Bx (offset by MAXARG_sBx = 131071)
"""

from dataclasses import dataclass
from typing import Optional
from .opcodes import OpCode, OpMode, OPCODE_INFO


# Instruction field sizes
SIZE_C = 9
SIZE_B = 9
SIZE_Bx = SIZE_C + SIZE_B  # 18
SIZE_A = 8
SIZE_OP = 6

# Field positions
POS_OP = 0
POS_A = POS_OP + SIZE_OP  # 6
POS_C = POS_A + SIZE_A    # 14
POS_B = POS_C + SIZE_C    # 23
POS_Bx = POS_C            # 14

# Maximum values
MAXARG_A = (1 << SIZE_A) - 1      # 255
MAXARG_B = (1 << SIZE_B) - 1      # 511
MAXARG_C = (1 << SIZE_C) - 1      # 511
MAXARG_Bx = (1 << SIZE_Bx) - 1    # 262143
MAXARG_sBx = MAXARG_Bx >> 1       # 131071

# Bit masks
MASK_OP = (1 << SIZE_OP) - 1      # 0x3F
MASK_A = (1 << SIZE_A) - 1        # 0xFF
MASK_B = (1 << SIZE_B) - 1        # 0x1FF
MASK_C = (1 << SIZE_C) - 1        # 0x1FF
MASK_Bx = (1 << SIZE_Bx) - 1      # 0x3FFFF

# RK (register or constant) encoding
# Bit 8 set means constant, clear means register
BITRK = 1 << (SIZE_B - 1)  # 256
MAXINDEXRK = BITRK - 1      # 255


def is_k(x: int) -> bool:
    """Check if a B/C value refers to a constant (bit 8 set)."""
    return (x & BITRK) != 0


def index_k(x: int) -> int:
    """Extract constant index from RK value."""
    return x & ~BITRK


def rk_as_k(x: int) -> int:
    """Encode a constant index as RK value."""
    return x | BITRK


@dataclass(frozen=True)
class Instruction:
    """
    Decoded Lua 5.1 instruction.

    All instructions have an opcode and A register.
    Depending on the instruction mode:
    - iABC: Also has B and C (9 bits each)
    - iABx: Also has Bx (18 bits unsigned)
    - iAsBx: Also has sBx (18 bits signed)
    """
    raw: int
    op: OpCode
    a: int
    b: int
    c: int
    bx: int
    sbx: int

    @classmethod
    def decode(cls, raw: int) -> 'Instruction':
        """Decode a 32-bit instruction into its components."""
        op = OpCode(raw & MASK_OP)
        a = (raw >> POS_A) & MASK_A
        c = (raw >> POS_C) & MASK_C
        b = (raw >> POS_B) & MASK_B
        bx = (raw >> POS_Bx) & MASK_Bx
        sbx = bx - MAXARG_sBx

        return cls(raw=raw, op=op, a=a, b=b, c=c, bx=bx, sbx=sbx)

    @classmethod
    def encode(cls, op: OpCode, a: int = 0, b: int = 0, c: int = 0,
               bx: Optional[int] = None, sbx: Optional[int] = None) -> 'Instruction':
        """Encode instruction components into a 32-bit instruction."""
        mode = OPCODE_INFO[op].mode

        if mode == OpMode.iABC:
            raw = (op & MASK_OP) | ((a & MASK_A) << POS_A) | \
                  ((c & MASK_C) << POS_C) | ((b & MASK_B) << POS_B)
            actual_bx = (b << SIZE_C) | c
            actual_sbx = actual_bx - MAXARG_sBx
        elif mode == OpMode.iABx:
            if bx is None:
                bx = 0
            raw = (op & MASK_OP) | ((a & MASK_A) << POS_A) | \
                  ((bx & MASK_Bx) << POS_Bx)
            actual_bx = bx
            actual_sbx = bx - MAXARG_sBx
            b = (bx >> SIZE_C) & MASK_B
            c = bx & MASK_C
        elif mode == OpMode.iAsBx:
            if sbx is None:
                sbx = 0
            actual_sbx = sbx
            actual_bx = sbx + MAXARG_sBx
            raw = (op & MASK_OP) | ((a & MASK_A) << POS_A) | \
                  ((actual_bx & MASK_Bx) << POS_Bx)
            b = (actual_bx >> SIZE_C) & MASK_B
            c = actual_bx & MASK_C
        else:
            raise ValueError(f"Unknown instruction mode: {mode}")

        return cls(raw=raw, op=op, a=a, b=b, c=c, bx=actual_bx, sbx=actual_sbx)

    @property
    def mode(self) -> OpMode:
        """Get the instruction mode."""
        return OPCODE_INFO[self.op].mode

    @property
    def name(self) -> str:
        """Get the opcode name."""
        return OPCODE_INFO[self.op].name

    def is_b_k(self) -> bool:
        """Check if B refers to a constant."""
        return is_k(self.b)

    def is_c_k(self) -> bool:
        """Check if C refers to a constant."""
        return is_k(self.c)

    def b_rk(self) -> int:
        """Get B value as register index or constant index."""
        return index_k(self.b) if self.is_b_k() else self.b

    def c_rk(self) -> int:
        """Get C value as register index or constant index."""
        return index_k(self.c) if self.is_c_k() else self.c

    def __repr__(self) -> str:
        mode = self.mode
        if mode == OpMode.iABC:
            return f"Instruction({self.name} A={self.a} B={self.b} C={self.c})"
        elif mode == OpMode.iABx:
            return f"Instruction({self.name} A={self.a} Bx={self.bx})"
        else:  # iAsBx
            return f"Instruction({self.name} A={self.a} sBx={self.sbx})"

    def disassemble_args(self) -> str:
        """Get disassembly string for arguments."""
        mode = self.mode
        if mode == OpMode.iABC:
            parts = [f"R{self.a}"]
            b_mode = OPCODE_INFO[self.op].b_mode
            c_mode = OPCODE_INFO[self.op].c_mode

            from .opcodes import OpArgMask
            if b_mode != OpArgMask.OpArgN:
                if is_k(self.b):
                    parts.append(f"K{index_k(self.b)}")
                else:
                    parts.append(f"R{self.b}" if b_mode == OpArgMask.OpArgR else str(self.b))
            if c_mode != OpArgMask.OpArgN:
                if is_k(self.c):
                    parts.append(f"K{index_k(self.c)}")
                else:
                    parts.append(f"R{self.c}" if c_mode == OpArgMask.OpArgR else str(self.c))
            return " ".join(parts)
        elif mode == OpMode.iABx:
            return f"R{self.a} {self.bx}"
        else:  # iAsBx
            return f"R{self.a} {self.sbx}"


def decode_instructions(code: list) -> list:
    """Decode a list of raw instructions."""
    return [Instruction.decode(raw) for raw in code]
