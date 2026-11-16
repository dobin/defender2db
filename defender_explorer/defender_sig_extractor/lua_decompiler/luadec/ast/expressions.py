"""
AST expression nodes for Lua decompilation.

Represents different types of expressions in Lua code including
constants, variables, function calls, and operators.
"""

from enum import IntEnum, auto
from typing import List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ..bytecode.opcodes import OpCode


class ExpressionType(IntEnum):
    """Types of expression nodes."""
    CONST_VAL = 0       # Constant value (nil, bool, number, string)
    LOCAL_VAR = auto()  # Local variable
    GLOBAL_VAR = auto() # Global variable
    UPVAL_VAR = auto()  # Upvalue (closure variable)
    VARARG_VAR = auto() # Vararg (...)
    FUNC_DEF = auto()   # Function definition
    TABLE_DEF = auto()  # Table constructor
    TABLE_REF = auto()  # Table reference (indexing)
    FUNC_CALL = auto()  # Function call
    UNARY_EXP = auto()  # Unary expression (-, not, #)
    BINARY_EXP = auto() # Binary expression (+, -, *, /, etc.)


@dataclass
class Expression:
    """
    AST node for an expression.

    Represents different types of Lua expressions with optional
    sub-expressions for complex expressions.
    """
    type: ExpressionType
    op: Optional['OpCode'] = None  # Opcode for operators
    reg: int = 0                   # Target register
    pc: int = 0                    # Program counter where created
    idx: int = 0                   # Index (constant, upvalue, etc.)
    left: Optional['Expression'] = None   # Left operand
    right: Optional['Expression'] = None  # Right operand
    args: List['Expression'] = field(default_factory=list)  # Call arguments

    @classmethod
    def make_const(cls, reg: int, pc: int, idx: int, op: Optional['OpCode'] = None) -> 'Expression':
        """Create a constant value expression."""
        return cls(ExpressionType.CONST_VAL, op=op, reg=reg, pc=pc, idx=idx)

    @classmethod
    def make_local(cls, reg: int, pc: int, idx: int) -> 'Expression':
        """Create a local variable expression."""
        return cls(ExpressionType.LOCAL_VAR, reg=reg, pc=pc, idx=idx)

    @classmethod
    def make_global(cls, reg: int, pc: int, idx: int, op: Optional['OpCode'] = None) -> 'Expression':
        """Create a global variable expression."""
        return cls(ExpressionType.GLOBAL_VAR, op=op, reg=reg, pc=pc, idx=idx)

    @classmethod
    def make_upval(cls, reg: int, pc: int, idx: int, op: Optional['OpCode'] = None) -> 'Expression':
        """Create an upvalue expression."""
        return cls(ExpressionType.UPVAL_VAR, op=op, reg=reg, pc=pc, idx=idx)

    @classmethod
    def make_vararg(cls, reg: int, pc: int) -> 'Expression':
        """Create a vararg expression."""
        return cls(ExpressionType.VARARG_VAR, reg=reg, pc=pc)

    @classmethod
    def make_func_def(cls, reg: int, pc: int, idx: int) -> 'Expression':
        """Create a function definition expression."""
        return cls(ExpressionType.FUNC_DEF, reg=reg, pc=pc, idx=idx)

    @classmethod
    def make_table_def(cls, reg: int, pc: int) -> 'Expression':
        """Create a table constructor expression."""
        return cls(ExpressionType.TABLE_DEF, reg=reg, pc=pc)

    @classmethod
    def make_table_ref(cls, reg: int, pc: int, idx: int, op: Optional['OpCode'] = None) -> 'Expression':
        """Create a table reference (indexing) expression."""
        return cls(ExpressionType.TABLE_REF, op=op, reg=reg, pc=pc, idx=idx)

    @classmethod
    def make_call(cls, reg: int, pc: int, op: Optional['OpCode'], func: 'Expression') -> 'Expression':
        """Create a function call expression."""
        exp = cls(ExpressionType.FUNC_CALL, op=op, reg=reg, pc=pc)
        exp.left = func
        return exp

    @classmethod
    def make_unary(cls, reg: int, pc: int, op: 'OpCode', operand: 'Expression') -> 'Expression':
        """Create a unary expression."""
        exp = cls(ExpressionType.UNARY_EXP, op=op, reg=reg, pc=pc)
        exp.left = operand
        return exp

    @classmethod
    def make_binary(cls, reg: int, pc: int, op: 'OpCode',
                   left: 'Expression', right: 'Expression') -> 'Expression':
        """Create a binary expression."""
        exp = cls(ExpressionType.BINARY_EXP, op=op, reg=reg, pc=pc)
        exp.left = left
        exp.right = right
        return exp

    def clear(self) -> None:
        """Clear this expression."""
        if self.left:
            self.left.clear()
            self.left = None
        if self.right:
            self.right.clear()
            self.right = None
        for arg in self.args:
            arg.clear()
        self.args.clear()


# Expression type names for debugging
EXPRESSION_TYPE_NAMES = {
    ExpressionType.CONST_VAL: "CONST_VAL",
    ExpressionType.LOCAL_VAR: "LOCAL_VAR",
    ExpressionType.GLOBAL_VAR: "GLOBAL_VAR",
    ExpressionType.UPVAL_VAR: "UPVAL_VAR",
    ExpressionType.VARARG_VAR: "VARARG_VAR",
    ExpressionType.FUNC_DEF: "FUNC_DEF",
    ExpressionType.TABLE_DEF: "TABLE_DEF",
    ExpressionType.TABLE_REF: "TABLE_REF",
    ExpressionType.FUNC_CALL: "FUNC_CALL",
    ExpressionType.UNARY_EXP: "UNARY_EXP",
    ExpressionType.BINARY_EXP: "BINARY_EXP",
}
