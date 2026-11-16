"""
Lua 5.1 Proto (function prototype) structure.

The Proto structure contains all information about a compiled Lua function:
- Source info (filename, line numbers)
- Parameters and vararg info
- Bytecode instructions
- Constants table
- Nested function prototypes
- Debug information (local variables, upvalue names, line info)
"""

from dataclasses import dataclass, field
from typing import List, Any, Optional, Union
from .instruction import Instruction


@dataclass
class LocVar:
    """
    Local variable debug information.

    Stored in Proto.locvars array, records:
    - varname: The variable name
    - startpc: First instruction where variable is active
    - endpc: Last instruction where variable is active (exclusive)
    """
    varname: str
    startpc: int
    endpc: int

    def __repr__(self) -> str:
        return f"LocVar({self.varname!r}, {self.startpc}-{self.endpc})"


@dataclass
class Proto:
    """
    Lua function prototype.

    This is the Python equivalent of the C Proto structure defined in lobject.h.
    It contains everything needed to execute or decompile a Lua function.
    """
    # Source information
    source: str = ""
    linedefined: int = 0
    lastlinedefined: int = 0

    # Function parameters
    numparams: int = 0
    is_vararg: int = 0  # 0=none, 2=vararg, 3/7=uses 'arg' parameter
    maxstacksize: int = 0

    # Bytecode
    code: List[int] = field(default_factory=list)

    # Constants (nil, bool, number, string)
    k: List[Any] = field(default_factory=list)

    # Nested function prototypes
    p: List['Proto'] = field(default_factory=list)

    # Debug information
    lineinfo: List[int] = field(default_factory=list)  # Line number per instruction
    locvars: List[LocVar] = field(default_factory=list)  # Local variable info
    upvalues: List[str] = field(default_factory=list)  # Upvalue names

    # Number of upvalues (may differ from len(upvalues) if debug info stripped)
    nups: int = 0

    @property
    def sizecode(self) -> int:
        """Number of instructions."""
        return len(self.code)

    @property
    def sizek(self) -> int:
        """Number of constants."""
        return len(self.k)

    @property
    def sizep(self) -> int:
        """Number of nested prototypes."""
        return len(self.p)

    @property
    def sizelineinfo(self) -> int:
        """Size of line info array."""
        return len(self.lineinfo)

    @property
    def sizelocvars(self) -> int:
        """Number of local variables."""
        return len(self.locvars)

    @property
    def sizeupvalues(self) -> int:
        """Number of upvalue names."""
        return len(self.upvalues)

    @property
    def func_block_end(self) -> int:
        """End of function block (sizecode - 1 for Lua 5.1)."""
        return self.sizecode - 1

    def needs_arg(self) -> bool:
        """
        Check if function uses the implicit 'arg' parameter.

        In Lua 5.1 with LUA_COMPAT_VARARG:
        - is_vararg = 0: not vararg
        - is_vararg = 2: vararg, main chunk
        - is_vararg = 3 or 7: vararg with 'arg' parameter
        """
        return self.is_vararg in (3, 7)

    def get_instruction(self, pc: int) -> Instruction:
        """Get decoded instruction at pc."""
        return Instruction.decode(self.code[pc])

    def get_constant(self, idx: int) -> Any:
        """Get constant at index."""
        if 0 <= idx < len(self.k):
            return self.k[idx]
        return None

    def get_local_name(self, reg: int, pc: int) -> Optional[str]:
        """
        Get local variable name for register at given pc.

        Returns None if no local variable is active at that register/pc.
        """
        for locvar in self.locvars:
            if locvar.startpc <= pc < locvar.endpc:
                if reg == 0:
                    return locvar.varname
                reg -= 1
        return None

    def get_upvalue_name(self, idx: int) -> Optional[str]:
        """Get upvalue name at index."""
        if 0 <= idx < len(self.upvalues):
            return self.upvalues[idx]
        return None

    def get_line(self, pc: int) -> int:
        """Get source line number for instruction at pc."""
        if 0 <= pc < len(self.lineinfo):
            return self.lineinfo[pc]
        return 0

    def __repr__(self) -> str:
        return (f"Proto(source={self.source!r}, lines={self.linedefined}-{self.lastlinedefined}, "
                f"params={self.numparams}, vararg={self.is_vararg}, "
                f"stack={self.maxstacksize}, code={self.sizecode}, "
                f"constants={self.sizek}, protos={self.sizep}, "
                f"upvalues={self.nups})")


def format_constant(value: Any) -> str:
    """
    Format a constant value as a Lua literal string.

    Handles:
    - None -> "nil"
    - bool -> "true" or "false"
    - int/float -> number literal
    - str -> quoted string with escapes
    """
    if value is None:
        return "nil"
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        # Handle special float values
        if isinstance(value, float):
            if value != value:  # NaN
                return "(0/0)"
            elif value == float('inf'):
                return "(1/0)"
            elif value == float('-inf'):
                return "(-1/0)"
            # Check if it's a whole number
            if value.is_integer() and abs(value) < 2**53:
                return str(int(value))
        return repr(value)
    elif isinstance(value, str):
        return format_string(value)
    else:
        return repr(value)


def format_string(s: str) -> str:
    """
    Format a string as a Lua string literal.

    Escapes special characters and uses appropriate quoting.
    """
    # Count quotes to decide which to use
    single_count = s.count("'")
    double_count = s.count('"')

    # Use whichever quote requires fewer escapes
    if single_count <= double_count:
        quote = "'"
        other_quote = '"'
    else:
        quote = '"'
        other_quote = "'"

    result = [quote]
    for char in s:
        code = ord(char)
        if char == quote:
            result.append('\\')
            result.append(quote)
        elif char == '\\':
            result.append('\\\\')
        elif char == '\n':
            result.append('\\n')
        elif char == '\r':
            result.append('\\r')
        elif char == '\t':
            result.append('\\t')
        elif char == '\a':
            result.append('\\a')
        elif char == '\b':
            result.append('\\b')
        elif char == '\f':
            result.append('\\f')
        elif char == '\v':
            result.append('\\v')
        elif char == '\0':
            result.append('\\0')
        elif code < 32 or code > 126:
            # Non-printable: use decimal escape
            result.append(f'\\{code}')
        else:
            result.append(char)

    result.append(quote)
    return ''.join(result)


def is_identifier(name: str) -> bool:
    """
    Check if a string is a valid Lua identifier.

    A valid identifier:
    - Starts with letter or underscore
    - Contains only letters, digits, underscores
    - Is not a reserved keyword
    """
    if not name:
        return False

    # Check first character
    if not (name[0].isalpha() or name[0] == '_'):
        return False

    # Check remaining characters
    for char in name[1:]:
        if not (char.isalnum() or char == '_'):
            return False

    # Check for reserved words
    from .opcodes import LUA_KEYWORDS
    if name in LUA_KEYWORDS:
        return False

    return True
