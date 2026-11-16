"""
Lua 5.1 Bytecode Undumper

Deserializes Lua bytecode into structured representation.
Supports both standard Lua 5.1 and MpLua (Microsoft's variant).
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Union, BinaryIO
from io import BytesIO
from enum import IntEnum

from .opcodes import Instruction, decode_instruction


# Lua bytecode header signature
LUA_SIGNATURE = b'\x1bLua'
LUAC_VERSION = 0x51  # Lua 5.1
LUAC_FORMAT = 0      # Official format

# Header byte positions
LUA_HEADER_SIZE = 12


class ConstType(IntEnum):
    """Lua constant types."""
    NIL = 0
    BOOLEAN = 1
    NUMBER = 3
    STRING = 4


@dataclass
class Local:
    """Local variable debug information."""
    name: str
    start_pc: int  # First point where active
    end_pc: int    # Last point where active


@dataclass
class Constant:
    """Lua constant value."""
    type: ConstType
    value: Union[None, bool, float, str, int]

    def __str__(self) -> str:
        if self.type == ConstType.NIL:
            return "nil"
        elif self.type == ConstType.BOOLEAN:
            return "true" if self.value else "false"
        elif self.type == ConstType.NUMBER:
            # Handle integer-like numbers
            if isinstance(self.value, float) and self.value == int(self.value):
                return str(int(self.value))
            return str(self.value)
        elif self.type == ConstType.STRING:
            # Escape special characters
            s = self.value
            s = s.replace('\\', '\\\\')
            s = s.replace('"', '\\"')
            s = s.replace('\n', '\\n')
            s = s.replace('\r', '\\r')
            s = s.replace('\t', '\\t')
            return f'"{s}"'
        return repr(self.value)


@dataclass
class Chunk:
    """Lua function/chunk representation."""
    name: str = ""
    first_line: int = 0
    last_line: int = 0
    num_upvalues: int = 0
    num_params: int = 0
    is_vararg: int = 0
    max_stack: int = 0
    instructions: List[Instruction] = field(default_factory=list)
    constants: List[Constant] = field(default_factory=list)
    protos: List['Chunk'] = field(default_factory=list)
    lines: List[int] = field(default_factory=list)
    locals: List[Local] = field(default_factory=list)
    upvalues: List[str] = field(default_factory=list)

    def get_constant(self, idx: int) -> Constant:
        """Get constant by index."""
        if 0 <= idx < len(self.constants):
            return self.constants[idx]
        return Constant(ConstType.NIL, None)

    def get_local_name(self, reg: int, pc: int) -> Optional[str]:
        """Get local variable name for register at given PC."""
        for local in self.locals:
            if local.start_pc <= pc < local.end_pc:
                if reg == 0:
                    return local.name
                reg -= 1
        return None


@dataclass
class LuaHeader:
    """Lua bytecode header information."""
    signature: bytes
    version: int
    format: int
    endianness: int  # 1 = little endian
    int_size: int
    size_t_size: int
    instruction_size: int
    number_size: int
    integral_flag: int  # 0 = floating point, 1 = integral

    @property
    def is_little_endian(self) -> bool:
        return self.endianness == 1

    @property
    def is_mplua(self) -> bool:
        """Check if this is MpLua format (integral numbers)."""
        return self.integral_flag == 1


class Undumper:
    """
    Lua bytecode deserializer.

    Reads binary Lua bytecode and produces Chunk objects.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.stream = BytesIO(data)
        self.header: Optional[LuaHeader] = None

    def _read_byte(self) -> int:
        """Read single byte."""
        b = self.stream.read(1)
        if not b:
            raise EOFError("Unexpected end of bytecode")
        return b[0]

    def _read_bytes(self, n: int) -> bytes:
        """Read n bytes."""
        data = self.stream.read(n)
        if len(data) < n:
            raise EOFError("Unexpected end of bytecode")
        return data

    def _read_int(self) -> int:
        """Read integer based on header size."""
        size = self.header.int_size if self.header else 4
        fmt = '<i' if size == 4 else '<q'
        data = self._read_bytes(size)
        return struct.unpack(fmt, data)[0]

    def _read_size_t(self) -> int:
        """Read size_t based on header size."""
        size = self.header.size_t_size if self.header else 8
        fmt = '<Q' if size == 8 else '<I'
        data = self._read_bytes(size)
        return struct.unpack(fmt, data)[0]

    def _read_number(self) -> float:
        """Read Lua number based on header format."""
        size = self.header.number_size if self.header else 8

        if self.header and self.header.is_mplua:
            # MpLua: numbers stored as 64-bit integers
            data = self._read_bytes(8)
            int_val = struct.unpack('<q', data)[0]
            return float(int_val)
        else:
            # Standard Lua: 64-bit double
            data = self._read_bytes(size)
            if size == 8:
                return struct.unpack('<d', data)[0]
            elif size == 4:
                return struct.unpack('<f', data)[0]
            else:
                raise ValueError(f"Unsupported number size: {size}")

    def _read_string(self) -> str:
        """Read Lua string (size_t length + data)."""
        size = self._read_size_t()
        if size == 0:
            return ""
        data = self._read_bytes(size)
        # Remove trailing null byte
        if data and data[-1] == 0:
            data = data[:-1]
        return data.decode('utf-8', errors='replace')

    def _read_instruction(self) -> Instruction:
        """Read single instruction."""
        raw = struct.unpack('<I', self._read_bytes(4))[0]
        return decode_instruction(raw)

    def read_header(self) -> LuaHeader:
        """Read and validate bytecode header."""
        signature = self._read_bytes(4)
        if signature != LUA_SIGNATURE:
            raise ValueError(f"Invalid Lua signature: {signature!r}")

        version = self._read_byte()
        format_byte = self._read_byte()
        endianness = self._read_byte()
        int_size = self._read_byte()
        size_t_size = self._read_byte()
        instruction_size = self._read_byte()
        number_size = self._read_byte()
        integral_flag = self._read_byte()

        self.header = LuaHeader(
            signature=signature,
            version=version,
            format=format_byte,
            endianness=endianness,
            int_size=int_size,
            size_t_size=size_t_size,
            instruction_size=instruction_size,
            number_size=number_size,
            integral_flag=integral_flag
        )

        return self.header

    def read_function(self) -> Chunk:
        """Read function prototype (chunk)."""
        chunk = Chunk()

        # Source name
        chunk.name = self._read_string()

        # Line info
        chunk.first_line = self._read_int()
        chunk.last_line = self._read_int()

        # Function info
        chunk.num_upvalues = self._read_byte()
        chunk.num_params = self._read_byte()
        chunk.is_vararg = self._read_byte()
        chunk.max_stack = self._read_byte()

        # Instructions
        num_instructions = self._read_int()
        for _ in range(num_instructions):
            chunk.instructions.append(self._read_instruction())

        # Constants
        num_constants = self._read_int()
        for _ in range(num_constants):
            const_type = ConstType(self._read_byte())
            if const_type == ConstType.NIL:
                chunk.constants.append(Constant(const_type, None))
            elif const_type == ConstType.BOOLEAN:
                chunk.constants.append(Constant(const_type, self._read_byte() != 0))
            elif const_type == ConstType.NUMBER:
                chunk.constants.append(Constant(const_type, self._read_number()))
            elif const_type == ConstType.STRING:
                chunk.constants.append(Constant(const_type, self._read_string()))
            else:
                raise ValueError(f"Unknown constant type: {const_type}")

        # Prototypes (nested functions)
        num_protos = self._read_int()
        for _ in range(num_protos):
            chunk.protos.append(self.read_function())

        # Debug info: line numbers
        num_lines = self._read_int()
        for _ in range(num_lines):
            chunk.lines.append(self._read_int())

        # Debug info: locals
        num_locals = self._read_int()
        for _ in range(num_locals):
            name = self._read_string()
            start_pc = self._read_int()
            end_pc = self._read_int()
            chunk.locals.append(Local(name, start_pc, end_pc))

        # Debug info: upvalue names
        num_upvalue_names = self._read_int()
        for _ in range(num_upvalue_names):
            chunk.upvalues.append(self._read_string())

        return chunk

    def undump(self) -> Chunk:
        """Parse complete Lua bytecode file."""
        self.read_header()
        return self.read_function()


def undump(data: bytes) -> Chunk:
    """Convenience function to undump Lua bytecode."""
    undumper = Undumper(data)
    return undumper.undump()


def undump_file(path: str) -> Chunk:
    """Undump Lua bytecode from file."""
    with open(path, 'rb') as f:
        return undump(f.read())


def is_lua_bytecode(data: bytes) -> bool:
    """Check if data looks like Lua bytecode."""
    return data[:4] == LUA_SIGNATURE


def get_lua_version(data: bytes) -> Optional[int]:
    """Get Lua version from bytecode header."""
    if len(data) < 5:
        return None
    if data[:4] != LUA_SIGNATURE:
        return None
    return data[4]
