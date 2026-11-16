"""
Lua 5.1 bytecode loader.

Parses compiled Lua bytecode files (.luac) and creates Proto structures.

Bytecode file format (Lua 5.1):
- Header (12 bytes)
- Main function prototype (recursive structure)

Header format:
- 4 bytes: LUA_SIGNATURE (0x1B 0x4C 0x75 0x61 = "\x1bLua")
- 1 byte:  Version (0x51 for Lua 5.1)
- 1 byte:  Format (0 = official)
- 1 byte:  Endianness (1 = little endian, 0 = big endian)
- 1 byte:  sizeof(int)
- 1 byte:  sizeof(size_t)
- 1 byte:  sizeof(Instruction)
- 1 byte:  sizeof(lua_Number)
- 1 byte:  Integral flag (1 if lua_Number is integral)
"""

import struct
from io import BytesIO
from typing import BinaryIO, Any, List, Optional, Union
from .proto import Proto, LocVar


# Lua type tags for constants
LUA_TNIL = 0
LUA_TBOOLEAN = 1
LUA_TNUMBER = 3
LUA_TSTRING = 4

# Lua 5.1 signature
LUA_SIGNATURE = b'\x1bLua'
LUAC_VERSION = 0x51
LUAC_FORMAT = 0


class LoaderError(Exception):
    """Error during bytecode loading."""
    pass


class BytecodeLoader:
    """
    Loads Lua 5.1 bytecode from a binary stream.

    Handles endianness and type sizes automatically based on the header.
    """

    def __init__(self, stream: BinaryIO, name: str = "?"):
        self.stream = stream
        self.name = name

        # Will be set by load_header
        self.little_endian = True
        self.int_size = 4
        self.size_t_size = 4
        self.instruction_size = 4
        self.number_size = 8
        self.number_integral = False

    def read_bytes(self, n: int) -> bytes:
        """Read exactly n bytes from the stream."""
        data = self.stream.read(n)
        if len(data) != n:
            raise LoaderError(f"Unexpected end of file (expected {n} bytes, got {len(data)})")
        return data

    def read_byte(self) -> int:
        """Read a single byte as unsigned integer."""
        return self.read_bytes(1)[0]

    def read_int(self) -> int:
        """Read an integer with configured size and endianness."""
        data = self.read_bytes(self.int_size)
        fmt = '<i' if self.little_endian else '>i'
        if self.int_size == 4:
            return struct.unpack(fmt, data)[0]
        elif self.int_size == 8:
            fmt = '<q' if self.little_endian else '>q'
            return struct.unpack(fmt, data)[0]
        else:
            raise LoaderError(f"Unsupported int size: {self.int_size}")

    def read_size_t(self) -> int:
        """Read a size_t with configured size and endianness."""
        data = self.read_bytes(self.size_t_size)
        if self.size_t_size == 4:
            fmt = '<I' if self.little_endian else '>I'
        elif self.size_t_size == 8:
            fmt = '<Q' if self.little_endian else '>Q'
        else:
            raise LoaderError(f"Unsupported size_t size: {self.size_t_size}")
        return struct.unpack(fmt, data)[0]

    def read_number(self) -> float:
        """Read a lua_Number with configured size and endianness."""
        data = self.read_bytes(self.number_size)
        if self.number_integral:
            if self.number_size == 4:
                fmt = '<i' if self.little_endian else '>i'
            elif self.number_size == 8:
                fmt = '<q' if self.little_endian else '>q'
            else:
                raise LoaderError(f"Unsupported integral number size: {self.number_size}")
            return struct.unpack(fmt, data)[0]
        else:
            if self.number_size == 4:
                fmt = '<f' if self.little_endian else '>f'
            elif self.number_size == 8:
                fmt = '<d' if self.little_endian else '>d'
            else:
                raise LoaderError(f"Unsupported number size: {self.number_size}")
            return struct.unpack(fmt, data)[0]

    def read_instruction(self) -> int:
        """Read a single instruction (32-bit unsigned)."""
        data = self.read_bytes(self.instruction_size)
        if self.instruction_size == 4:
            fmt = '<I' if self.little_endian else '>I'
        else:
            raise LoaderError(f"Unsupported instruction size: {self.instruction_size}")
        return struct.unpack(fmt, data)[0]

    def read_string(self) -> Optional[str]:
        """Read a Lua string (size_t length + chars + null terminator)."""
        size = self.read_size_t()
        if size == 0:
            return None
        data = self.read_bytes(size)
        # Remove trailing null terminator and decode
        return data[:-1].decode('latin-1')

    def load_header(self) -> None:
        """Load and validate the bytecode header."""
        # Check signature
        sig = self.read_bytes(4)
        if sig != LUA_SIGNATURE:
            raise LoaderError(f"Not a Lua bytecode file (bad signature: {sig!r})")

        # Check version
        version = self.read_byte()
        if version != LUAC_VERSION:
            raise LoaderError(f"Unsupported Lua version: 0x{version:02x} (expected 0x{LUAC_VERSION:02x})")

        # Check format
        fmt = self.read_byte()
        if fmt != LUAC_FORMAT:
            raise LoaderError(f"Unsupported format: {fmt} (expected {LUAC_FORMAT})")

        # Read type sizes
        endianness = self.read_byte()
        self.little_endian = (endianness == 1)

        self.int_size = self.read_byte()
        self.size_t_size = self.read_byte()
        self.instruction_size = self.read_byte()
        self.number_size = self.read_byte()
        self.number_integral = (self.read_byte() != 0)

        # Validate sizes
        if self.int_size not in (4, 8):
            raise LoaderError(f"Unsupported int size: {self.int_size}")
        if self.size_t_size not in (4, 8):
            raise LoaderError(f"Unsupported size_t size: {self.size_t_size}")
        if self.instruction_size != 4:
            raise LoaderError(f"Unsupported instruction size: {self.instruction_size}")
        if self.number_size not in (4, 8):
            raise LoaderError(f"Unsupported number size: {self.number_size}")

    def load_code(self, proto: Proto) -> None:
        """Load the instruction array for a function."""
        n = self.read_int()
        proto.code = [self.read_instruction() for _ in range(n)]

    def load_constants(self, proto: Proto, parent_source: Optional[str]) -> None:
        """Load constants and nested function prototypes."""
        # Load constants
        n = self.read_int()
        proto.k = []
        for _ in range(n):
            t = self.read_byte()
            if t == LUA_TNIL:
                proto.k.append(None)
            elif t == LUA_TBOOLEAN:
                proto.k.append(self.read_byte() != 0)
            elif t == LUA_TNUMBER:
                proto.k.append(self.read_number())
            elif t == LUA_TSTRING:
                proto.k.append(self.read_string())
            else:
                raise LoaderError(f"Unknown constant type: {t}")

        # Load nested function prototypes
        n = self.read_int()
        proto.p = []
        for _ in range(n):
            child = self.load_function(parent_source)
            proto.p.append(child)

    def load_debug(self, proto: Proto) -> None:
        """Load debug information (line info, local vars, upvalue names)."""
        # Line info
        n = self.read_int()
        proto.lineinfo = [self.read_int() for _ in range(n)]

        # Local variables
        n = self.read_int()
        proto.locvars = []
        for _ in range(n):
            varname = self.read_string() or ""
            startpc = self.read_int()
            endpc = self.read_int()
            proto.locvars.append(LocVar(varname, startpc, endpc))

        # Upvalue names
        n = self.read_int()
        proto.upvalues = []
        for _ in range(n):
            name = self.read_string() or ""
            proto.upvalues.append(name)

    def load_function(self, parent_source: Optional[str] = None) -> Proto:
        """Load a function prototype recursively."""
        proto = Proto()

        # Source name
        proto.source = self.read_string() or parent_source or "?"

        # Line numbers
        proto.linedefined = self.read_int()
        proto.lastlinedefined = self.read_int()

        # Function parameters
        proto.nups = self.read_byte()
        proto.numparams = self.read_byte()
        proto.is_vararg = self.read_byte()
        proto.maxstacksize = self.read_byte()

        # Load code, constants, debug info
        self.load_code(proto)
        self.load_constants(proto, proto.source)
        self.load_debug(proto)

        return proto

    def load(self) -> Proto:
        """Load the entire bytecode file and return the main Proto."""
        self.load_header()
        return self.load_function()


def load_chunk(source: Union[BinaryIO, bytes, str], name: str = "?") -> Proto:
    """
    Load a Lua 5.1 bytecode chunk.

    Args:
        source: File-like object, bytes, or file path
        name: Name for error messages

    Returns:
        Proto structure for the main function
    """
    if isinstance(source, str):
        # File path
        with open(source, 'rb') as f:
            return load_chunk(f, source)
    elif isinstance(source, bytes):
        # Bytes
        return load_chunk(BytesIO(source), name)
    else:
        # File-like object
        loader = BytecodeLoader(source, name)
        return loader.load()


def load_file(path: str) -> Proto:
    """Load a Lua 5.1 bytecode file from disk."""
    return load_chunk(path, path)


def load_chunk_auto(source: Union[bytes, str], name: str = "?") -> Proto:
    """
    Load a Lua 5.1 bytecode chunk with automatic MpLua detection and conversion.

    This function automatically detects Microsoft's MpLua format (used in Windows
    Defender) and converts it to standard Lua 5.1 before loading.

    Args:
        source: Bytes or file path
        name: Name for error messages

    Returns:
        Proto structure for the main function
    """
    # Get bytes
    if isinstance(source, str):
        with open(source, 'rb') as f:
            data = f.read()
        name = source
    else:
        data = source

    # Import MpLua converter from parent package
    try:
        from ...mplua_converter import auto_convert, is_mplua
        data = auto_convert(data)
    except ImportError:
        # MpLua converter not available, try loading as-is
        pass

    return load_chunk(data, name)
