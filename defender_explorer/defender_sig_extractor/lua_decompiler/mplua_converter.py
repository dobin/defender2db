"""
MpLua to Standard Lua 5.1 Converter

Microsoft Defender uses a modified Lua 5.1 format called MpLua.
Key differences from standard Lua 5.1:
- Header: \x1bLuaQ\x00\x01\x04\x08\x04\x08\x01 (integral flag = 1)
- Numbers stored as 64-bit integers instead of doubles
- Strings use 4-byte lengths instead of 8-byte size_t
- Function header uses 12 null bytes (4+4+4) instead of size-prefixed string

This module converts MpLua bytecode to standard Lua 5.1 format.
Based on: https://gist.github.com/HackingLZ/65f289b8b0b9c8c3a675aa26c06dfe09
"""

import struct
from io import BytesIO
from typing import Optional, List, Union
from dataclasses import dataclass


# MpLua header signature
MPLUA_HEADER = b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'

# Standard Lua 5.1 header
LUA51_HEADER = b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x00'

# Header size
HEADER_SIZE = 12


@dataclass
class MpLuaConst:
    """Constant value from MpLua."""
    const_type: int
    value: Union[None, int, bytes]


@dataclass
class MpLuaFunc:
    """Parsed MpLua function."""
    nb_upvalues: int
    nb_params: int
    is_vararg: int
    max_stacksize: int
    instrs: bytes
    consts: List[MpLuaConst]
    funcs: List['MpLuaFunc']


class MpLuaReader:
    """
    Reads MpLua bytecode format.

    MpLua format differences from standard Lua 5.1:
    - Function headers use fixed 12 null bytes (not size-prefixed string)
    - Strings use 4-byte length prefix (not 8-byte size_t)
    - Numbers are 64-bit signed integers (not 64-bit doubles)
    """

    def __init__(self, stream: BytesIO):
        self.stream = stream

    def read_byte(self) -> int:
        b = self.stream.read(1)
        if not b:
            raise EOFError("Unexpected end of bytecode")
        return b[0]

    def read_int(self) -> int:
        """Read 4-byte little-endian integer."""
        data = self.stream.read(4)
        if len(data) < 4:
            raise EOFError("Unexpected end of bytecode")
        return struct.unpack("<I", data)[0]

    def read_function(self) -> MpLuaFunc:
        """Read MpLua function prototype."""
        # MpLua uses 12 null bytes for src_name(4) + line_def(4) + lastline_def(4)
        header = self.stream.read(12)
        if header != b'\x00' * 12:
            # Some scripts may have data here, but we ignore it
            pass

        nb_upvalues = self.read_byte()
        nb_params = self.read_byte()
        is_vararg = self.read_byte()
        max_stacksize = self.read_byte()

        nb_instr = self.read_int()
        instrs = self.stream.read(4 * nb_instr)

        nb_const = self.read_int()
        consts = []
        for _ in range(nb_const):
            cst_type = self.read_byte()
            if cst_type == 4:  # String
                length = self.read_int()  # MpLua uses 4-byte length
                value = self.stream.read(length)
                consts.append(MpLuaConst(cst_type, value))
            elif cst_type == 3:  # Number (int64)
                value = struct.unpack("<q", self.stream.read(8))[0]
                consts.append(MpLuaConst(cst_type, value))
            elif cst_type == 1:  # Boolean
                value = self.read_byte()
                consts.append(MpLuaConst(cst_type, value))
            elif cst_type == 0:  # Nil
                consts.append(MpLuaConst(cst_type, None))
            else:
                raise ValueError(f"Unknown constant type: {cst_type}")

        nb_func = self.read_int()
        funcs = [self.read_function() for _ in range(nb_func)]

        # Debug info (skip, should be zeros)
        src_line_positions = self.read_int()
        if src_line_positions != 0:
            self.stream.read(4 * src_line_positions)

        nb_locals = self.read_int()
        if nb_locals != 0:
            for _ in range(nb_locals):
                length = self.read_int()
                self.stream.read(length)
                self.stream.read(8)  # start_pc + end_pc

        debug_upvalue_count = self.read_int()
        if debug_upvalue_count != 0:
            for _ in range(debug_upvalue_count):
                length = self.read_int()
                self.stream.read(length)

        return MpLuaFunc(
            nb_upvalues=nb_upvalues,
            nb_params=nb_params,
            is_vararg=is_vararg,
            max_stacksize=max_stacksize,
            instrs=instrs,
            consts=consts,
            funcs=funcs
        )


class MpLuaWriter:
    """Writes standard Lua 5.1 bytecode format."""

    def __init__(self):
        self.output = BytesIO()

    def write_header(self):
        """Write Lua 5.1 header."""
        self.output.write(LUA51_HEADER)

    def write_function(self, func: MpLuaFunc):
        """Write function in standard Lua 5.1 format."""
        # Write 16 null bytes for standard format:
        # - 8 bytes: size_t = 0 (empty source name)
        # - 4 bytes: first_line = 0
        # - 4 bytes: last_line = 0
        self.output.write(b'\x00' * 16)

        # Function info
        self.output.write(struct.pack("BBBB",
            func.nb_upvalues, func.nb_params,
            func.is_vararg, func.max_stacksize))

        # Instructions
        nb_instr = len(func.instrs) // 4
        self.output.write(struct.pack("<I", nb_instr))
        self.output.write(func.instrs)

        # Constants
        self.output.write(struct.pack("<I", len(func.consts)))
        for cst in func.consts:
            if cst.const_type == 0:  # Nil
                self.output.write(struct.pack("B", 0))
            elif cst.const_type == 1:  # Boolean
                self.output.write(struct.pack("BB", 1, cst.value))
            elif cst.const_type == 3:  # Number
                # Convert int64 to double
                self.output.write(struct.pack("<Bd", 3, float(cst.value)))
            elif cst.const_type == 4:  # String
                # Use 8-byte size_t for standard Lua 5.1
                self.output.write(struct.pack("<BQ", 4, len(cst.value)))
                self.output.write(cst.value)

        # Nested functions
        self.output.write(struct.pack("<I", len(func.funcs)))
        for nested in func.funcs:
            self.write_function(nested)

        # Debug info (empty)
        self.output.write(struct.pack("<III", 0, 0, 0))

    def get_bytes(self) -> bytes:
        return self.output.getvalue()


def is_mplua(data: bytes) -> bool:
    """Check if data is MpLua bytecode."""
    if len(data) < HEADER_SIZE:
        return False
    if data[:5] != b'\x1bLuaQ':
        return False
    return len(data) >= 12 and data[11] == 1


def is_lua51(data: bytes) -> bool:
    """Check if data is standard Lua 5.1 bytecode."""
    if len(data) < HEADER_SIZE:
        return False
    if data[:5] != b'\x1bLuaQ':
        return False
    return len(data) >= 12 and data[11] == 0


def convert_mplua_to_lua51(data: bytes) -> bytes:
    """
    Convert MpLua bytecode to standard Lua 5.1.

    If the input is already standard Lua 5.1, returns it unchanged.
    """
    if is_lua51(data):
        return data

    if not is_mplua(data):
        raise ValueError("Not valid MpLua bytecode")

    # Skip 12-byte header
    stream = BytesIO(data[12:])
    reader = MpLuaReader(stream)
    func = reader.read_function()

    writer = MpLuaWriter()
    writer.write_header()
    writer.write_function(func)

    return writer.get_bytes()


def auto_convert(data: bytes) -> bytes:
    """
    Automatically detect and convert bytecode format.
    """
    if is_lua51(data):
        return data
    elif is_mplua(data):
        return convert_mplua_to_lua51(data)
    else:
        raise ValueError("Unknown Lua bytecode format")


def extract_lua_from_signature(sig_data: bytes) -> Optional[bytes]:
    """
    Extract Lua bytecode from a Defender signature payload.
    """
    lua_sig = b'\x1bLua'
    idx = sig_data.find(lua_sig)
    if idx == -1:
        return None
    return sig_data[idx:]


def get_format_info(data: bytes) -> dict:
    """Get information about Lua bytecode format."""
    if len(data) < HEADER_SIZE:
        return {"valid": False, "error": "Too short"}

    if data[:4] != b'\x1bLua':
        return {"valid": False, "error": "Invalid signature"}

    return {
        "valid": True,
        "version": data[4],
        "format": data[5],
        "endianness": "little" if data[6] == 1 else "big",
        "int_size": data[7],
        "size_t_size": data[8],
        "instruction_size": data[9],
        "number_size": data[10],
        "integral": data[11] == 1,
        "is_mplua": is_mplua(data),
        "is_lua51": is_lua51(data),
    }
