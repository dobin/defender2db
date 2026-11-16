"""
Lua 5.1 bytecode decompiler with MpLua support.

This module provides decompilation of Lua 5.1 bytecode, including Microsoft's
MpLua variant used in Windows Defender signatures.

Usage:
    from lua_decompiler import decompile_bytecode

    with open('script.luac', 'rb') as f:
        bytecode = f.read()

    source = decompile_bytecode(bytecode)
    print(source)
"""

from .mplua_converter import (
    auto_convert,
    is_mplua,
    is_lua51,
    convert_mplua_to_lua51,
    get_format_info,
)
from .luadec import load_chunk_auto, decompile as luadec_decompile, Decompiler

from .undump import (
    undump,
    undump_file,
    is_lua_bytecode,
    Undumper,
    Chunk,
    Constant,
    ConstType,
    Local,
)


def decompile_bytecode(data: bytes) -> str:
    """
    Decompile Lua bytecode to source code.

    Automatically handles both standard Lua 5.1 and MpLua (Microsoft Defender)
    bytecode formats.

    Args:
        data: Raw bytecode bytes

    Returns:
        Decompiled Lua source code as a string
    """
    # Load with automatic MpLua conversion
    proto = load_chunk_auto(data)

    # Decompile to source
    source = luadec_decompile(proto)

    # Strip the function wrapper if present (luadec adds function(...) ... end)
    lines = source.strip().split('\n')
    if lines and lines[0].strip().startswith('function('):
        # Remove function wrapper
        if len(lines) > 2 and lines[-1].strip() == 'end':
            # Remove first and last line, dedent the rest
            inner_lines = lines[1:-1]
            # Find minimum indentation
            min_indent = float('inf')
            for line in inner_lines:
                if line.strip():
                    indent = len(line) - len(line.lstrip())
                    min_indent = min(min_indent, indent)
            if min_indent == float('inf'):
                min_indent = 0
            # Dedent
            source = '\n'.join(
                line[min_indent:] if len(line) > min_indent else line
                for line in inner_lines
            )

    return source


__all__ = [
    # Main API
    'decompile_bytecode',
    'load_chunk_auto',
    'Decompiler',

    # MpLua utilities
    'auto_convert',
    'is_mplua',
    'is_lua51',
    'convert_mplua_to_lua51',
    'get_format_info',

    # Bytecode parsing
    'undump',
    'undump_file',
    'is_lua_bytecode',
    'Undumper',
    'Chunk',
    'Constant',
    'ConstType',
    'Local',
]
