"""
LuaDec Python - Lua 5.1 Decompiler

A complete Python port of the luadec Lua 5.1 bytecode decompiler.
Integrated with MpLua support for Microsoft Defender signatures.
"""

__version__ = "1.0.0"
__author__ = "Ported from luadec C project"

from .bytecode.loader import load_chunk, load_chunk_auto
from .decompiler.engine import Decompiler, decompile
from .disassembler import disassemble

__all__ = ['load_chunk', 'load_chunk_auto', 'Decompiler', 'decompile', 'disassemble']
