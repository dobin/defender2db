"""Bytecode parsing and instruction handling."""

from .opcodes import OpCode, OpMode, OPCODE_INFO
from .instruction import Instruction
from .proto import Proto, LocVar
from .loader import load_chunk

__all__ = ['OpCode', 'OpMode', 'OPCODE_INFO', 'Instruction', 'Proto', 'LocVar', 'load_chunk']
