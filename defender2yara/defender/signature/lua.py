"""SIGNATURE_TYPE_LUASTANDALONE (0xbd) — a standalone MpLua script.

The record is a *script*, not a file fingerprint: a wrapper around a precompiled
Lua 5.1 chunk that Defender's MpLua engine loads and runs at a specific
definition/scan *phase*.  Layout::

    u8   name_length        length of the script name including its NUL
    u8   phase              index into the engine's phase table (0..0x23)
    u16  attributes_length
    u32  body_length
    u8   name[name_length]
    u8   attributes[attributes_length]   NUL-separated name / value pairs
    u8   body[body_length]               Lua 5.1 chunk

``FUN_180415898`` builds the record from the "custom ASR"/definition blob and
requires ``phase < 0x24`` (the 36-entry table at ``0x180c6a650``, entries are
``{char *name, u64 flags}``).  The flag word selects the plain vs tagged record
path (bit 0), marks the ``TimeStamp``/``Flags`` attributes as expected
(bits 2/3) and its high nibble becomes a chunk-loader option.

Two chunk encodings exist.  The normal one starts with the 12-byte MpLua header
``1b 4c 75 61 51 00 01 04 08 04 08 01``; a second variant replaces that header
with ``01 00 00 00 00 00 00 00 00 00 00 00``.  ``FUN_1803e6f18`` treats a first
dword of ``1`` as that headerless form and skips 12 bytes either way, so the
undumped function follows in both cases.  The loader (``FUN_180a9a76c``) drops
all debug information, but the serialised chunk still contains it.

The normal-header form stores plain Lua 5.1 instruction words.  The headerless
records in the shipped database substitute the ``code`` arrays with the
byte-wise chained cipher from :mod:`lua_crypto` (``0x6305c366`` is the fixed
last word of every function, i.e. the encoded ``RETURN``), while the wrapper,
constants, prototypes and debug section stay plain.  ``LuaSig`` decodes those
words and validates the result; ``code_encoding`` is ``"substituted"`` for a
successfully decoded chunk, ``"plain"`` when the words were already ordinary
Lua 5.1 and ``"encoded"`` only when the array cannot be decoded (callers must
not hand that last case to a Lua 5.1 decompiler).

This module decodes the wrapper, splits the attributes into name/value pairs and
walks the whole Lua chunk (function prototypes, code, constants), so the
script's literals and structure are available without running a decompiler.
"""

import struct

from .base import BaseSig
from .lua_crypto import decode_word
from defender2yara.defender.constant import SIG_TYPES


LUA_HEADER = b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'
HEADERLESS_LUA_MARKER = b'\x01' + b'\x00' * 11
LUA_HEADER_SIZE = len(LUA_HEADER)

#: Engine phase table at ``0x180c6a650`` (36 entries, index = record byte 1).
LUA_PHASES = {
    0x00: "Unknown",
    0x01: "Infrastructure",
    0x02: "Deprecated",
    0x03: "Deprecated",
    0x04: "Deprecated",
    0x05: "Deprecated",
    0x06: "Deprecated",
    0x07: "Deprecated",
    0x08: "PEPREEMU",
    0x09: "PEPOSTEMU",
    0x0A: "PELast",
    0x0B: "PEFinalizer",
    0x0C: "GenFirst",
    0x0D: "GenLast",
    0x0E: "PreRemediation",
    0x0F: "PostRemediation",
    0x10: "IETrigger",
    0x11: "DetectionSpecific",
    0x12: "ProcessInspector",
    0x13: "UACTrigger",
    0x14: "FFR",
    0x15: "SignatureValidator",
    0x16: "MacroSource",
    0x17: "DynamicSignature",
    0x18: "GenFinalizer",
    0x19: "HipsRuleDefinition",
    0x1A: "RtpSkipRule",
    0x1B: "RtpSkipRuleEx",
    0x1C: "OnDetection",
    0x1D: "GenConsolidator",
    0x1E: "MachOGen",
    0x1F: "MemScan",
    0x20: "GenEarly",
    0x21: "OnImageConfig",
    0x22: "MpDiag",
    0x23: "ELFGen",
}

MAX_PHASE = 0x23
MAX_PROTO_DEPTH = 24

#: Lua 5.1 opcodes, in encoding order (bits 0..5 of an instruction).
LUA_OPCODES = (
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL",
    "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF",
    "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT",
    "JMP", "EQ", "LT", "LE", "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN",
    "FORLOOP", "FORPREP", "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG",
)

#: constant tags used by the undump (LUA_TNIL/BOOLEAN/NUMBER/STRING)
LUA_TNIL = 0
LUA_TBOOLEAN = 1
LUA_TNUMBER = 3
LUA_TSTRING = 4

MAX_CONSTANT_STRINGS = 48
MAX_CONSTANT_NUMBERS = 16
MAX_CONSTANT_TEXT = 96


def phase_name(value: int) -> str:
    """Name of a definition/scan phase, or ``phase_0x..`` when unknown."""
    name = LUA_PHASES.get(value)
    if name is not None:
        return name
    return f"phase_0x{value:02x}"


def _json_number(value):
    """Render a number constant so ``json.dumps(..., allow_nan=False)`` works."""
    if isinstance(value, float):
        if value != value:
            return "nan"
        if value in (float("inf"), float("-inf")):
            return "inf" if value > 0 else "-inf"
    return value


class _Reader:
    """Cursor with bounds checks over the serialised Lua chunk."""

    def __init__(self, data: bytes, position: int = 0) -> None:
        self.data = data
        self.position = position

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise ValueError(
                f"Truncated Lua chunk at offset {self.position}: "
                f"wanted {size} bytes, {self.remaining} left"
            )
        chunk = self.data[self.position:self.position + size]
        self.position += size
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def string(self) -> str:
        """Read a length-prefixed Lua string (length includes the NUL)."""
        size = self.u32()
        if size == 0:
            return ""
        raw = self.take(size)
        return raw.rstrip(b"\x00").decode("utf-8", "replace")


class LuaFunction:
    """One serialised Lua 5.1 function prototype."""

    def __init__(self, source: str, line_defined: int, last_line_defined: int,
                 nups: int, numparams: int, is_vararg: int, maxstacksize: int,
                 code: list[int], constants: list, protos: list["LuaFunction"],
                 line_info_count: int, locals_: list[dict], upvalues: list[str]) -> None:
        self.source = source
        self.line_defined = line_defined
        self.last_line_defined = last_line_defined
        self.nups = nups
        self.numparams = numparams
        self.is_vararg = is_vararg
        self.maxstacksize = maxstacksize
        self.code = code
        self.constants = constants
        self.protos = protos
        self.line_info_count = line_info_count
        self.locals = locals_
        self.upvalues = upvalues

    def walk(self, depth: int = 0):
        yield self
        for proto in self.protos:
            yield from proto.walk(depth + 1)

    @property
    def opcode_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for instruction in self.code:
            index = instruction & 0x3F
            name = LUA_OPCODES[index] if index < len(LUA_OPCODES) else f"OP_{index}"
            counts[name] = counts.get(name, 0) + 1
        return counts

    @property
    def invalid_opcode_count(self) -> int:
        return sum(1 for instruction in self.code
                   if (instruction & 0x3F) >= len(LUA_OPCODES))


class LuaChunk:
    """A parsed MpLua / Lua 5.1 chunk."""

    def __init__(self, has_header: bool, header: dict, root: LuaFunction) -> None:
        self.has_header = has_header
        self.header = header
        self.root = root

    @property
    def functions(self) -> list[LuaFunction]:
        return list(self.root.walk())

    @property
    def instruction_count(self) -> int:
        return sum(len(function.code) for function in self.functions)

    @property
    def string_constants(self) -> list[str]:
        seen: list[str] = []
        for function in self.functions:
            for constant in function.constants:
                if isinstance(constant, str) and constant not in seen:
                    seen.append(constant)
        return seen

    @property
    def number_constants(self) -> list:
        seen: list = []
        for function in self.functions:
            for constant in function.constants:
                if isinstance(constant, bool) or not isinstance(constant, (int, float)):
                    continue
                if constant not in seen:
                    seen.append(constant)
        return seen

    @property
    def opcode_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for function in self.functions:
            for name, value in function.opcode_counts.items():
                counts[name] = counts.get(name, 0) + value
        return counts

    @property
    def invalid_opcode_count(self) -> int:
        return sum(function.invalid_opcode_count for function in self.functions)

    @property
    def is_plain_bytecode(self) -> bool:
        """True when every instruction word uses a documented Lua 5.1 opcode."""
        return self.invalid_opcode_count == 0

    def to_details(self) -> dict:
        functions = self.functions
        strings: list[str] = []
        numbers: list = []
        opcodes: dict[str, int] = {}
        for function in functions:
            for constant in function.constants:
                if isinstance(constant, str):
                    if constant not in strings:
                        strings.append(constant)
                elif not isinstance(constant, bool) and isinstance(constant, (int, float)):
                    if constant not in numbers:
                        numbers.append(constant)
            for name, value in function.opcode_counts.items():
                opcodes[name] = opcodes.get(name, 0) + value
        opcode_rows = sorted(opcodes.items(), key=lambda item: (-item[1], item[0]))
        return {
            "has_header": self.has_header,
            "header": dict(self.header),
            "version": self.header.get("version", ""),
            "number_encoding": self.header.get("number_encoding", ""),
            "functions": len(functions),
            "instructions": sum(len(function.code) for function in functions),
            "invalid_opcodes": self.invalid_opcode_count,
            "constants": sum(len(function.constants) for function in functions),
            "string_count": len(strings),
            "string_constants": [
                value[:MAX_CONSTANT_TEXT] for value in strings[:MAX_CONSTANT_STRINGS]
            ],
            "number_count": len(numbers),
            "number_constants": [
                _json_number(value) for value in numbers[:MAX_CONSTANT_NUMBERS]
            ],
            "opcodes": [
                {"name": name, "count": count} for name, count in opcode_rows[:8]
            ],
            "max_stacksize": max(
                (function.maxstacksize for function in functions), default=0
            ),
            "is_vararg": any(function.is_vararg for function in functions),
            "upvalues": sorted({name for function in functions for name in function.upvalues}),
            "sources": sorted({function.source for function in functions if function.source}),
            "debug_locals": sum(len(function.locals) for function in functions),
        }


def _read_number(reader: _Reader, integral: bool):
    """Read one Lua number constant.

    MpLua dumps the header's ``integral`` byte as 1, which means the 8-byte
    value is a signed integer rather than an IEEE double.  Reading it as a
    double turns ordinary values such as 2700 into denormals, so the flag is
    honoured.  Non-finite doubles are sanitised in ``to_details`` because JSON
    has no representation for them.
    """
    raw = reader.take(8)
    if integral:
        return struct.unpack("<q", raw)[0]
    return struct.unpack("<d", raw)[0]


def _read_function(reader: _Reader, depth: int = 0, integral: bool = True) -> LuaFunction:
    if depth > MAX_PROTO_DEPTH:
        raise ValueError(f"Lua chunk nests functions deeper than {MAX_PROTO_DEPTH}")

    source = reader.string()
    line_defined = reader.u32()
    last_line_defined = reader.u32()
    nups = reader.u8()
    numparams = reader.u8()
    is_vararg = reader.u8()
    maxstacksize = reader.u8()

    code_count = reader.u32()
    if code_count * 4 > reader.remaining:
        raise ValueError(f"Truncated Lua code array: {code_count} instructions")
    code = list(struct.unpack(f"<{code_count}I", reader.take(code_count * 4))) if code_count else []

    constant_count = reader.u32()
    constants: list = []
    for _ in range(constant_count):
        tag = reader.u8()
        if tag == LUA_TNIL:
            constants.append(None)
        elif tag == LUA_TBOOLEAN:
            constants.append(bool(reader.u8()))
        elif tag == LUA_TNUMBER:
            constants.append(_read_number(reader, integral))
        elif tag == LUA_TSTRING:
            constants.append(reader.string())
        else:
            raise ValueError(f"Unknown Lua constant tag {tag} at offset {reader.position - 1}")

    proto_count = reader.u32()
    protos = [_read_function(reader, depth + 1, integral) for _ in range(proto_count)]

    line_info_count = reader.u32()
    reader.take(4 * line_info_count)

    local_count = reader.u32()
    locals_ = []
    for _ in range(local_count):
        name = reader.string()
        start_pc = reader.u32()
        end_pc = reader.u32()
        locals_.append({"name": name, "start_pc": start_pc, "end_pc": end_pc})

    upvalue_count = reader.u32()
    upvalues = [reader.string() for _ in range(upvalue_count)]

    return LuaFunction(
        source=source,
        line_defined=line_defined,
        last_line_defined=last_line_defined,
        nups=nups,
        numparams=numparams,
        is_vararg=is_vararg,
        maxstacksize=maxstacksize,
        code=code,
        constants=constants,
        protos=protos,
        line_info_count=line_info_count,
        locals_=locals_,
        upvalues=upvalues,
    )


def parse_lua_chunk(data: bytes) -> LuaChunk:
    """Parse a 12-byte-header MpLua chunk (the form the engine undumps)."""
    if len(data) < LUA_HEADER_SIZE:
        raise ValueError(f"Truncated Lua header: {len(data)} bytes")
    header = data[:LUA_HEADER_SIZE]
    if header[:4] != LUA_HEADER[:4]:
        raise ValueError(f"Invalid Lua signature: {header[:4].hex()}")
    reader = _Reader(data, LUA_HEADER_SIZE)
    integral = header[11] != 0
    root = _read_function(reader, 0, integral)
    if reader.remaining:
        raise ValueError(f"{reader.remaining} bytes after the Lua chunk")
    details = _decode_header(header)
    details["number_encoding"] = "integer" if integral else "double"
    return LuaChunk(True, details, root)


def _decode_header(header: bytes) -> dict:
    return {
        "signature": header[:4].decode("latin-1"),
        "version": f"{header[4] >> 4}.{header[4] & 0xF}",
        "format": header[5],
        "little_endian": header[6] == 1,
        "int_size": header[7],
        "size_t_size": header[8],
        "instruction_size": header[9],
        "number_size": header[10],
        "integral_numbers": header[11],
    }


def decode_chunk_code(data: bytes) -> bytes:
    """Return a copy of ``data`` with every ``code`` word decoded.

    Only the serialised ``code`` arrays are transformed; everything else
    (wrapper, constants, prototypes, debug info) is copied unchanged.  The
    walker mirrors :func:`_read_function` and raises :class:`ValueError` when
    the chunk is truncated or the arrays do not cover the buffer exactly.
    """
    if len(data) < LUA_HEADER_SIZE:
        raise ValueError(f"Truncated Lua header: {len(data)} bytes")
    if data[:4] != LUA_HEADER[:4]:
        raise ValueError(f"Invalid Lua signature: {data[:4].hex()}")

    decoded = bytearray(data)
    reader = _Reader(data, LUA_HEADER_SIZE)

    def walk(depth: int = 0) -> None:
        if depth > MAX_PROTO_DEPTH:
            raise ValueError(f"Lua chunk nests functions deeper than {MAX_PROTO_DEPTH}")
        reader.string()                 # source name
        reader.take(12)                 # lines, nups, params, vararg, stack
        for _ in range(reader.u32()):
            offset = reader.position
            struct.pack_into(
                "<I", decoded, offset, decode_word(struct.unpack_from("<I", data, offset)[0])
            )
            reader.take(4)
        for _ in range(reader.u32()):   # constants
            tag = reader.u8()
            if tag == LUA_TNIL:
                continue
            if tag == LUA_TBOOLEAN:
                reader.take(1)
            elif tag == LUA_TNUMBER:
                reader.take(8)
            elif tag == LUA_TSTRING:
                reader.string()
            else:
                raise ValueError(
                    f"Unknown Lua constant tag {tag} at offset {reader.position - 1}"
                )
        for _ in range(reader.u32()):   # nested prototypes
            walk(depth + 1)
        reader.take(4 * reader.u32())   # line info
        for _ in range(reader.u32()):   # debug locals
            reader.string()
            reader.take(8)
        for _ in range(reader.u32()):   # debug upvalue names
            reader.string()

    walk()
    if reader.remaining:
        raise ValueError(f"{reader.remaining} bytes after the Lua chunk")
    return bytes(decoded)


def split_attributes(raw: bytes) -> tuple[list[dict], bytes]:
    """Split the attribute blob into NUL-separated name/value pairs.

    The engine writes repeated ``name\\0value\\0`` items.  ``Ob``-prefixed
    names mark an obfuscated value (decoded by ``FUN_1805afc44`` plus the
    256-byte substitution table at ``0x180dc18a0``); the value is kept verbatim
    here.  Any trailing bytes that do not form a complete pair are returned
    separately so a caller can keep them as raw data.
    """
    attributes: list[dict] = []
    position = 0
    while position < len(raw):
        end = raw.find(b"\x00", position)
        if end < 0:
            break
        name = raw[position:end]
        position = end + 1
        if not name:
            continue
        end = raw.find(b"\x00", position)
        if end < 0:
            break
        value = raw[position:end]
        position = end + 1
        attributes.append({
            "name": name.decode("utf-8", "replace"),
            "value": value.decode("utf-8", "replace"),
            "obfuscated": name.startswith(b"Ob"),
        })
    return attributes, raw[position:]


class LuaSig(BaseSig):
    """A standalone MpLua script (script name, phase, attributes and chunk)."""

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0xBD]

        if len(self.sig_data) < 8:
            raise ValueError(
                f"Truncated {self.sig_type} header: {len(self.sig_data)} bytes"
            )

        self.name_length = self.sig_data[0]
        self.script_type = self.sig_data[1]
        self.attributes_length = struct.unpack_from("<H", self.sig_data, 2)[0]
        self.body_length = struct.unpack_from("<I", self.sig_data, 4)[0]

        expected_size = 8 + self.name_length + self.attributes_length + self.body_length
        if expected_size != len(self.sig_data):
            raise ValueError(
                f"Invalid {self.sig_type} lengths: expected {expected_size} bytes, "
                f"got {len(self.sig_data)}"
            )

        body_offset = 8 + self.name_length + self.attributes_length
        self.name_raw = self.sig_data[8:8 + self.name_length]
        self.name = self.name_raw.rstrip(b'\0').decode('utf-8', 'replace')
        self.attributes_raw = self.sig_data[
            8 + self.name_length:8 + self.name_length + self.attributes_length
        ]
        self.body = self.sig_data[body_offset:body_offset + self.body_length]

        self.phase = self.script_type
        self.phase_name = phase_name(self.phase) if self.phase <= MAX_PHASE else (
            f"invalid_0x{self.phase:02x}"
        )

        if self.body.startswith(LUA_HEADER):
            self.body_format = "lua"
            self.lua_chunk_raw = self.body
        elif self.body[:4] == HEADERLESS_LUA_MARKER[:4]:
            self.body_format = "mplua_headerless"
            # The engine skips the 12-byte pseudo header and undumps the rest.
            self.lua_chunk_raw = LUA_HEADER + self.body[LUA_HEADER_SIZE:]
        else:
            self.body_format = "unknown"
            self.lua_chunk_raw = None

        self.attributes, self.attribute_data = split_attributes(self.attributes_raw)
        self.attribute_strings = [
            item[key]
            for item in self.attributes
            for key in ("name", "value")
            if item[key]
        ]

        self.chunk: LuaChunk | None = None
        self.lua_chunk_data: bytes | None = self.lua_chunk_raw
        self.lua_bytecode: bytes | None = self.lua_chunk_raw
        self.code_encoding = "unknown"
        self.decode_warnings = []
        if self.lua_chunk_raw is None:
            self.decode_warnings.append("Unrecognized Lua script body")
        else:
            plain = self._parse_stored_chunk()
            if plain:
                self.code_encoding = "plain"
            elif self.body_format == "mplua_headerless":
                self._decode_headerless_chunk()

    def _parse_stored_chunk(self) -> bool:
        """Parse the chunk as stored; true when its instruction words are plain."""
        try:
            self.chunk = parse_lua_chunk(self.lua_chunk_data)
        except (ValueError, struct.error) as error:
            self.decode_warnings.append(f"Invalid Lua chunk: {error}")
            return False
        return self.chunk.is_plain_bytecode

    def _decode_headerless_chunk(self) -> None:
        """Decode the substituted ``code`` arrays of a headerless chunk.

        Only reached when the stored words are not plain Lua 5.1, so a
        marker-only body with plain words (e.g. a synthetic chunk) is never
        corrupted.  A decoded chunk is accepted only when it parses and has no
        invalid opcode; otherwise the stored words and their warning are kept.
        """
        try:
            decoded = decode_chunk_code(self.lua_chunk_data)
            chunk: LuaChunk | None = parse_lua_chunk(decoded)
        except (ValueError, struct.error):
            chunk = None
        if chunk is not None and chunk.is_plain_bytecode:
            self.lua_chunk_data = decoded
            self.lua_bytecode = decoded
            self.chunk = chunk
            self.code_encoding = "substituted"
            return
        if self.chunk is not None:
            self.code_encoding = "encoded"
            self.decode_warnings.append(self._invalid_bytecode_warning())

    def _invalid_bytecode_warning(self) -> str:
        return (
            "Non-standard Lua bytecode: "
            f"{self.chunk.invalid_opcode_count} of "
            f"{self.chunk.instruction_count} instructions have an invalid opcode"
        )

    def to_details(self) -> dict:
        chunk = self.chunk.to_details() if self.chunk is not None else None
        return {
            "record_name": self.name,
            "has_name": self.name_length > 0,
            "script_type": self.script_type,
            "phase_name": self.phase_name,
            "attributes": [dict(item) for item in self.attributes],
            "attribute_strings": list(self.attribute_strings),
            "attribute_data_hex": (
                self.attribute_data.hex() if self.attribute_data else None
            ),
            "body_size": self.body_length,
            "body_format": self.body_format,
            "code_encoding": self.code_encoding,
            "has_lua_bytecode": self.lua_chunk_data is not None,
            "chunk": chunk,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = f"LUA {self.name or '(unnamed)'} phase={self.phase_name} body={self.body_format}"
        if self.attribute_strings:
            text += f" attributes={'/'.join(self.attribute_strings)}"
        text += f" size={self.body_length}"
        if self.chunk is not None:
            text += (
                f" protos={len(self.chunk.functions)}"
                f" strings={len(self.chunk.string_constants)}"
            )
        return text
