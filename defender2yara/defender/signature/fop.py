"""File-offset pattern signatures: ``FOP`` (``0x7f``) and ``FOPEX`` (``0x89``).

FOP is Defender's **code-pattern** signature used by the emulator/code scanner
(``FopScanner``): the payload is a literal x86/x64 code fragment that is matched
at a file offset.  FOPEX is the extended form: the fragment is split into a
literal prefix, a wildcard body and an optional wildcard suffix, and carries a
signed match offset.

On-disk payloads (x64 build 1.1.26100.4, parser ``FUN_1802b10b4``)::

    FOP (0x7f)
    u8   flags                  bit 0 only (0/1 observed)
    u8   name_length
    u16  pattern_length
    u8   name[name_length]      feed label, not NUL terminated
    u8   pattern[pattern_length] literal bytes

    FOPEX (0x89)
    u8   flags                  bit 0 only (0/1 observed)
    u8   name_length
    u16  prefix_length          literal code block
    u16  body_length            wildcard pattern block
    u16  suffix_length          optional wildcard block (0 or 1 observed)
    i16  offset                 signed match offset (-480..1064 observed)
    u8   name[name_length]      feed label, not NUL terminated
    u8   prefix[prefix_length]
    u8   body[body_length]
    u8   suffix[suffix_length]

The parser validates the total length as ``4 + name + pattern`` (FOP) or
``10 + name + prefix + body + suffix`` (FOPEX).  FOP bytes are literal: a
``0x90`` is a NOP, not a wildcard.  In FOPEX the body and suffix are validated
with the engine wildcard validator ``FUN_1802b1974`` and use the shared
``0x90`` opcode language (``90 00`` terminator, ``90 01 n`` skip, ...).
The signed ``offset`` is added to the current scan position by the matcher
(``FUN_1801fa18c`` reads it as ``(short)entry[4]``).

Registration (``FUN_180b60a70``) covers the whole family:

======  ==========================  ==========================================
type    name                        meaning
======  ==========================  ==========================================
0x7f    ``FOP``                     x86 literal code pattern
0x89    ``FOPEX``                   x86 wildcard code pattern
0xc8    ``FOP64``                   x64 literal code pattern
0xc9    ``FOPEX64``                 x64 wildcard code pattern
0xb4    ``VBFOP``                   Visual Basic p-code pattern
0xc7    ``VBFOPEX``                 Visual Basic p-code wildcard pattern
0xba    ``MSILFOP``                 .NET MSIL code pattern
0xc6    ``MSILFOPEX``               .NET MSIL wildcard pattern
======  ==========================  ==========================================

The four contexts live in ``DAT_181114ab0`` (0x138 bytes each).  The matcher
entry point is ``FUN_1801f9ec0`` / ``FUN_1801fa18c``; ``FUN_180b66e50`` selects
``FopScanner::x86_fop_processor`` or ``FopScanner::x64_fop_processor`` (vftables
``0x180c84870`` / ``0x180c84860``) from the record id.  The same table is used by
the KVIR32 page scanner (``FUN_180118728``), the MSIL/VB scanners
(``FUN_1804288a4`` / ``FUN_18058dda4``) and the generic record lookup.

These records are code fingerprints, not file hashes, and the optional name is
the aggregator/feed label (``!#FOP:...``, ``!#FOPEX:...``,
``!#attrmatch_codepatch_EIP_...``).
"""

import struct
from typing import List, Tuple

from .base import BaseSig
from .hstr import decode_hstr_pattern
from .kpat import decode_kpatex_hex, iter_key_pattern_opcodes
from defender2yara.defender.constant import SIG_TYPES


FOP_SIG = "SIGNATURE_TYPE_FOP"
FOPEX_SIG = "SIGNATURE_TYPE_FOPEX"
FOP_SIGS = (FOP_SIG, FOPEX_SIG)

WILDCARD_MARKER = 0x90
PATTERN_TERMINATOR = b"\x90\x00"


def _escape_byte(byte: int) -> str:
    if byte == 0:
        return "\\x00"
    if 0x20 <= byte < 0x7F:
        return chr(byte)
    return f"\\x{byte:02x}"


def _render_literal(data: bytes) -> str:
    return "".join(_escape_byte(byte) for byte in data)


def _render_literal_hex(data: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


def _is_text_like(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(
        1 for byte in data
        if 0x20 <= byte < 0x7F or byte in (0x00, 0x09, 0x0A, 0x0D)
    )
    return printable >= len(data) * 0.85


def _decode_pattern_text(prefix: bytes, body: bytes, suffix: bytes) -> Tuple[str, str]:
    """Render a FOPEX pattern as text; returns ``(text, encoding)``."""
    text = _render_literal(prefix)
    encodings = []
    for block in (body, suffix):
        if not block:
            continue
        block_text, encoding = decode_hstr_pattern(block)
        text += block_text
        encodings.append(encoding)
    if not encodings:
        return text, "binary"
    if "binary" in encodings:
        encoding = "binary"
    elif "utf-16-le" in encodings:
        encoding = "utf-16-le"
    else:
        encoding = "ascii"
    return text, encoding


def _read_name(payload: bytes, offset: int, length: int) -> Tuple[bytes, str]:
    end = offset + length
    if end > len(payload):
        raise ValueError(
            f"Truncated FOP name: {length} bytes at offset {offset}"
        )
    raw = bytes(payload[offset:end])
    if raw and raw[-1] == 0:
        raw = raw[:-1]
    return raw, raw.decode("utf-8", "replace")


class _FopBase(BaseSig):
    """Shared details/summary helpers for the two FOP record types."""

    SIG_TYPE_ID = 0
    layout = "fop"
    SHORT_NAME = "FOP"

    @property
    def name_present(self) -> bool:
        return self.name_length > 0

    def _base_details(self) -> dict:
        return {
            "layout": self.layout,
            "flags": self.flags,
            "name_length": self.name_length,
            "record_name": self.name,
            "has_name": self.name_present,
            "decode_warnings": list(self.decode_warnings),
        }

    def describe(self) -> str:
        text = f"{self.SHORT_NAME} len={len(self.pattern)}"
        if self.name:
            text += f" name={self.name!r}"
        text += f" pattern={self.pattern_hex}"
        return text


class FopSig(_FopBase):
    """``SIGNATURE_TYPE_FOP`` (``0x7f``) - literal file-offset code pattern."""

    SIG_TYPE_ID = 0x7F
    layout = "fop"
    SHORT_NAME = "FOP"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[self.SIG_TYPE_ID]

        payload = self.sig_data
        if len(payload) < 4:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(payload)} bytes"
            )

        self.flags = payload[0]
        self.name_length = payload[1]
        self.pattern_length = struct.unpack_from("<H", payload, 2)[0]
        expected = 4 + self.name_length + self.pattern_length
        if expected > len(payload):
            raise ValueError(
                f"Truncated {self.sig_type} pattern: need "
                f"{self.pattern_length} bytes, have "
                f"{max(0, len(payload) - 4 - self.name_length)}"
            )

        self.name_raw, self.name = _read_name(payload, 4, self.name_length)
        pattern_start = 4 + self.name_length
        self.pattern = bytes(payload[pattern_start:expected])
        self.pattern_hex = _render_literal_hex(self.pattern)
        self.pattern_text = _render_literal(self.pattern)
        self.text_like = _is_text_like(self.pattern)
        self.is_literal = True

        self.decode_warnings: List[str] = []
        if self.flags & ~0x01:
            self.decode_warnings.append(
                f"Unsupported flags 0x{self.flags:02x} (engine only uses bit 0)"
            )
        if expected != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(payload) - expected} bytes"
            )
        if not self.pattern:
            self.decode_warnings.append("Empty code pattern")

    def to_details(self) -> dict:
        details = self._base_details()
        details.update({
            "pattern_length": self.pattern_length,
            "pattern_hex": self.pattern_hex,
            "pattern_text": self.pattern_text,
            "text_like": self.text_like,
            "is_literal": self.is_literal,
            "summary": self.describe(),
        })
        return details


class FopExSig(_FopBase):
    """``SIGNATURE_TYPE_FOPEX`` (``0x89``) - extended file-offset code pattern."""

    SIG_TYPE_ID = 0x89
    layout = "fopex"
    SHORT_NAME = "FOPEX"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[self.SIG_TYPE_ID]

        payload = self.sig_data
        if len(payload) < 10:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(payload)} bytes"
            )

        (self.flags, self.name_length, self.prefix_length,
         self.body_length, self.suffix_length,
         self.offset) = struct.unpack_from("<BBHHHh", payload, 0)
        expected = (
            10 + self.name_length + self.prefix_length
            + self.body_length + self.suffix_length
        )
        if expected > len(payload):
            raise ValueError(
                f"Truncated {self.sig_type} blocks: need "
                f"{self.prefix_length + self.body_length + self.suffix_length} "
                f"pattern bytes, have "
                f"{max(0, len(payload) - 10 - self.name_length)}"
            )

        self.name_raw, self.name = _read_name(payload, 10, self.name_length)
        offset = 10 + self.name_length
        self.prefix = bytes(payload[offset:offset + self.prefix_length])
        offset += self.prefix_length
        self.body = bytes(payload[offset:offset + self.body_length])
        offset += self.body_length
        self.suffix = bytes(payload[offset:offset + self.suffix_length])
        self.pattern = self.prefix + self.body + self.suffix

        self.prefix_hex = _render_literal_hex(self.prefix)
        self.body_hex = decode_kpatex_hex(b"", self.body)
        self.suffix_hex = decode_kpatex_hex(b"", self.suffix)
        self.pattern_hex = " ".join(
            part for part in (self.prefix_hex, self.body_hex, self.suffix_hex)
            if part
        )
        self.pattern_text, self.encoding = _decode_pattern_text(
            self.prefix, self.body, self.suffix
        )
        self.text_like = _is_text_like(self.prefix + self.body + self.suffix)

        self.opcode_counts = {}
        self.wildcard_count = 0
        for block in (self.body, self.suffix):
            for _, opcode, _ in iter_key_pattern_opcodes(block):
                self.opcode_counts[opcode] = (
                    self.opcode_counts.get(opcode, 0) + 1
                )
                if opcode not in (0x00, WILDCARD_MARKER):
                    self.wildcard_count += 1
        self.uses_wildcards = self.wildcard_count > 0

        self.decode_warnings: List[str] = []
        if self.flags & ~0x01:
            self.decode_warnings.append(
                f"Unsupported flags 0x{self.flags:02x} (engine only uses bit 0)"
            )
        if expected != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(payload) - expected} bytes"
            )
        if self.body and not self.body.endswith(PATTERN_TERMINATOR):
            self.decode_warnings.append(
                "Wildcard body does not end with the 0x90 0x00 terminator"
            )

    def to_details(self) -> dict:
        details = self._base_details()
        details.update({
            "prefix_length": self.prefix_length,
            "prefix_hex": self.prefix_hex,
            "body_length": self.body_length,
            "body_hex": self.body_hex,
            "suffix_length": self.suffix_length,
            "suffix_hex": self.suffix_hex,
            "offset": self.offset,
            "pattern_length": len(self.pattern),
            "pattern_hex": self.pattern_hex,
            "pattern_text": self.pattern_text,
            "encoding": self.encoding,
            "text_like": self.text_like,
            "wildcard_count": self.wildcard_count,
            "uses_wildcards": self.uses_wildcards,
            "opcode_counts": {
                f"{opcode:02x}": count
                for opcode, count in sorted(self.opcode_counts.items())
            },
            "summary": self.describe(),
        })
        return details
