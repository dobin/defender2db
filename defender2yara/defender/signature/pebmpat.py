"""PEB match patterns: ``SIGNATURE_TYPE_PEBMPAT`` (``0x95``).

``PEBMPAT`` is a code-pattern signature used by the emulator/memory scanners
against the process environment block (PEB) and other emulated PE structures.
Despite its name it is the same **pattern language** as ``FOPEX``: a literal
code fragment followed by the shared ``0x90`` wildcard opcodes.  It is *not* a
file hash and does not describe a file offset.

On-disk payload (x64 build 1.1.26100.4, parser ``FUN_1802b0c10``)::

    u8   flags                  bit 0 = hit-class/mode flag
    u8   name_length            0 = anonymous
    u16  pattern_length
    u8   name[name_length]      feed/aggregator label, not NUL terminated
    u8   pattern[pattern_length] code fragment + ``0x90`` wildcard tokens,
                                always ends with ``90 00``

The parser requires ``flags & 0xfe == 0`` and ``4 + name_length +
pattern_length == payload size``.  It also requires at least four literal bytes
before the first ``0x90`` token (and before the first eight pattern bytes), so
the pattern always has a usable multi-pattern anchor.  Every shipped record
ends in ``90 00``.

Registration and matching:

* the type is registered by a static 0x30-byte descriptor at
  ``PTR_FUN_1810d4af0`` (parser ``FUN_1802b0c10``, helper ``FUN_180b60d90``),
  which the ``PEBMPat`` module init ``FUN_1804f4e80`` installs;
* ``FUN_180b60d90`` flushes the matcher and ``FUN_180b60e90`` walks the hit
  list, resolving condition ids to threat names;
* the scan driver is ``FUN_1801176e0``.  It feeds a byte source through the
  multi-pattern matcher, verifies each candidate with ``FUN_1801167ac`` and
  emits hits (flag bit 0 selects the report class).

Database coverage (``cache/threats.db``): 2,711 records.  955 are anonymous
real-threat records (352 threats); 1,756 are named infrastructure records with
1,109 distinct labels (``!#PEBMPAT:...``, ``!#attrmatch_codepatch_EIP_...``,
``!FakeXPA_Obfuscator``).  Pattern lengths are 6..177 bytes, median 33.
"""

import struct
from typing import List

from .base import BaseSig
from .hstr import decode_hstr_pattern
from .kpat import decode_kpatex_hex, iter_key_pattern_opcodes
from .record_id import packed_record_id
from defender2yara.defender.constant import SIG_TYPES


PEBMPAT_SIG = "SIGNATURE_TYPE_PEBMPAT"
PEBMPAT_TYPE_ID = 0x95
WILDCARD_MARKER = 0x90
PATTERN_TERMINATOR = b"\x90\x00"


class PebmPatSig(BaseSig):
    """``SIGNATURE_TYPE_PEBMPAT`` (``0x95``) - PEB/memory code pattern."""

    layout = "pebmpat"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[PEBMPAT_TYPE_ID]

        payload = self.sig_data
        if len(payload) < 4:
            raise ValueError(
                f"Truncated PEBMPAT payload: {len(payload)} bytes"
            )

        self.flags = payload[0]
        self.name_length = payload[1]
        self.pattern_length = struct.unpack_from("<H", payload, 2)[0]
        expected = 4 + self.name_length + self.pattern_length
        if expected > len(payload):
            raise ValueError(
                f"Truncated PEBMPAT pattern: need {self.pattern_length} bytes, "
                f"have {max(0, len(payload) - 4 - self.name_length)}"
            )

        self.name_raw = bytes(payload[4:4 + self.name_length])
        self.name = self.name_raw.decode("utf-8", "replace")
        pattern_start = 4 + self.name_length
        self.pattern = bytes(payload[pattern_start:expected])
        self.pattern_hex = decode_kpatex_hex(b"", self.pattern)
        self.pattern_text, self.encoding = decode_hstr_pattern(self.pattern)
        self.has_name = bool(self.name_raw)

        # The multi-pattern anchor is the literal run before the first 0x90
        # token; the parser rejects patterns with fewer than four literal bytes.
        anchor_end = 0
        while (
            anchor_end < min(8, len(self.pattern))
            and self.pattern[anchor_end] != WILDCARD_MARKER
        ):
            anchor_end += 1
        self.anchor = self.pattern[:anchor_end]
        self.anchor_hex = " ".join(f"{byte:02x}" for byte in self.anchor)

        self.opcode_counts = {}
        self.wildcard_count = 0
        for _, opcode, _ in iter_key_pattern_opcodes(self.pattern):
            self.opcode_counts[opcode] = self.opcode_counts.get(opcode, 0) + 1
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
        if not self.pattern:
            self.decode_warnings.append("Empty code pattern")
        elif not self.pattern.endswith(PATTERN_TERMINATOR):
            self.decode_warnings.append(
                "Pattern does not end with the 0x90 0x00 terminator"
            )
        if len(self.anchor) < 4:
            self.decode_warnings.append(
                "Pattern has fewer than four literal anchor bytes"
            )

        self.packed_record_id = packed_record_id(
            self.normalised_payload(), PEBMPAT_TYPE_ID
        )

    def normalised_payload(self) -> bytes:
        """Payload as hashed by ``FUN_1801836c8`` / ``FUN_180184898``.

        ``FUN_180184898`` strips the inline name for ``0x95`` (same handling as
        ``FOP``), so the record id covers ``flags``, a zero name length, the
        pattern length and the pattern.
        """
        return (
            bytes(self.sig_data[:1])
            + b"\x00"
            + bytes(self.sig_data[2:4])
            + bytes(self.pattern)
        )

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "flags": self.flags,
            "record_name": self.name,
            "has_name": self.has_name,
            "name_length": self.name_length,
            "pattern_length": self.pattern_length,
            "pattern_hex": self.pattern_hex,
            "pattern_text": self.pattern_text,
            "encoding": self.encoding,
            "anchor_hex": self.anchor_hex,
            "wildcard_count": self.wildcard_count,
            "uses_wildcards": self.uses_wildcards,
            "opcode_counts": {
                f"{opcode:02x}": count
                for opcode, count in sorted(self.opcode_counts.items())
            },
            "packed_record_id_hex": f"{self.packed_record_id:016x}",
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = f"PEBMPAT anchor={self.anchor_hex} len={self.pattern_length}"
        if self.name:
            text += f" name={self.name!r}"
        text += f" pattern={self.pattern_hex}"
        return text
