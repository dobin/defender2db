"""Polymorphic-virus fingerprints: ``SIGNATURE_TYPE_POLYVIR32`` (``0x21``).

``POLYVIR32`` is a legacy **code fingerprint** for polymorphic 32-bit viruses.
It is not a file hash and not a plain byte pattern: a record stores a 16-byte
literal code fragment plus the CRC-32 of two windows that start at fixed
offsets **relative to that fragment**.  The matcher searches for the fragment
and then verifies the two surrounding/decrypted windows, which lets one record
match a whole family of differently encrypted variants.

The record type is registered as a generic template table by the HSTR module
init ``FUN_180a1f948`` (``FUN_1804eae94(&DAT_181113a98, 0x28, 0x12,
&DAT_180f07470, ..., 0x421)``).  The ``0x421`` type selects the per-type
template context for ``0x21``; the template ``0x180f07470`` is::

    0x2010 @ 0x00    copy 16 bytes        -> 16-byte literal code anchor
    0x1001 @ 0x10    read u16             -> window 1 offset
    0x1001 @ 0x12    read u16             -> window 1 length
    0x1000 @ 0x14    read u32             -> window 1 CRC-32
    0x1001 @ 0x18    read u16             -> window 2 offset
    0x1001 @ 0x1a    read u16             -> window 2 length
    0x1000 @ 0x1c    read u32             -> window 2 CRC-32
    0x1009 @ 0x24    read u16 + data      -> optional extra blob (0 in this DB)
    0x1016 @ 0x20    condition id + name  -> trailing optional name

so the on-disk payload is::

    u8  anchor[16]          literal code fragment
    u16 window1_offset      relative to the anchor start
    u16 window1_length
    u32 window1_crc         Defender CRC-32 (init 0xffffffff, no final xor)
    u16 window2_offset
    u16 window2_length
    u32 window2_crc
    u16 extra_length        optional extra blob length (always 0 here)
    u8  extra[extra_length]
    ...                     optional name (none in this DB)

All 151 shipped records are exactly 34 bytes, so the optional blob/name are
absent.  Window offsets are small (mostly 0x10/0x20/0x30) and window lengths
0x10/0x20/0x30, i.e. the windows cover code immediately around the anchor.

Matching (``FUN_180047590``, the generic multi-pattern matcher): it compares
the 16-byte anchor ending at the current match position, then with
``base = match_position - 15`` and the scanned buffer ``buf``:

* require ``window1_offset + window1_length + base <= size`` and
  ``FUN_180676c58(buf + base + window1_offset, window1_length) == window1_crc``;
* if the condition has a special EUS name (`FUN_18015fe38` returns non-zero)
  it reports via `FUN_180154640`; otherwise require the same for window 2
  (`window2_offset + window2_length + base <= size` and the second CRC) and
  report the condition id stored at entry `+0x20`.

Database coverage (``cache/threats.db``): 151 records, 148 threats, all
anonymous (legacy DOS/Win32 families: Godog, Bofra, Bugbear, Bagle, ASK, CTX,
Leviathan, Hybris, Magistr, ...).  133 distinct anchors.  The owner name is
the only label.
"""

import struct
from typing import List, Optional, Tuple

from .base import BaseSig
from .record_id import packed_record_id
from defender2yara.defender.constant import SIG_TYPES


POLYVIR32_SIG = "SIGNATURE_TYPE_POLYVIR32"
POLYVIR32_TYPE_ID = 0x21
ANCHOR_SIZE = 16
BASE_SIZE = ANCHOR_SIZE + 2 + 2 + 4 + 2 + 2 + 4 + 2  # 34 bytes


def _render_text(data: bytes) -> str:
    out = []
    for byte in data:
        if byte == 0:
            out.append("\\x00")
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


class Polyvir32Sig(BaseSig):
    """``SIGNATURE_TYPE_POLYVIR32`` (``0x21``) - two-window code fingerprint."""

    layout = "polyvir32"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[POLYVIR32_TYPE_ID]

        payload = self.sig_data
        if len(payload) < BASE_SIZE:
            raise ValueError(
                f"Truncated POLYVIR32 payload: {len(payload)} bytes "
                f"(need {BASE_SIZE})"
            )

        self.anchor = bytes(payload[:ANCHOR_SIZE])
        (
            self.window1_offset,
            self.window1_length,
            self.window1_crc,
            self.window2_offset,
            self.window2_length,
            self.window2_crc,
            self.extra_length,
        ) = struct.unpack_from("<HHIHHIH", payload, ANCHOR_SIZE)

        consumed = BASE_SIZE + self.extra_length
        if consumed > len(payload):
            raise ValueError(
                f"Truncated POLYVIR32 extra blob: need {self.extra_length} "
                f"bytes, have {max(0, len(payload) - BASE_SIZE)}"
            )
        self.extra = bytes(payload[BASE_SIZE:consumed])
        self.record_name: Optional[str] = None
        self.name_raw = b""
        if consumed < len(payload):
            # The template's 0x1016 field is a u8 length followed by the name.
            name_length = payload[consumed]
            name_end = consumed + 1 + name_length
            if name_end > len(payload):
                raise ValueError(
                    f"Truncated POLYVIR32 name: {name_length} bytes at offset "
                    f"{consumed}"
                )
            self.name_raw = bytes(payload[consumed + 1:name_end])
            self.record_name = self.name_raw.decode("utf-8", "replace")
            consumed = name_end

        self.window1_end = self.window1_offset + self.window1_length
        self.window2_end = self.window2_offset + self.window2_length
        self.anchor_hex = " ".join(f"{byte:02x}" for byte in self.anchor)
        self.anchor_text = _render_text(self.anchor)
        self.anchor_text_like = sum(
            1 for byte in self.anchor
            if 0x20 <= byte < 0x7F or byte in (0x00, 0x09, 0x0A, 0x0D)
        ) >= len(self.anchor) * 0.75

        self.decode_warnings: List[str] = []
        if consumed != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(payload) - consumed} bytes"
            )
        if self.window1_length == 0:
            self.decode_warnings.append("Window 1 is empty")
        if self.window2_length == 0:
            self.decode_warnings.append("Window 2 is empty")
        if self.extra_length:
            self.decode_warnings.append(
                f"Optional extra blob present: {self.extra_length} bytes"
            )
        if self.record_name is not None and not self.record_name:
            self.decode_warnings.append("Empty record name")

        self.packed_record_id = packed_record_id(
            bytes(self.sig_data[:BASE_SIZE]), POLYVIR32_TYPE_ID
        )

    def window(self, index: int) -> Tuple[int, int, int]:
        """Return ``(offset, length, crc)`` for window 1 or 2."""
        if index == 1:
            return self.window1_offset, self.window1_length, self.window1_crc
        if index == 2:
            return self.window2_offset, self.window2_length, self.window2_crc
        raise ValueError("window index must be 1 or 2")

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "anchor_hex": self.anchor_hex,
            "anchor_text": self.anchor_text,
            "anchor_text_like": self.anchor_text_like,
            "window1_offset": self.window1_offset,
            "window1_length": self.window1_length,
            "window1_end": self.window1_end,
            "window1_crc_hex": f"{self.window1_crc:08x}",
            "window2_offset": self.window2_offset,
            "window2_length": self.window2_length,
            "window2_end": self.window2_end,
            "window2_crc_hex": f"{self.window2_crc:08x}",
            "extra_length": self.extra_length,
            "record_name": self.record_name,
            "has_name": self.record_name is not None,
            "packed_record_id_hex": f"{self.packed_record_id:016x}",
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"POLYVIR32 anchor={self.anchor_hex} "
            f"w1=[{self.window1_offset},{self.window1_end})"
            f"=0x{self.window1_crc:08x} "
            f"w2=[{self.window2_offset},{self.window2_end})"
            f"=0x{self.window2_crc:08x}"
        )
        if self.record_name:
            text += f" name={self.record_name!r}"
        return text
