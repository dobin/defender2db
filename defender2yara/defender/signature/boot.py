"""Boot-image signatures: BOOT (0x44).

``SIGNATURE_TYPE_BOOT`` holds the "boot image" byte patterns used by the
boot-sector / MBR / VBR scans.  It is a **real matchable pattern**, not a hash:
the non-CRC form is a literal prefix followed by bytes where ``0x90`` is a
single-byte wildcard.  The engine keeps the records in a dedicated table
(``DAT_181115d10``, 0x24-byte entries, matcher object tagged ``boot``) built by
the ``BootImgs`` module init ``FUN_180ac2ca0``.

On-disk payload (template ``0x180f39560``, type ``0x544`` = ``0x544 | 0x44``)::

    u8 name_length            0..0x3f (0 = anonymous)
    u8 name[name_length]      definition/feed label, not NUL terminated
    u8 blob[32]

The 32-byte blob has two forms, selected by its first byte:

Normal pattern (``blob[0]`` = pattern length, 4..31)::

    u8 pattern_length
    u8 pattern[31]            only the first pattern_length bytes are significant;
                              the rest is zero padding

The first four pattern bytes are compared as a dword; the remaining
``pattern_length - 4`` bytes are compared byte-wise with ``0x90`` as a
single-byte wildcard (``FUN_18015da40``).

CRC form (``blob[0] == 0x20``)::

    u8  0x20
    u8  0x00
    u8  anchor[8]             literal first eight bytes at the match position
    u16 length                covered region length
    u32 crc32                 Defender CRC-32 of [match, match + length)
    u8  padding[15]

The matcher first matches the 8-byte anchor, then requires
``match + length < buffer_size`` and compares the stored CRC-32 with the
Defender CRC (init ``0xffffffff``, no final xor) of the covered region.

Scan paths (x64 build 1.1.26100.4, see ``cache/functions_vdm.md`` section 22):
``FUN_1800f95a0`` scans every ``0x800``-aligned sector up to ``0x40000`` of a
boot device/MBR/VBR; ``FUN_1800fb080`` adds the boot memory-stealth path and
``FUN_180363558`` the boot verification path (it reports the match offset as
``MpInternal_bootsigoffset=%lld`` / the ``bootsigoffset`` field).  A match is
reported through ``FUN_18015dde0`` with the record's condition id.
"""

from typing import List

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


BOOT_SIG = "SIGNATURE_TYPE_BOOT"

BLOB_SIZE = 32
PATTERN_AREA = 31
CRC_FORM_MARKER = 0x20
ANCHOR_LENGTH = 8
WILDCARD_MARKER = 0x90
MIN_PATTERN_LENGTH = 4


def decode_boot_pattern(pattern: bytes) -> str:
    """Render a normal BOOT pattern as hex, ``??`` for tail wildcards.

    The first four bytes are compared as a dword, so a ``0x90`` in them is a
    literal byte; only bytes from index 4 on use the wildcard semantics.
    """
    tokens = [f"{byte:02x}" for byte in pattern[:MIN_PATTERN_LENGTH]]
    tokens.extend(
        "??" if byte == WILDCARD_MARKER else f"{byte:02x}"
        for byte in pattern[MIN_PATTERN_LENGTH:]
    )
    return " ".join(tokens)


class BootSig(BaseSig):
    """SIGNATURE_TYPE_BOOT (0x44) - boot-sector / MBR / VBR byte pattern.

    ``is_crc_form`` selects the CRC variant: the record then exposes
    ``anchor``, ``covered_length`` and ``crc32`` instead of ``pattern``.  The
    optional ``name`` is a definition label (``!#BOOT:...``, ``!#TEL:...``),
    never a threat name; real-threat records are anonymous.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x44]

        payload = self.sig_data
        if not payload:
            raise ValueError(f"Empty {self.sig_type} payload")
        self.name_length = payload[0]
        if self.name_length > 0x3F:
            raise ValueError(
                f"Invalid {self.sig_type} name length {self.name_length}"
            )
        name_end = 1 + self.name_length
        if name_end + BLOB_SIZE > len(payload):
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(payload)} bytes"
            )
        raw_name = bytes(payload[1:name_end])
        self.name = raw_name.decode("utf-8", "replace")
        self.name_raw = raw_name
        self.blob = bytes(payload[name_end:name_end + BLOB_SIZE])
        self.marker = self.blob[0]

        self.is_crc_form = self.marker == CRC_FORM_MARKER
        self.pattern_length = 0
        self.pattern = b""
        self.pattern_hex = ""
        self.wildcard_count = 0
        self.anchor = b""
        self.covered_length = 0
        self.crc32 = 0
        self.padding = b""

        if self.is_crc_form:
            self.anchor = self.blob[2:2 + ANCHOR_LENGTH]
            self.covered_length = int.from_bytes(self.blob[10:12], "little")
            self.crc32 = int.from_bytes(self.blob[12:16], "little")
            self.padding = self.blob[16:]
        else:
            self.pattern_length = self.marker
            if self.pattern_length < MIN_PATTERN_LENGTH:
                raise ValueError(
                    f"Invalid {self.sig_type} pattern length "
                    f"{self.pattern_length} (smaller than the 4-byte prefix)"
                )
            if self.pattern_length > PATTERN_AREA:
                raise ValueError(
                    f"Invalid {self.sig_type} pattern length "
                    f"{self.pattern_length}"
                )
            self.pattern = self.blob[1:1 + self.pattern_length]
            self.padding = self.blob[1 + self.pattern_length:]
            self.pattern_hex = decode_boot_pattern(self.pattern)
            self.wildcard_count = self.pattern[MIN_PATTERN_LENGTH:].count(
                WILDCARD_MARKER
            )
        self.uses_wildcards = self.wildcard_count > 0

        self.expected_size = name_end + BLOB_SIZE
        self.decode_warnings: List[str] = []
        if self.expected_size != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: "
                f"{len(payload) - self.expected_size} bytes"
            )
        if any(self.padding):
            self.decode_warnings.append("Non-zero padding in the 32-byte blob")
        if self.is_crc_form:
            if self.marker != CRC_FORM_MARKER:
                self.decode_warnings.append("Unexpected CRC-form marker")
            if self.blob[1] != 0:
                self.decode_warnings.append("CRC-form reserved byte is not zero")

    def to_details(self) -> dict:
        return {
            "layout": "boot",
            "record_name": self.name,
            "has_name": self.name_length > 0,
            "is_crc_form": self.is_crc_form,
            "pattern_length": self.pattern_length,
            "pattern_hex": self.pattern_hex,
            "wildcard_count": self.wildcard_count,
            "uses_wildcards": self.uses_wildcards,
            "anchor_hex": self.anchor.hex(),
            "covered_length": self.covered_length,
            "crc32": self.crc32,
            "crc32_hex": f"{self.crc32:08x}",
            "padding_hex": self.padding.hex(),
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        if self.is_crc_form:
            text = (
                f"BOOT crc anchor={self.anchor.hex()} "
                f"length={self.covered_length} crc32=0x{self.crc32:08x}"
            )
        else:
            text = (
                f"BOOT len={self.pattern_length} {self.pattern_hex}"
            )
        if self.name_length:
            text += f" name={self.name!r}"
        return text
