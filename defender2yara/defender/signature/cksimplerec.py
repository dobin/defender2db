"""Checksum-region signatures: CKSIMPLEREC (0x50) and CKOLDREC (0x11).

Both types are produced by the ``cksig`` module (``FUN_180a1d2b0``) and are
simple **checksum-region** detections, not byte patterns.  They were the
classic DOS-era file checks: a handful of CRC-32 windows over known offsets.

CKSIMPLEREC (``0x50``, base payload 20 bytes)::

    u32 file_prefix       first 4 bytes of the file (literal lookup key)
    u32 header_crc        CRC-32 of the first 0x10 bytes
    u16 region_offset
    u16 region_length
    u32 region_crc        CRC-32 of [region_offset, region_offset + region_length)
    u32 flags             bits 26..29 = scan group, low 26 bits = flags
    u8  name_len          optional; length includes the trailing NUL
    u8  name[name_len]    optional; NUL-terminated engine label

CKOLDREC (``0x11``, base payload 20 bytes)::

    u16 region1_offset
    u16 region1_length
    u32 region1_crc       CRC-32 of region 1
    u16 region2_offset
    u16 region2_length
    u32 region2_crc       CRC-32 of region 2
    u32 flags             bits 26..29 = scan group, low 26 bits = flags

The CRC is the engine CRC-32 (init ``0xffffffff``, no final xor), i.e.
``zlib.crc32(data) ^ 0xffffffff``.

Engine anchors (x64 build 1.1.26100.4):

* ``FUN_180a1d2b0`` - ``cksig`` module init; constructs the ``0x24``-byte
  CKSIMPLEREC table (``DAT_181115c88``) and the ``0x1c``-byte CKOLDREC table
  (``DAT_181115428``) through ``FUN_1804eae94``.
* ``FUN_1800fdc68`` - CKSIMPLEREC matcher.  It looks the record up by the first
  four file bytes, verifies ``header_crc`` over ``[0, 0x10)``, then verifies
  ``region_crc`` over the stored offset/length.  On a hit it reports signature
  type ``0x50`` through ``FUN_18015dde0``.
* ``FUN_1800fe028`` - CKOLDREC matcher; same idea with two explicit regions and
  signature type ``0x11``.
* ``FUN_1800fe530`` / ``FUN_1800fe560`` - region CRC-32 over the in-memory
  buffer or through the file reader (``FUN_180676c58``).
* ``FUN_180a1d660`` - converts a hit into a detection/feature.
"""

import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


CKSIMPLEREC_SIG = "SIGNATURE_TYPE_CKSIMPLEREC"
CKOLDREC_SIG = "SIGNATURE_TYPE_CKOLDREC"

HEADER_LENGTH = 0x10
MAX_NAME_LENGTH = 0x3F


def _render_prefix(data: bytes) -> str:
    """Printable rendering of the literal 4-byte file prefix."""
    text = "".join(
        chr(byte) if 0x20 <= byte < 0x7F else "." for byte in data
    )
    return f"{data.hex()} ({text})"


def _flags_fields(flags: int) -> dict:
    return {
        "flags": flags,
        "scan_group": (flags >> 26) & 0xF,
        "flags_low": flags & 0x03FFFFFF,
    }


def _read_name(payload: bytes, offset: int) -> tuple:
    """Read the optional ``u8 length-including-NUL + NUL-terminated name``."""
    if offset == len(payload):
        return b"", "", offset
    if offset > len(payload):
        raise ValueError("Truncated checksum record name")
    length = payload[offset]
    if length > MAX_NAME_LENGTH or length == 0:
        raise ValueError(f"Invalid checksum record name length {length}")
    end = offset + 1 + length
    if end > len(payload):
        raise ValueError("Truncated checksum record name")
    raw = bytes(payload[offset + 1:end])
    if raw and raw[-1] == 0:
        raw = raw[:-1]
    return raw, raw.decode("utf-8", "replace"), end


class _ChecksumRecordSig(BaseSig):
    """Shared details/describe helpers for the two checksum-region types."""

    layout = "checksum_record"

    def _finish(self, base_size: int) -> None:
        self.raw_name, self.name, end = _read_name(self.sig_data, base_size)
        self.name_length = len(self.raw_name)
        self.expected_size = end

        self.decode_warnings = []
        if self.expected_size != len(self.sig_data):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(self.sig_data) - self.expected_size} bytes"
            )

    def _name_details(self) -> dict:
        return {
            "record_name": self.name,
            "has_name": self.name_length > 0,
        }

    def _name_suffix(self) -> str:
        return f" name={self.name!r}" if self.name_length else ""

    def to_details(self) -> dict:
        details = {
            "layout": self.layout,
            **self._name_details(),
            **self.region_details(),
            **self._flags_fields(),
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }
        return details


class CkSimpleRecSig(_ChecksumRecordSig):
    """SIGNATURE_TYPE_CKSIMPLEREC (0x50) — three-check file identifier.

    The first four bytes of the file are used as the primary table key, so the
    field is a literal prefix (DOS ``MZ`` headers show up unchanged, e.g.
    ``4d 5a 20 00``), not a hash.  The record then requires the CRC-32 of the
    first ``0x10`` bytes and the CRC-32 of one explicit region to match.
    """

    layout = "cksimplerec"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x50]

        if len(self.sig_data) < 20:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(self.sig_data)} bytes"
            )

        (self.file_prefix, self.header_crc, self.region_offset,
         self.region_length, self.region_crc, self.flags) = struct.unpack_from(
            "<IIHHII", self.sig_data, 0
        )
        self.file_prefix_raw = bytes(self.sig_data[:4])
        self.file_prefix_hex = self.file_prefix_raw.hex()
        self.file_prefix_text = _render_prefix(self.file_prefix_raw)
        self.flags_low = self.flags & 0x03FFFFFF
        self.scan_group = (self.flags >> 26) & 0xF
        self._finish(20)

    def _flags_fields(self) -> dict:
        return _flags_fields(self.flags)

    def region_details(self) -> dict:
        return {
            "file_prefix_hex": self.file_prefix_hex,
            "file_prefix_text": self.file_prefix_text,
            "header_length": HEADER_LENGTH,
            "header_crc": self.header_crc,
            "region_offset": self.region_offset,
            "region_length": self.region_length,
            "region_crc": self.region_crc,
        }

    def describe(self) -> str:
        text = (
            f"CKSIMPLEREC prefix={self.file_prefix_hex} "
            f"header_crc=0x{self.header_crc:08x} "
            f"region={self.region_offset}+{self.region_length} "
            f"crc=0x{self.region_crc:08x} flags=0x{self.flags:08x}"
        )
        return text + self._name_suffix()


class CkOldRecSig(_ChecksumRecordSig):
    """SIGNATURE_TYPE_CKOLDREC (0x11) — two-region file checksum.

    The runtime table is keyed by ``region1_offset`` (groups 0..0x3f), so the
    first region offset is limited to ``0x3f``.  Both regions carry explicit
    16-bit offset and length fields.
    """

    layout = "ckoldrec"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x11]

        if len(self.sig_data) < 20:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(self.sig_data)} bytes"
            )

        (self.region1_offset, self.region1_length, self.region1_crc,
         self.region2_offset, self.region2_length, self.region2_crc,
         self.flags) = struct.unpack_from("<HHIHHII", self.sig_data, 0)
        self.flags_low = self.flags & 0x03FFFFFF
        self.scan_group = (self.flags >> 26) & 0xF
        self._finish(20)

    def _flags_fields(self) -> dict:
        return _flags_fields(self.flags)

    def region_details(self) -> dict:
        return {
            "region1_offset": self.region1_offset,
            "region1_length": self.region1_length,
            "region1_crc": self.region1_crc,
            "region2_offset": self.region2_offset,
            "region2_length": self.region2_length,
            "region2_crc": self.region2_crc,
        }

    def describe(self) -> str:
        text = (
            f"CKOLDREC region1={self.region1_offset}+{self.region1_length} "
            f"crc=0x{self.region1_crc:08x} "
            f"region2={self.region2_offset}+{self.region2_length} "
            f"crc=0x{self.region2_crc:08x} flags=0x{self.flags:08x}"
        )
        return text + self._name_suffix()
