"""Legacy page/virus signature: ``SIGNATURE_TYPE_KVIR32`` (0x20).

``KVIR32`` is one of Defender's oldest record types.  Despite the name it is
not tied to a single virus family: the shipped database uses it for
entry-point / packer fingerprints (``!UPX_1_X``, ``!ASProtect``, ``!Themida``,
``!FSG`` ...), PE-emulator code-patch conditions
(``!#attrmatch_codepatch_EIP_...``) and legacy file-infector detections.  It
is a two-window CRC fingerprint, not a byte pattern.

On-disk payload::

    u32 anchor_crc      CRC-32 of 16 bytes at page offset 16 * anchor_window
    u32 body_crc        CRC-32 of body_length bytes at body_offset
    u16 body_offset     offset inside the 4 KiB scan page
    u16 body_length     number of bytes covered by body_crc
    u16 anchor_window   0, 1 or 2 -> anchor is at page offset 0, 16 or 32
    i16 flags           0 = report; negative (0x8000) = do not report
    u8  name_length     optional; absent means anonymous
    u8  name[name_length]  definition label, not NUL terminated

All CRCs are the engine CRC-32 (reflected, init ``0xffffffff``, no final xor;
``FUN_180676c58``).  The 16-byte anchor is the key: the scanner computes the
CRC of the 16-byte windows at page offsets 0, 16 and 32 (``FUN_180118728``),
binary-searches the record table (``FUN_18011804c``), checks that the stored
``anchor_window`` equals the window that matched, and finally verifies
``body_crc`` over ``[body_offset, body_offset + body_length)``
(``FUN_1804a4c5c``).  A negative ``flags`` value skips the detection report;
those records only feed the emulator/repair logic.

Engine notes (x64 build 1.1.26100.4; see ``cache/functions_vdm.md`` section
21):

* ``FUN_18057b57c`` - re-serialises an in-memory entry into the 16-byte
  payload.
* ``FUN_18057f55c`` - packed record id: ``crc32(16-byte payload)
  | 0x20 << 32 | 0x10 << 40``.  The optional name is not part of the id.
* ``FUN_180118728`` - page scan driver: for each mapped page it tries up to
  four 16-byte anchors at offsets ``page + 16 * i``.
* ``FUN_18011804c`` - record lookup plus bloom filter, then verification.
* ``FUN_1804a4c5c`` - per-record verifier: anchor CRC / anchor window /
  body CRC (``FUN_180676c58`` over the mapped body window).

Database coverage (``cache/threats.db``): 6,595 records - 5,369 in real
threats (2,704 threats) and 1,226 in ``!InfrastructureShared`` (680 distinct
labels); 6,239 records have ``body_offset == 16 * anchor_window``.
"""

import struct
from typing import Optional

from .base import BaseSig
from .record_id import packed_record_id
from defender2yara.defender.constant import SIG_TYPES


KVIR32_SIG = "SIGNATURE_TYPE_KVIR32"
KVIR32_TYPE_ID = 0x20
KVIR32_BASE_SIZE = 16
ANCHOR_SIZE = 16
# The page scanner tries anchors at 0, 16, 32 (and, when the whole 4 KiB page
# is available, a fourth at 48).
MAX_ANCHOR_WINDOW = 3


class Kvir32Sig(BaseSig):
    """SIGNATURE_TYPE_KVIR32 (0x20) - two-window CRC page fingerprint."""

    layout = "kvir32"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[KVIR32_TYPE_ID]

        payload = self.sig_data
        if len(payload) < KVIR32_BASE_SIZE:
            raise ValueError(
                f"Truncated KVIR32 signature: {len(payload)} bytes "
                f"(need {KVIR32_BASE_SIZE})"
            )

        (
            self.anchor_crc,
            self.body_crc,
            self.body_offset,
            self.body_length,
            self.anchor_window,
            flags_raw,
        ) = struct.unpack_from("<IIHHHh", payload)

        self.flags = flags_raw
        self.flags_unsigned = flags_raw & 0xFFFF
        self.reports_detection = self.flags >= 0
        self.anchor_offset = self.anchor_window * ANCHOR_SIZE
        self.body_end = self.body_offset + self.body_length
        self.anchor_matches_body_start = self.anchor_offset == self.body_offset

        self.decode_warnings = []
        if self.body_length == 0:
            self.decode_warnings.append("Body window is empty")
        if self.anchor_window > MAX_ANCHOR_WINDOW:
            self.decode_warnings.append(
                f"Anchor window {self.anchor_window} is never scanned"
            )
        if self.body_offset == 0 and self.body_length > 0x4000:
            self.decode_warnings.append("Implausible body window length")

        self.record_name: Optional[str] = None
        self.record_name_raw = b""
        consumed = KVIR32_BASE_SIZE
        if len(payload) > KVIR32_BASE_SIZE:
            name_length = payload[KVIR32_BASE_SIZE]
            name_end = KVIR32_BASE_SIZE + 1 + name_length
            if name_end > len(payload):
                self.decode_warnings.append(
                    f"Truncated KVIR32 name: {name_length} bytes at offset "
                    f"{KVIR32_BASE_SIZE}"
                )
                name_end = len(payload)
            self.record_name_raw = bytes(payload[KVIR32_BASE_SIZE + 1:name_end])
            self.record_name = self.record_name_raw.decode("utf-8", "replace")
            consumed = name_end
        self.has_name = bool(self.record_name_raw)
        if consumed != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(payload) - consumed} bytes"
            )

        # The name is stored outside the id payload; the id covers 16 bytes.
        self.packed_record_id = packed_record_id(
            payload[:KVIR32_BASE_SIZE], KVIR32_TYPE_ID
        )

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "record_name": self.record_name,
            "has_name": self.has_name,
            "anchor_crc": self.anchor_crc,
            "anchor_crc_hex": f"{self.anchor_crc:08x}",
            "body_crc": self.body_crc,
            "body_crc_hex": f"{self.body_crc:08x}",
            "body_offset": self.body_offset,
            "body_length": self.body_length,
            "body_end": self.body_end,
            "anchor_window": self.anchor_window,
            "anchor_offset": self.anchor_offset,
            "flags": self.flags_unsigned,
            "reports_detection": self.reports_detection,
            "anchor_matches_body_start": self.anchor_matches_body_start,
            "packed_record_id_hex": f"{self.packed_record_id:016x}",
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"KVIR32 anchor=0x{self.anchor_crc:08x}"
            f"@{self.anchor_offset} body=0x{self.body_crc:08x}"
            f"[{self.body_offset},{self.body_end})"
        )
        if not self.reports_detection:
            text += " flags=0x%04x (no report)" % self.flags_unsigned
        if self.record_name:
            text += f" name={self.record_name!r}"
        return text
