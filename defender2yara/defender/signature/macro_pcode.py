"""SIGNATURE_TYPE_MACRO_PCODE (0x42) and MACRO_PCODE64 (0xcf).

Both types are **macro p-code fingerprints**: the engine hashes the p-code
(final, normalised byte-code) of every VBA module stream and stores up to three
64-bit routine keys per record.  A record is emitted as a detection when the
keys of a module stream match the record.

The ``macro`` module (``FUN_180a50370``) registers the two handlers:

=========  ==========================================================
handler    role
=========  ==========================================================
``0x180432aa0``  ``0x42`` parser: three ``u32`` keys + optional name
``0x180432b10``  ``0xcf`` parser: three ``u64`` keys + optional name
``0x180432b78``  shared record builder (``is_64bit`` flag, name intern)
=========  ==========================================================

Layout::

    u32 key0            0x42 only: CRC-32 of the module p-code stream
    u32 key1            CRC-32 of the "significant" opcode subset
    u32 key2            third slot (unused by the matcher)

    u64 key0            0xcf: crc32 | crc16 << 32 | length << 48
    u64 key1            same for the significant-opcode subset
    u64 key2            third slot (unused by the matcher)

    u8  name[]          optional, NUL terminated (no length prefix)

Every 64-bit key is a *routine key*: the low 32 bits are Defender's CRC-32
(init ``0xffffffff``, no final xor), bits 32..47 are a CRC-16 over the same
bytes (init ``0``), and bits 48..63 count the bytes that were hashed.  The
32-bit form only keeps the CRC-32, so its ``crc16``/``length`` fields are zero
and a key of ``0xffffffff`` means "unset".

``FUN_180432b78`` builds a 0x20-byte in-memory entry from the three keys plus
the record's condition id and the ``is_64bit`` flag, so the on-disk record is
literally the entry minus the condition metadata.
"""

import struct
import zlib

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


MACRO_PCODE_SIGS = (
    "SIGNATURE_TYPE_MACRO_PCODE",
    "SIGNATURE_TYPE_MACRO_PCODE64",
)

#: engine type id -> (key width, fixed payload size before the name)
MACRO_PCODE_FORMS = {
    0x42: (4, 12),
    0xCF: (8, 24),
}

KEY_SLOTS = 3

#: ``0`` and ``0xffffffff`` are the two "slot not used" spellings the engine
#: writes (an untouched 64-bit routine key has crc32 ``0xffffffff`` and a zero
#: length/crc16, an absent slot is stored as zero).
UNSET_KEYS = (0, 0xFFFFFFFF)


def defender_crc32(data: bytes, value: int = 0xFFFFFFFF) -> int:
    """Defender CRC-32 (init ``0xffffffff``, no final xor), continuable."""
    return (zlib.crc32(data, (value & 0xFFFFFFFF) ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def defender_crc16(data: bytes, value: int = 0) -> int:
    """Reflected CRC-16/ARC (poly ``0xa001``, init 0, no final xor)."""
    crc = value & 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def routine_key(data: bytes) -> int:
    """Build the 64-bit ``crc32 | crc16 << 32 | length << 48`` routine key."""
    return (
        defender_crc32(data)
        | (defender_crc16(data) << 32)
        | (min(len(data), 0xFFFF) << 48)
    )


def decode_routine_key(key: int, bits: int) -> dict:
    """Split one raw key into its CRC-32 / CRC-16 / length fields.

    The raw integer is deliberately not part of the projection: 64-bit values
    exceed JavaScript's exact-integer range, so only the hex string and the
    decoded fields are exposed.
    """
    entry = {
        "hex": f"{key:0{bits // 4}x}",
        "crc32": f"{key & 0xFFFFFFFF:08x}",
        "unset": key in UNSET_KEYS,
    }
    if bits == 64:
        entry["crc16"] = f"{(key >> 32) & 0xFFFF:04x}"
        entry["length"] = (key >> 48) & 0xFFFF
    return entry


class MacroPcodeSig(BaseSig):
    """A macro p-code fingerprint: three 64-bit (or 32-bit) routine keys."""

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        if self.sig_type_id not in MACRO_PCODE_FORMS:
            raise ValueError(f"Not a MACRO_PCODE record: {self.sig_type}")
        assert self.sig_type in MACRO_PCODE_SIGS

        self.key_size, base_size = MACRO_PCODE_FORMS[self.sig_type_id]
        self.key_bits = self.key_size * 8
        self.is_64bit = self.key_size == 8
        self.base_size = base_size

        if len(self.sig_data) < base_size:
            raise ValueError(
                f"Truncated {self.sig_type} key table: {len(self.sig_data)} bytes"
            )

        fmt = "<" + ("Q" if self.is_64bit else "I") * KEY_SLOTS
        self.keys = list(struct.unpack_from(fmt, self.sig_data, 0))
        self.key_hex = [f"{key:0{self.key_bits // 4}x}" for key in self.keys]
        self.decoded_keys = [decode_routine_key(key, self.key_bits) for key in self.keys]
        self.key_count = sum(1 for key in self.keys if key not in UNSET_KEYS)

        remainder = self.sig_data[base_size:]
        self.name_raw = b""
        self.name = ""
        self.decode_warnings = []
        if remainder:
            end = remainder.find(b"\x00")
            if end < 0:
                # FUN_180432b78 rejects a record whose name is not terminated.
                self.name_raw = bytes(remainder)
                self.name = remainder.decode("utf-8", "replace")
                self.decode_warnings.append(
                    f"Unterminated {self.sig_type} name ({len(remainder)} bytes)"
                )
            else:
                self.name_raw = bytes(remainder[:end])
                self.name = self.name_raw.decode("utf-8", "replace")
                trailing = remainder[end + 1:]
                if trailing:
                    self.decode_warnings.append(
                        f"Unexpected trailing data after name: {len(trailing)} bytes"
                    )
        self.name_length = len(self.name_raw)

        if not self.key_count:
            self.decode_warnings.append(
                f"{self.sig_type} record has no routine keys"
            )

    @property
    def unset_keys(self) -> list[int]:
        """Indexes of the key slots that are not set."""
        return [i for i, key in enumerate(self.keys) if key in UNSET_KEYS]

    def to_details(self) -> dict:
        return {
            "record_name": self.name,
            "has_name": bool(self.name_length),
            "key_bits": self.key_bits,
            "is_64bit": self.is_64bit,
            "key_count": self.key_count,
            "keys": list(self.key_hex),
            "decoded_keys": [dict(entry) for entry in self.decoded_keys],
            "unset_slots": self.unset_keys,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"MACRO_PCODE{'64' if self.is_64bit else ''} "
            f"keys={'/'.join(self.key_hex)}"
        )
        if self.unset_keys:
            text += f" unset={','.join(str(slot) for slot in self.unset_keys)}"
        if self.name_length:
            text += f" name={self.name!r}"
        return text
