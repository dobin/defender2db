import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# The low bits of `flags` select the strong hash appended after the
# common 18-byte STATIC header.
STATIC_HASH_TYPES = {
    0x0001: "md5",
    0x1001: "sha1",
    0x2001: "crc32",
}


class StaticSig(BaseSig):
    """
    SIGNATURE_TYPE_STATIC (0x67).

    Layout (little endian), derived from mpengine + database analysis:

        u32 hash1          partial CRC32
        u32 hash2          partial CRC32
        u32 hash3          partial CRC32 (CRC32 of first min(size, 0x10000) bytes)
        u32 file_size
        u16 flags          0x0001 = MD5, 0x1001 = SHA1, 0x2001 = CRC32
        u8  file_hash[]    16 bytes (MD5), 20 bytes (SHA1) or 4 bytes (CRC32)

    That gives the three observed payload lengths: 22, 34 and 38 bytes.

    hash3 is the engine's "partial CRC 2": it covers the first
    min(file_size, 0x10000) bytes.  The trailing CRC32 (22-byte form) is the
    CRC32 of the whole file, which is why hash3 == file_hash for files of at
    most 64 KiB.  hash1/hash2 are the other partial CRCs (first and last
    windows); their exact windows are not fully confirmed yet.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x67]

        if len(self.sig_data) < 18:
            raise ValueError(
                f"Truncated STATIC signature: {len(self.sig_data)} bytes"
            )

        self.hash1, self.hash2, self.hash3, self.file_size = struct.unpack(
            "<IIII", self.sig_data[0:16]
        )
        self.flags = struct.unpack("<H", self.sig_data[16:18])[0]

        self.hash_type = STATIC_HASH_TYPES.get(self.flags, "unknown")
        self.file_hash = self.sig_data[18:]

        # Convenience typed accessors.
        self.md5 = self.file_hash if self.hash_type == "md5" else None
        self.sha1 = self.file_hash if self.hash_type == "sha1" else None
        self.crc32 = (
            struct.unpack("<I", self.file_hash)[0]
            if self.hash_type == "crc32" and len(self.file_hash) == 4
            else None
        )
