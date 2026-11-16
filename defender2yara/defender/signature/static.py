import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# The high nibble of `flags` selects the strong hash appended after the
# common 18-byte STATIC header.  The low bit (0x0001) is a separate flag.
STATIC_HASH_TYPES = {
    0x0000: "md5",
    0x1000: "sha1",
    0x2000: "crc32",
}

STATIC_HASH_SIZES = {
    "md5": 16,
    "sha1": 20,
    "crc32": 4,
}


class StaticSig(BaseSig):
    """
    SIGNATURE_TYPE_STATIC (0x67).

    Base layout (little endian), derived from mpengine + database analysis:

        u32 hash1          partial CRC32
        u32 hash2          partial CRC32
        u32 hash3          partial CRC32 (CRC32 of first min(size, 0x10000) bytes)
        u32 file_size
        u16 flags          high nibble: 0x0000 = MD5, 0x1000 = SHA1,
                           0x2000 = CRC32; low bit is a separate flag
        u8  file_hash[]    16 bytes (MD5), 20 bytes (SHA1) or 4 bytes (CRC32)

    Newer databases also carry an inline name after the file hash:

        u8  name_length
        u8  name[name_length]

    The name is not NUL-terminated.  Examples are `#Clean`, `#kkrunchy`,
    `#FP:Occamy`, etc.

    The three base hashes are partial CRCs.  hash3 is the engine's
    "partial CRC 2": it covers the first min(file_size, 0x10000) bytes.
    The trailing CRC32 is the CRC32 of the whole file, which is why
    hash3 == file_hash for files of at most 64 KiB.  hash1/hash2 are the other
    partial CRCs (first and last windows); their exact windows are not fully
    confirmed yet.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x67]

        if len(self.sig_data) < 18:
            raise ValueError(
                f"Truncated STATIC signature: {len(self.sig_data)} bytes"
            )

        self.hash1, self.hash2, self.hash3, self.file_size = struct.unpack_from(
            "<IIII", self.sig_data
        )
        self.flags = struct.unpack_from("<H", self.sig_data, 16)[0]

        self.hash_type = STATIC_HASH_TYPES.get(self.flags & 0xF000, "unknown")
        hash_size = STATIC_HASH_SIZES.get(self.hash_type, 0)
        base_size = 18 + hash_size
        self.file_hash = self.sig_data[18:base_size] if hash_size else b""

        # Extended form: one-byte length followed by the name (no NUL).
        self.record_name = None
        self.record_name_raw = b""
        if hash_size and len(self.sig_data) > base_size:
            name_length = self.sig_data[base_size]
            self.record_name_raw = self.sig_data[base_size + 1:base_size + 1 + name_length]
            self.record_name = self.record_name_raw.decode("utf-8", "replace")

        # Convenience typed accessors.
        self.md5 = self.file_hash if self.hash_type == "md5" else None
        self.sha1 = self.file_hash if self.hash_type == "sha1" else None
        self.crc32 = (
            struct.unpack("<I", self.file_hash)[0]
            if self.hash_type == "crc32" and len(self.file_hash) == 4
            else None
        )
