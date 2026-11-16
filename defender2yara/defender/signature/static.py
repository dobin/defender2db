import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# `flags` (u16 at +0x10):
#   bits 12..14  strong-hash algorithm selector
#   bit  0       `file_size` is a lower bound (prefix/truncated match)
#
# mpengine selects the trailing hash length from bits 29..31 of its internal
# flags dword and copies those bits into the high nibble of the serialised
# flags word (`FUN_180210dd8`).
STATIC_HASH_TYPES = {
    0x0000: "md5",
    0x1000: "sha1",
    0x2000: "crc32",
    0x3000: "sha1_32",
    0x4000: "sha256",
}

STATIC_HASH_SIZES = {
    "md5": 16,
    "sha1": 20,
    "crc32": 4,
    "sha1_32": 4,
    "sha256": 32,
}


class StaticSig(BaseSig):
    """
    SIGNATURE_TYPE_STATIC (0x67).

    Base layout (little endian), derived from mpengine + database analysis:

        u32 hash1          partial CRC1 of the first 0x1000 bytes
        u32 hash2          partial CRC3 of the last 0x1000 bytes
        u32 hash3          partial CRC2 of the first min(size, 0x10000) bytes
        u32 file_size
        u16 flags          0x0001 = prefix/truncated match, bits 12..14 = algo
        u8  file_hash[]    16 bytes (MD5), 20 (SHA1), 4 (CRC32 / SHA1[:4])
                           or 32 (SHA256)

    Newer databases also carry an inline name/tag after the file hash:

        u8  name_length
        u8  name[name_length]

    The name is not NUL-terminated.  Examples are ``#Clean``, ``#ClnFile:30``,
    ``#ExpensiveFile``, ``#CFG:A:ClnFile``, ``#PUA:Win32/Creprote`` and
    ``!#ALF:...``.

    Field order is worth noting: the on-disk order is partial CRC1, partial
    CRC3, partial CRC2 (mpengine's ``FUN_180213c60`` compares ``hash3`` first,
    then ``hash2``, and ``FUN_18028c670`` looks records up by ``hash1``).

    Window definitions (engine CRC-32, see ``FUN_180676c58``; zero padded for
    short files):

    * ``hash1`` = CRC32 of the first ``min(size, 0x1000)`` bytes, then zero
      padded to 0x1000.
    * ``hash2`` = CRC32 of the last ``0x1000`` bytes of the first ``size``
      bytes (zero padded at the front when ``size < 0x1000``).
    * ``hash3`` = CRC32 of the first ``min(size, 0x10000)`` bytes.

    For CRC32 signatures ``hash3`` therefore equals the trailing full-file CRC
    exactly when ``size <= 0x10000``.  When all three windows describe the same
    0x1000 bytes (``size == 0x1000``) the three hashes are identical.

    If ``flags & 0x0001`` is clear the record only matches a file whose size is
    exactly ``file_size``.  If set, the size check becomes ``size <= file_size``
    and the trailing strong hash covers only the first ``file_size`` bytes, so
    the record matches a prefix of a longer file.
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

        # Engine names / semantics for the three partial CRCs.
        self.partial_crc1 = self.hash1
        self.partial_crc3 = self.hash2
        self.partial_crc2 = self.hash3
        self.prefix_match = bool(self.flags & 0x0001)

        self.hash_type = STATIC_HASH_TYPES.get(self.flags & 0xF000, "unknown")
        hash_size = STATIC_HASH_SIZES.get(self.hash_type, 0)
        base_size = 18 + hash_size
        self.file_hash = self.sig_data[18:base_size] if hash_size else b""

        # Extended form: one-byte length followed by the name/tag (no NUL).
        self.record_name = None
        self.record_name_raw = b""
        if hash_size and len(self.sig_data) > base_size:
            name_length = self.sig_data[base_size]
            self.record_name_raw = self.sig_data[base_size + 1:base_size + 1 + name_length]
            self.record_name = self.record_name_raw.decode("utf-8", "replace")

        # Convenience typed accessors.
        self.md5 = self.file_hash if self.hash_type == "md5" else None
        self.sha1 = self.file_hash if self.hash_type == "sha1" else None
        self.sha256 = self.file_hash if self.hash_type == "sha256" else None
        self.sha1_32 = (
            struct.unpack("<I", self.file_hash)[0]
            if self.hash_type == "sha1_32" and len(self.file_hash) == 4
            else None
        )
        self.crc32 = (
            struct.unpack("<I", self.file_hash)[0]
            if self.hash_type == "crc32" and len(self.file_hash) == 4
            else None
        )
