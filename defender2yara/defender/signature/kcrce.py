import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


class KcrceSig(BaseSig):
    """
    SIGNATURE_TYPE_KCRCE (0x80).

    Base layout (16 bytes, little endian), derived from mpengine + database
    analysis:

        u32 crc1
        u32 crc2
        u32 crc3
        u16 region        window size / anchor offset (0x1000 and 0x400 dominate)
        u16 flags         observed 0x0000, 0x8000, 0xc000

    Newer databases also carry an inline name after the base record:

        u8  name_length
        u8  name[name_length]

    The name is not NUL-terminated.  It is used for named KCRCE records such as
    `!#KCRC:Emotet.A42`.

    The three values at +0 are full-entropy 32-bit CRC32s.  mpengine stores
    four related values per file in its FileHashes table (KCRC1, KCRC2, KCRC3,
    KCRC3n); it computes them over 0x20 bytes, the first 0x100, 0x400 and
    0x1000 bytes of a section.  A KCRCE record only keeps three of them plus
    the small region/flags word, which makes it a compact "known file" CRC
    fast-path signature rather than a byte pattern.

    `region` is believed to be the size or the start offset of the hashed
    region.  Values 0xffc0 (-0x40) and 0xffff (-1) show up, which is why it is
    also consistent with an offset relative to EOF (mpengine has a
    `kcrce_scanfilelast` code path).  The precise meaning of the flag bits is
    not confirmed yet.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x80]

        if len(self.sig_data) < 16:
            raise ValueError(
                f"Truncated KCRCE signature: {len(self.sig_data)} bytes"
            )

        self.crc1, self.crc2, self.crc3, self.region, self.flags = struct.unpack_from(
            "<IIIHH", self.sig_data
        )

        # Extended form: one-byte length followed by the name (no NUL).
        self.record_name = None
        self.record_name_raw = b""
        if len(self.sig_data) > 16:
            name_length = self.sig_data[16]
            self.record_name_raw = self.sig_data[17:17 + name_length]
            self.record_name = self.record_name_raw.decode("utf-8", "replace")
