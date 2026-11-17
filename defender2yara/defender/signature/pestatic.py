import struct
import zlib

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# The static PE scanner fingerprints PE regions — normally a section's raw
# data, but also 0x1000-aligned regions of unpacked buffers and custom PE
# objects — with three CRC-32 windows (``FUN_180242d2c`` / ``FUN_18024368c``):
#
#   0x40   head of the region (cheap early reject)
#   0x200  larger prefix window
#   N      first N bytes of the region, N taken from the record
#
# The engine CRC-32 has init 0xffffffff and no final xor (``FUN_180676c58``).
SECTION_HEAD_SIZE = 0x40
SECTION_PREFIX_SIZE = 0x200

# Length words above this value only appear on 23 ``!#ALF`` feed records and
# look like flag bits in the top two bits rather than a real window length.
IMPLAUSIBLE_WINDOW_LIMIT = 0x40000000

# Record ids are ``crc32(payload) | sig_type << 32 | payload_size << 40``
# (see ``FUN_180b5589c`` / ``FUN_180b558fc``).
RECORD_ID_SIG_TYPE_SHIFT = 32
RECORD_ID_SIZE_SHIFT = 40

PESTATIC_SIGS = [
    "SIGNATURE_TYPE_PESTATIC",
    "SIGNATURE_TYPE_PESTATICEX",
]


def defender_crc32(data: bytes) -> int:
    """CRC-32 as used by mpengine: reflected, init 0xffffffff, no final xor."""
    return zlib.crc32(data) & 0xFFFFFFFF ^ 0xFFFFFFFF


def _packed_record_id(payload: bytes, sig_type_id: int) -> int:
    return (
        defender_crc32(payload)
        | sig_type_id << RECORD_ID_SIG_TYPE_SHIFT
        | len(payload) << RECORD_ID_SIZE_SHIFT
    )


class PestaticSig(BaseSig):
    """
    SIGNATURE_TYPE_PESTATIC (0x87) and PESTATICEX (0xcb).

    Both types belong to the ``pestatic`` module (``FUN_180b56870``) and are
    **PE region fingerprints**, not byte patterns.  The module keeps two
    containers per type (``0x87``/``0x187`` and ``0xcb``/``0x1cb``); the
    ``0x100`` bit is an internal table selector, only the base byte is written
    to the VDM.

    PESTATIC (0x87), 16 bytes::

        u32 crc_head     CRC32 of the first 0x40 bytes of the region
        u32 crc_prefix   CRC32 of the first 0x200 bytes of the region
        u32 crc_region   CRC32 of the first ``hashed_length`` bytes
        u32 hashed_length

    PESTATICEX (0xcb), 32 bytes::

        u32 crc_head     CRC32 of the first 0x40 bytes of the region
        u32 crc_prefix   CRC32 of the first 0x200 bytes of the region
        u8  md5[16]      MD5 of ``hashed_length`` bytes at ``hashed_offset``
        u32 hashed_length
        u32 hashed_offset

    Both forms may be followed by ``u8 name_length`` and a non NUL-terminated
    name.  In the shipped database only PESTATIC records are named
    (1,579 records, all in ``!InfrastructureShared``), e.g.
    ``!#ESRP:PEStatic:iobios64.sys``, ``!#SLF:ProcessInjector.BTP`` and
    ``!#TEL:VulnerableDriver:Win32/BootRepairDriver``.  The names are engine
    directives/exclusions, not threat names.

    Matching (``FUN_180243960`` -> ``FUN_180243844`` -> ``FUN_1802429a4`` ->
    ``FUN_180242e30`` / ``FUN_18024368c``) walks:

    * every PE section whose raw size is greater than 0x1ff,
    * every 0x1000-aligned region of an unpacked/generated buffer
      (``FUN_180240ff0``),
    * custom PE sub-objects such as resource/version data
      (``FUN_180a626b0``),

    and compares the three windows, followed by the MD5 region for the
    extended form.  The region type/index is not stored in the record: a record
    can only match a region whose bytes produce these exact CRCs.  PESTATIC is
    therefore the same class of detection as STATIC — file/region reputation,
    used for vulnerable drivers, clean-file lists and exclusions — and cannot
    be expressed as a YARA string pattern.

    ``SIGNATURE_TYPE_PESTATIC`` has 593,613 records in the shipped database;
    ``SIGNATURE_TYPE_PESTATICEX`` has none.  When ``hashed_length`` is 0x200
    the region CRC equals ``crc_prefix`` (83,105 of 83,105 records), which
    confirms the window order used above.  7 records have a window below 0x200
    (they target unpacked-buffer/custom regions, not sections) and 23 ``!#ALF``
    feed records store implausible windows with the top bits set.
    """

    SIG_TYPE_IDS = (0x87, 0xCB)
    BASE_SIZES = {0x87: 16, 0xCB: 32}

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type in PESTATIC_SIGS

        base_size = self.BASE_SIZES[self.sig_type_id]
        if len(self.sig_data) < base_size:
            raise ValueError(
                f"Truncated {self.sig_type} signature: {len(self.sig_data)} bytes"
            )

        self.crc_head = struct.unpack_from("<I", self.sig_data, 0)[0]
        self.crc_prefix = struct.unpack_from("<I", self.sig_data, 4)[0]
        self.md5 = None
        self.md5_hex = None
        if self.sig_type_id == 0x87:
            self.crc_section, self.hashed_length = struct.unpack_from(
                "<II", self.sig_data, 8
            )
            self.hashed_offset = None
            base_size = 16
        else:
            self.md5 = self.sig_data[8:24]
            self.md5_hex = self.md5.hex()
            self.hashed_length, self.hashed_offset = struct.unpack_from(
                "<II", self.sig_data, 24
            )
            # The MD5 covers this window; there is no rolling section CRC.
            self.crc_section = None
            base_size = 32

        self.decode_warnings = []
        if self.sig_type_id == 0x87 and self.hashed_length < SECTION_HEAD_SIZE:
            self.decode_warnings.append(
                "Region hash window is shorter than the 0x40 head window"
            )
        if self.hashed_length > IMPLAUSIBLE_WINDOW_LIMIT:
            self.decode_warnings.append(
                "Implausible PESTATIC window length (top flag bits set?)"
            )
        if self.sig_type_id == 0xCB and self.hashed_length == 0:
            self.decode_warnings.append("PESTATICEX MD5 window is empty")

        # Extended form: one-byte length followed by the name (no NUL).
        self.record_name = None
        self.record_name_raw = b""
        if len(self.sig_data) > base_size:
            name_length = self.sig_data[base_size]
            self.record_name_raw = self.sig_data[base_size + 1:base_size + 1 + name_length]
            self.record_name = self.record_name_raw.decode("utf-8", "replace")
            if len(self.record_name_raw) < name_length:
                self.decode_warnings.append("Truncated PESTATIC record name")

        self.base_size = base_size
        self.packed_record_id = _packed_record_id(
            self.sig_data[:base_size], self.sig_type_id
        )

    def to_details(self) -> dict:
        return {
            "decode_warnings": list(self.decode_warnings),
            "crc_head": self.crc_head,
            "crc_prefix": self.crc_prefix,
            "crc_section": self.crc_section,
            "md5_hex": self.md5_hex,
            "hashed_length": self.hashed_length,
            "hashed_offset": self.hashed_offset,
            "record_name": self.record_name,
            "packed_record_id_hex": f"{self.packed_record_id:016x}",
            "is_extended_form": self.sig_type_id == 0xCB,
            "summary": self.describe(),
        }

    @property
    def section_crc_equals_prefix(self) -> bool:
        """The section window is exactly the 0x200 prefix window."""
        return (
            self.crc_section is not None
            and self.hashed_length == SECTION_PREFIX_SIZE
            and self.crc_section == self.crc_prefix
        )

    def describe(self) -> str:
        text = (
            f"{self.sig_type} crc_head=0x{self.crc_head:08x} "
            f"crc_prefix=0x{self.crc_prefix:08x}"
        )
        if self.crc_section is not None:
            text += f" crc_section=0x{self.crc_section:08x} length={self.hashed_length}"
        else:
            text += f" md5={self.md5_hex} offset={self.hashed_offset} length={self.hashed_length}"
        if self.record_name:
            text += f" name={self.record_name!r}"
        return text
