from typing import Tuple,List
import struct
from .base import BaseSig
from defender2yara.defender.subrule.hstr import HStrSubRule, HStrExtSubRule
from defender2yara.defender.constant import SIG_TYPES


HSTR_EXT_SIGS = [
    "SIGNATURE_TYPE_PEHSTR_EXT",
    "SIGNATURE_TYPE_ELFHSTR_EXT",
    "SIGNATURE_TYPE_MACHOHSTR_EXT",
    "SIGNATURE_TYPE_DOSHSTR_EXT",
    "SIGNATURE_TYPE_MACROHSTR_EXT",
    "SIGNATURE_TYPE_DEXHSTR_EXT",
    "SIGNATURE_TYPE_JAVAHSTR_EXT",
    "SIGNATURE_TYPE_ARHSTR_EXT",
    "SIGNATURE_TYPE_SWFHSTR_EXT",
    "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    "SIGNATURE_TYPE_INNOHSTR_EXT",
    "SIGNATURE_TYPE_CMDHSTR_EXT",
    "SIGNATURE_TYPE_MDBHSTR_EXT",
    "SIGNATURE_TYPE_DMGHSTR_EXT"
]


class HStrSig(BaseSig):
    def to_details(self) -> dict:
        return {
            "unknown_u16_1": self.unknown_u16_1,
            "threshold": self.threshold,
            "rule_numbers": self.rule_numbers,
            "unknown_u8_1": self.unknown_u8_1,
            "decode_warnings": list(self.decode_warnings),
            "subrules": [rule.to_details() for rule in self.subrules],
        }

    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type == SIG_TYPES[0x61]

        # parse signature data header
        self.unknown_u16_1 = struct.unpack('<H',self.sig_data[0:2])[0]
        self.threshold = struct.unpack('<H',self.sig_data[2:4])[0]
        self.rule_numbers = struct.unpack('<H',self.sig_data[4:6])[0]
        self.unknown_u8_1 = self.sig_data[6]

        # parse subrules
        self.decode_warnings = []
        self.subrules = []
        pos = 7
        while pos < len(self.sig_data):
            subrule = HStrSubRule(self.sig_data,pos)
            # no more subrule
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            pos += 3 + subrule.rule_size
            if pos > len(self.sig_data):
                self.decode_warnings.append("Truncated HSTR subrule pattern")
        if self.rule_numbers and len(self.subrules) < self.rule_numbers:
            self.decode_warnings.append("Fewer HSTR subrules than declared")


class HStrExtSig(BaseSig):
    """
    Generic ``*HSTR_EXT`` signature (0x78, 0x8c, 0x8d, 0x8e, 0x8f, 0xbe, ...).

    Layout, confirmed against every ``*HSTR_EXT`` record in the shipped
    database and against the mpengine sub-rule parser::

        u16  unknown
        u16  threshold       minimum total weight of the matching sub-rules
        u16  rule_numbers    number of sub-rules that follow
        u8   name[]          NUL-terminated label / definition name
        sub-rule[rule_numbers]:
            i16  weight
            u8   size
            u8   flags       (0x80/0x81/0x88/0x90 add one extra length byte)
            u8   bytes[size]
        u16  end_marker       normally 0x0000
        u16  flags            optional; present in ~4% of records

    The byte at offset 6 is *not* a reserved byte: it is the first byte of a
    NUL-terminated name string.  In compiled records the name is empty, so the
    byte is simply ``0x00`` and the sub-rules start at offset 7.  In
    ``!InfrastructureShared`` records the field holds the definition/name
    reference, e.g. ``!#HSTR:StringCodeForMshta.A!pli``; the sub-rules still
    follow the NUL.

    Bounding the sub-rule loop with ``rule_numbers`` (instead of scanning for
    a zero weight) keeps several malformed-looking records from overrunning
    their payload, e.g. ``VirTool:Win32/CeeInject.gen!HP``.

    ``PEHSTR_EXT``/``PEHSTR_EXT2`` bytes are PE code fragments and wildcard
    opcodes, not strings.  Their details therefore contain only the hex
    pattern; the other ``*HSTR_EXT`` kinds (e.g. DEX/Java string fragments)
    keep the best-effort text rendering.
    """

    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type in HSTR_EXT_SIGS

        if len(self.sig_data) < 7:
            raise ValueError(
                f"Unexpected {self.sig_type} payload size: {len(self.sig_data)}"
            )

        # parse signature data header
        self.unknown_u16_1 = struct.unpack('<H',self.sig_data[0:2])[0]
        self.threshold = struct.unpack('<H',self.sig_data[2:4])[0]
        self.rule_numbers = struct.unpack('<H',self.sig_data[4:6])[0]
        self.unknown_u8_1 = self.sig_data[6]

        self.decode_warnings = []
        # byte 6 starts an optional NUL-terminated name
        name_end = self.sig_data.find(b"\x00", 6)
        if name_end < 0:
            # Malformed / legacy: keep the old "reserved byte" assumption.
            self.decode_warnings.append("Unterminated HSTR_EXT name; used legacy layout")
            self.name_raw = b""
            self.name = ""
            rules_pos = 7
        else:
            self.name_raw = self.sig_data[6:name_end]
            self.name = self.name_raw.decode("utf-8", "replace")
            rules_pos = name_end + 1

        # parse subrules
        self.subrules = []
        if self.rule_numbers:
            self.subrules_end = self._parse_counted_subrules(rules_pos)
            if len(self.subrules) < self.rule_numbers:
                self.decode_warnings.append("Fewer HSTR_EXT subrules than declared")
        else:
            self.subrules_end = self._parse_terminated_subrules(rules_pos)

        if self.subrules_end > len(self.sig_data):
            self.decode_warnings.append("Truncated HSTR_EXT subrule pattern")

        # trailing data: u16 end marker and optional u16 flags word.  Some
        # record kinds use the whole trailing word as flags and have no
        # explicit zero terminator.
        self.tail = bytes(self.sig_data[self.subrules_end:])
        self.end_marker = None
        self.flags = 0
        self.flags_present = False
        if len(self.tail) >= 2:
            first = struct.unpack_from('<H', self.tail, 0)[0]
            rest = self.tail[2:]
            if len(rest) >= 2:
                self.end_marker = first
                self.flags = struct.unpack_from('<H', rest, 0)[0]
                self.flags_present = True
            elif first != 0:
                self.flags = first
                self.flags_present = True
            else:
                self.end_marker = first

    def to_details(self) -> dict:
        include_text = self.sig_type not in (
            "SIGNATURE_TYPE_PEHSTR_EXT",
            "SIGNATURE_TYPE_PEHSTR_EXT2",
        )
        return {
            "unknown_u16_1": self.unknown_u16_1,
            "threshold": self.threshold,
            "rule_numbers": self.rule_numbers,
            "unknown_u8_1": self.unknown_u8_1,
            "name": self.name,
            "name_present": self.name_present,
            "decode_warnings": list(self.decode_warnings),
            "end_marker": self.end_marker,
            "flags": self.flags,
            "flags_present": self.flags_present,
            "subrules": [
                rule.to_details(include_text=include_text)
                for rule in self.subrules
            ],
        }

    @property
    def name_present(self) -> bool:
        return len(self.name_raw) > 0

    def _parse_counted_subrules(self, ptr: int) -> int:
        data = self.sig_data
        for _ in range(self.rule_numbers):
            if ptr + 4 > len(data):
                break
            subrule = HStrExtSubRule(data, ptr)
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            ptr += 4 + subrule.rule_size
        return ptr

    def _parse_terminated_subrules(self, ptr: int) -> int:
        """Fallback for records without a usable rule count."""
        data = self.sig_data
        while ptr + 4 <= len(data):
            subrule = HStrExtSubRule(data, ptr)
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            ptr += 4 + subrule.rule_size
        return ptr


class DexHStrExtSig(HStrExtSig):
    """
    SIGNATURE_TYPE_DEXHSTR_EXT (0xbe).

    This is the DEX / Android (Dalvik ``classes.dex``) flavour of the generic
    ``HSTR_EXT`` string pattern signature.  The layout is identical to the other
    ``*HSTR_EXT`` types::

        u16  unknown       (== threshold in almost every record)
        u16  threshold     minimum total weight of the matching sub-rules
        u16  rule_numbers  number of sub-rules
        u8   name[]        NUL-terminated name (empty in compiled records)
        sub-rule[]         weight: i16, size: u8, flags: u8, bytes[size]
        u16  0x0000        end of sub-rule list
        u16  flags         optional

    The patterns are UTF-8 fragments of strings from the DEX string table, and
    DEX's ``string_data_item`` prefixes every string with a (usually 2-byte)
    uleb128 length, which the engine skips with the ``90 01 02`` wildcard::

        68 69 2c 78 69 61 6f 6c 75 90 01 02 68 69 2c 6c 69 71 69 61 6e
        "hi,xiaolu"                skip 2         "hi,liqian"

    Two extra details over the plain HSTR_EXT layout were found in the shipped
    database:

    * About 14% of records carry one more ``u16`` after the sub-rule
      terminator.  It behaves like a small flag bitmask (observed 1..46) and is
      exposed as :attr:`flags`; ``flags_present`` tells whether it was there.
    * A small number of records (287 in the shipped database, all inside the
      ``!InfrastructureShared`` bucket) use the name field: byte 6 starts a
      NUL-terminated reference such as ``!#Tel:Trojan:AndroidOS/Fakecalls.YU``.
      They are exposed as :attr:`name_reference` (without the leading ``!``)
      and :attr:`is_name_reference`.
    """

    def to_details(self) -> dict:
        details = super().to_details()
        details.update({
            "is_name_reference": self.is_name_reference,
            "name_reference": self.name_reference,
        })
        return details

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        super().__init__(data, ptr)
        assert self.sig_type == SIG_TYPES[0xBE]

        self.is_name_reference = self.name_present
        self.name_reference = ""
        if self.name_present:
            # Not a real DEX string pattern; see !InfrastructureShared.
            self.name_reference = (
                self.name[1:] if self.name.startswith("!") else self.name
            )
            self.subrules = []

