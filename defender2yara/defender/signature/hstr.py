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
        self.subrules = []
        pos = 7
        while pos < len(self.sig_data):
            subrule = HStrSubRule(self.sig_data,pos)
            # no more subrule
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            pos += 3 + subrule.rule_size


class HStrExtSig(BaseSig):
    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type in HSTR_EXT_SIGS

        # parse signature data header
        self.unknown_u16_1 = struct.unpack('<H',self.sig_data[0:2])[0]
        self.threshold = struct.unpack('<H',self.sig_data[2:4])[0]
        self.rule_numbers = struct.unpack('<H',self.sig_data[4:6])[0]
        self.unknown_u8_1 = self.sig_data[6]

        # parse subrules 
        self.subrules = []
        self.subrules_end = 7
        ptr = 7
        while ptr < len(self.sig_data):
            subrule = HStrExtSubRule(self.sig_data,ptr)
            # no more subrule
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            ptr += 4 + subrule.rule_size
        self.subrules_end = ptr


class DexHStrExtSig(HStrExtSig):
    """
    SIGNATURE_TYPE_DEXHSTR_EXT (0xbe).

    This is the DEX / Android (Dalvik ``classes.dex``) flavour of the generic
    ``HSTR_EXT`` string pattern signature.  The layout is identical to the other
    ``*HSTR_EXT`` types::

        u16  unknown       (== threshold in almost every record)
        u16  threshold     minimum total weight of the matching sub-rules
        u16  rule_numbers  number of sub-rules
        u8   reserved      (0)
        sub-rule[]         weight: i16, size: u8, flags: u8, bytes[size]
        u16  0x0000        end of sub-rule list

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
      ``!InfrastructureShared`` bucket) use a different shape: byte 6 is
      non-zero and the payload is a plain threat-name reference such as
      ``#Tel:Trojan:AndroidOS/Fakecalls.YU``.  Those are detected and left
      unparsed (``is_name_reference`` is True).
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        super().__init__(data, ptr)
        assert self.sig_type == SIG_TYPES[0xBE]

        self.flags = 0
        self.flags_present = False
        self.is_name_reference = False
        self.name_reference = ""

        if self.unknown_u8_1 != 0:
            # Not a real DEX string pattern; see !InfrastructureShared.
            self.is_name_reference = True
            self.subrules = []
            raw = self.sig_data[7:].split(b"\x00", 1)[0]
            self.name_reference = raw.decode("latin-1", "replace")
            return

        tail = self.sig_data[self.subrules_end:]
        if tail[:2] == b"\x00\x00":
            tail = tail[2:]
        if len(tail) >= 2:
            self.flags, = struct.unpack_from("<H", tail, 0)
            self.flags_present = True
        self.tail = bytes(tail)
