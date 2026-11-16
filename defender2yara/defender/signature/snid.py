from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


class SnidSig(BaseSig):
    """
    SIGNATURE_TYPE_SNID (0x7e).

    Layout, derived from mpengine:

        u8 record_sha1[20]   SHA1 key of the referenced signature record
        u8 record_sig_type   signature type of the referenced record

    mpengine builds this record verbatim in the record lookup path
    (FUN_18010df68 -> FUN_180217edc(type=0x7e, len=0x15)): it matches a
    20-byte record key plus the type byte, then emits a 21-byte SNID entry.
    The `SNidSearch` text command takes a SHA1 string, resolves it to a record
    id and unpacks the record's name, which is the same lookup.

    In other words SNID is an indirection/re-use entry: a threat points at a
    shared signature record by SHA1 instead of duplicating its body.  Most of
    the 2.2M SNID entries live in `!InfrastructureShared`.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x7E]

        if len(self.sig_data) != 21:
            raise ValueError(
                f"Unexpected SNID payload size: {len(self.sig_data)}"
            )

        self.record_sha1 = self.sig_data[0:20]
        self.record_sig_type_id = self.sig_data[20]
        self.record_sig_type = SIG_TYPES.get(
            self.record_sig_type_id,
            f"UNKNOWN(0x{self.record_sig_type_id:02x})",
        )
