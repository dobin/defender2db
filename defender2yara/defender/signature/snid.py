from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


class SnidSig(BaseSig):
    """
    SIGNATURE_TYPE_SNID (0x7e) - shared-record reference ("signature NID").

    On-disk layout, derived from mpengine + the shipped database:

        u8  record_key[20]   key of the referenced record in the engine's
                             record store
        u8  record_sig_type  signature type of the referenced record
        u8  name[]           optional NUL-terminated group / definition name

    The first 21 bytes are the base record.  mpengine builds exactly this
    record in its record lookup path (FUN_18010df68 ->
    FUN_180217edc(type=0x7e, len=0x15)): it looks a record up by a 20-byte
    key plus a type byte and serialises that pair.  The `SNidSearch`
    definition command (FUN_18037dfc0) takes a 40-character SHA-1 string,
    resolves it through FUN_18010dc74 -> FUN_18010df68 and unpacks the
    record name.  The record store keeps two tables (+0x8 and +0x90); both
    are searched.

    SNID is therefore an indirection / de-duplication entry: a threat
    points at a shared record by key instead of embedding its body.  Most
    SNID entries are in the `!#ALF:...` aggregator groups and in
    `!InfrastructureShared`.  Real threats normally use only the 21-byte
    reference form.

    The extended form adds the *group* the reference belongs to.  It is not
    the target's name: every named SNID lives in `!InfrastructureShared`
    and the same group name repeats for many different keys, e.g. all
    `SIGNATURE_TYPE_IL2_PATTERN` references in `#TopPkg:Prevalent` or all
    `SIGNATURE_TYPE_AAGGREGATOREX` references in `!#OrgSignerRmmNormal`.

    The 20-byte key is the record store key, not necessarily a SHA-1 of the
    on-disk payload.  Hashing the payload/TLV of every shipped record
    (6.1M records) matches only two SNID keys, and those are accidental
    matches against a 4-byte THREAT_END payload.  Several record families
    use a 16-byte (MD5/GUID-sized) key zero-padded into the 20-byte field:
    LOCALHASH, FTRIE_POS and GENSFX pad at the end, MACHOHSTR_EXT and
    ELFHSTR_EXT pad at the front.
    """

    SIG_TYPE_ID = 0x7E

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[self.SIG_TYPE_ID]

        if len(self.sig_data) < 21:
            raise ValueError(
                f"Truncated SNID signature: {len(self.sig_data)} bytes"
            )

        self.record_sha1 = self.sig_data[0:20]
        self.record_sig_type_id = self.sig_data[20]
        self.record_sig_type = SIG_TYPES.get(
            self.record_sig_type_id,
            f"UNKNOWN(0x{self.record_sig_type_id:02x})",
        )

        # Extended form: NUL-terminated group name after the 21-byte base.
        self.record_name = None
        self.record_name_raw = b""
        if len(self.sig_data) > 21:
            self.record_name_raw = self.sig_data[21:].split(b"\x00", 1)[0]
            self.record_name = self.record_name_raw.decode("utf-8", "replace")

    def to_details(self) -> dict:
        return {
            "record_key_hex": self.key_hex,
            "record_sig_type_id": self.record_sig_type_id,
            "record_sig_type": self.record_sig_type,
            "group_name": self.group_name,
            "is_named": self.is_named,
            "key_is_padded": self.key_is_padded,
            "description": self.describe(),
        }

    @property
    def record_key(self) -> bytes:
        """Alias for the 20-byte record-store key (kept as bytes)."""
        return self.record_sha1

    @property
    def key_hex(self) -> str:
        return self.record_sha1.hex()

    @property
    def key_core(self) -> bytes:
        """The key with the zero padding removed.

        20 bytes for SHA-1-keyed records, 16 bytes for MD5/GUID-keyed ones.
        """
        return self.record_sha1.strip(b"\x00")

    @property
    def key_is_padded(self) -> bool:
        core = self.key_core
        return len(core) != len(self.record_sha1)

    @property
    def is_named(self) -> bool:
        return bool(self.record_name_raw)

    @property
    def group_name(self) -> str | None:
        """The definition/group this reference belongs to (extended form)."""
        return self.record_name

    @property
    def reference_type_id(self) -> int:
        return self.record_sig_type_id

    @property
    def reference_type(self) -> str:
        return self.record_sig_type

    def describe(self) -> str:
        text = f"ref={self.record_sig_type}(0x{self.record_sig_type_id:02x}) key={self.key_hex}"
        if self.is_named:
            text += f" group={self.record_name!r}"
        return text
