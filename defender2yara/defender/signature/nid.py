import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


class NidSig(BaseSig):
    """
    SIGNATURE_TYPE_NID (0x55).

    On-disk layout, derived from mpengine + database analysis::

        u32 key           32-bit record / object id
        u8  kind          namespace or attribute id attached to ``key``
        u8  name[]        optional NUL-terminated text (only present in
                          definition records, e.g. !InfrastructureShared)

    The engine stores the first five bytes verbatim as the record id
    (``crc32(key,kind) | 0x55 << 32 | 5 << 40``) and keeps a hash-table entry
    of ``{key, kind, value, name-id}``.  ``NidSearch`` / ``Nid64Search`` look
    an entry up by ``(key, kind)`` and return its name.  ``FUN_18015b364``
    consumes small kinds (``0x2b``..``0x4b``) as feature/attribute ids from the
    ``NID_*`` enum; shipped records also use larger namespace ids.

    In real threats the payload is always exactly five bytes ("attach
    attribute/kind to object key", no text).  The ``!InfrastructureShared``
    bucket additionally carries the long form, where ``name`` is the record
    name the id maps to (e.g. ``#LOWFI:AGG:Chindo.A1``, ``#TEL``,
    ``!#OrgSignerRmmNormal``).

    ``SIGNATURE_TYPE_NID64`` (0xce) is the same format with an 8-byte key.
    """

    SIG_TYPE_ID = 0x55
    KEY_SIZE = 4

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[self.SIG_TYPE_ID]

        if len(self.sig_data) < self.KEY_SIZE + 1:
            raise ValueError(
                f"Unexpected NID payload size: {len(self.sig_data)}"
            )

        self.record_key = int.from_bytes(
            self.sig_data[: self.KEY_SIZE], "little"
        )
        self.record_kind = self.sig_data[self.KEY_SIZE]

        self.record_name = ""
        self.record_name_raw = b""
        self.trailing = b""

        rest = self.sig_data[self.KEY_SIZE + 1 :]
        if rest:
            end = rest.find(b"\x00")
            raw = rest if end < 0 else rest[:end]
            self.record_name_raw = raw
            self.record_name = raw.decode("utf-8", "replace")
            if end >= 0:
                self.trailing = rest[end + 1 :]

    @property
    def has_name(self) -> bool:
        return len(self.record_name_raw) > 0

    def describe(self) -> str:
        text = f"key=0x{self.record_key:0{self.KEY_SIZE * 2}x} kind=0x{self.record_kind:02x}"
        if self.has_name:
            text += f" name={self.record_name!r}"
        return text


class Nid64Sig(NidSig):
    """SIGNATURE_TYPE_NID64 (0xce): 8-byte key, 1-byte kind, optional name."""

    SIG_TYPE_ID = 0xCE
    KEY_SIZE = 8
