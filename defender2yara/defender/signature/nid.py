import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# Empirically derived labels for the one-byte ``kind`` field.  Microsoft does
# not document this enum; the labels come from the names found on the long-form
# records in ``!InfrastructureShared`` and from the families that reference each
# kind (see app/static/sigs/NID.md).
NID_KIND_LABELS = {
    0x03: "Win32 legacy names",
    0x04: "BAT / Win32 legacy names",
    0x05: "IRC / legacy names",
    0x06: "SWF names",
    0x07: "HTML names",
    0x0B: "PDB / SLF / ALF names",
    0x0D: "legacy DOS virus names",
    0x0E: "test-file names",
    0x0F: "legacy scanner DB names",
    0x10: "legacy scanner DB names",
    0x11: "name slots (packers, tags)",
    0x12: "Win95 legacy names",
    0x13: "Win16 legacy names",
    0x14: "legacy scanner DB names",
    0x15: "unnamed tags",
    0x16: "JS / ASP names",
    0x18: "Word macro names (W1M/W2M)",
    0x19: "Access macro names (A97M)",
    0x1A: "ALF names",
    0x1B: "Java names",
    0x1C: "misc attribute names",
    0x1D: "WinNT names",
    0x1E: "O97M macro names",
    0x1F: "O97M macro names",
    0x20: "O97M macro names",
    0x21: "Excel macro names (X97M)",
    0x24: "API function names",
    0x27: "API import names",
    0x28: "installer script names (RAR)",
    0x29: "installer script names (NSIS)",
    0x2A: "installer script names (Inno)",
    0x2B: "engine attribute / analysis flag",
    0x2C: "engine attribute / analysis flag",
    0x2D: "engine attribute / analysis flag",
    0x2E: "engine attribute / analysis flag",
    0x2F: "password list entries",
    0x31: "engine attribute / analysis flag",
    0x32: "engine attribute / analysis flag",
    0x35: "engine attribute / analysis flag",
    0x36: "engine attribute / analysis flag",
    0x3A: "LowFi / aggregator names",
    0x3C: "engine attribute / analysis flag",
    0x4D: "ALF group entries",
    0x4E: "LowFi Lua names",
    0x51: "attribute-match code-patch names",
    0x59: "persistence names",
    0x5D: "LowFi behaviour names",
    0x5F: "LowFi Lua / path names",
    0x61: "PE string / ALF group entries",
    0x63: "DLL name references",
    0x71: "FDR names",
    0x78: "PE extended string names",
    0x7C: "telemetry (#TEL) names",
    0x7D: "telemetry (#TEL) names",
    0xA2: "tag names",
    0xC8: "ALF Java entries",
    0xC9: "NID group definitions",
    0xCA: "not-interesting list",
    0xD2: "clean-folder list",
    0xD5: "trusted-installer list",
    0xDC: "clean-domain / NID list",
    0xDF: "ALF group entries",
    0xE6: "SNID-EX helper names",
    0xE7: "org-signer RMM list",
}

# Best-effort labels for the one-byte namespace on NID64 (0xce) records.  These
# are observed in the shipped database and cross-checked against the type of the
# 64-bit key when that key is a packed record id (see ``Nid64Sig``).
NID64_KIND_LABELS = {
    0x50: "CKSIMPLEREC table members",
    0x3A: "telemetry (#TEL) names",
    0x57: "UNPLIB ids",
    0x5C: "threat-name ids",
    0x5E: "file-name ids",
    0x67: "STATIC table members",
    0x6A: "removal-policy ids",
    0x6E: "script-brute HSTR names",
    0x7B: "sample-request names",
    0x80: "KCRCE ids",
    0x84: "high-trust publisher names",
    0xE4: "MDBHSTR_EXT names (Go functions)",
}

# Kinds the engine reads as attributes of the object being scanned (enable deep
# analysis, VMM grow, exhaustive HSTR, API/SEH limits, ...).  These describe the
# scan, they don't match a file.
TAGGING_KINDS = frozenset({0x2B, 0x2C, 0x2D, 0x2E, 0x31, 0x32, 0x35, 0x36, 0x3C})

# Kinds whose ids are members of a named list (allow-lists, clean lists, the
# shared ALF/behaviour groups).
GROUP_KINDS = frozenset({0x4D, 0xA2, 0xC9, 0xCA, 0xD2, 0xD5, 0xDC, 0xDF, 0xE7})

PURPOSE_NOTES = {
    "tagging": (
        "Tells the engine something about the object being scanned "
        "(for example: analyse it deeper). It is not a detection."
    ),
    "group membership": (
        "One id of a named list or shared group "
        "(allow-list, clean list, ALF/behaviour group). It is not a detection."
    ),
    "naming": (
        "A name slot in Defender's internal id table. It names or aliases something; "
        "it describes no file content, so nothing can match it."
    ),
}

# Shorter display names for the roles above.
PURPOSE_LABELS = {
    "tagging": "tagging",
    "group membership": "group / list entry",
    "naming": "naming",
}


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
    queries (kind, key) pairs to toggle engine features; those kinds
    (``0x2b``..``0x3c``) are attributes of the object being scanned rather than
    names.

    In real threats the payload is always exactly five bytes ("this object id is
    referenced here", no text).  The ``!InfrastructureShared`` bucket additionally
    carries the long form, where ``name`` is the definition group the reference
    belongs to (e.g. ``#TEL``, ``!#OrgSignerRmmNormal``) - not the name of the
    target.  It is therefore not a usable ``id -> name`` dictionary (only a
    handful of the ~192k per-threat references have a companion record at all).

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

    def to_details(self) -> dict:
        return {
            "record_key_hex": f"{self.record_key:0{self.KEY_SIZE * 2}x}",
            "record_kind": self.record_kind,
            "record_name": self.record_name,
            "has_name": self.has_name,
            "id_block": self.id_block,
            "is_legacy_id": self.is_legacy_id,
            "kind_label": self.kind_label,
            "likely_purpose": self.likely_purpose,
            "purpose_label": self.purpose_label,
            "purpose_note": self.purpose_note,
            "description": self.describe(),
        }

    @property
    def has_name(self) -> bool:
        return len(self.record_name_raw) > 0

    @property
    def key_text(self) -> str:
        return f"0x{self.record_key:0{self.KEY_SIZE * 2}x}"

    @property
    def kind_text(self) -> str:
        return f"0x{self.record_kind:02x}"

    @property
    def key_bytes(self) -> bytes:
        """Raw key bytes (4 bytes for NID, 8 bytes for NID64)."""
        return self.sig_data[: self.KEY_SIZE]

    @property
    def id_block(self) -> int | None:
        """High 16 bits of a 32-bit key: ids are allocated in blocks."""
        if self.KEY_SIZE != 4:
            return None
        return (self.record_key >> 16) & 0xFFFF

    @property
    def is_legacy_id(self) -> bool:
        """Small keys are ids from one of the old flat name tables."""
        return self.KEY_SIZE == 4 and self.record_key < 0x10000

    @property
    def kind_label(self) -> str:
        """Best-effort family name for the ``kind`` byte."""
        if self.KEY_SIZE == 8:
            return NID64_KIND_LABELS.get(self.record_kind, "")
        return NID_KIND_LABELS.get(self.record_kind, "")

    @property
    def likely_purpose(self) -> str:
        """Best-effort role: ``naming``, ``tagging`` or ``group membership``.

        The record itself does not say which role it has; the guess is based on
        the kind namespace it lives in.
        """
        if self.record_kind in TAGGING_KINDS:
            return "tagging"
        if self.record_kind in GROUP_KINDS:
            return "group membership"
        return "naming"

    @property
    def purpose_note(self) -> str:
        return PURPOSE_NOTES[self.likely_purpose]

    @property
    def purpose_label(self) -> str:
        """Short display name for :attr:`likely_purpose`."""
        return PURPOSE_LABELS[self.likely_purpose]

    def describe(self) -> str:
        text = f"key=0x{self.record_key:0{self.KEY_SIZE * 2}x} kind=0x{self.record_kind:02x}"
        if self.has_name:
            text += f" name={self.record_name!r}"
        return text


class Nid64Sig(NidSig):
    """SIGNATURE_TYPE_NID64 (0xce): 8-byte key, 1-byte kind, optional name.

    NID64 is the 64-bit sibling of NID.  The engine stores the same
    ``{key, kind, name-id, extra}`` entry in a dedicated table
    (``FUN_180a19c7c`` / ``FUN_180a1b678`` -> ``FUN_1803f4988``), sorted by
    the key, and looks entries up by ``(key, kind)``.  ``Nid64Search``
    (``FUN_180b1e6d0``) is the text-command equivalent of ``NidSearch``:
    ``Nid64Search <kind> <id>``.  The engine also uses the table for simple
    membership tests such as "is this record id a revoked certificate?"
    (``FUN_180336368`` -> ``FUN_18015d2d4``).

    For record-backed namespaces the 64-bit key is the engine's packed record
    id — the same scheme produced by ``FUN_18015c56c`` for NID
    (``crc32(payload) | type << 32 | size << 40``) and by the STATIC builder:
    low 32 bits are the Defender CRC-32 of the record payload, bits 32..39
    the record's signature type and bits 40..63 its payload size.  In the
    shipped database 5,141 of 12,109 keys resolve exactly to a record in the
    merged VDM stream, mostly NID64, STATIC, revoked-certificate,
    aggregator, SNID and NID records.
    """

    SIG_TYPE_ID = 0xCE
    KEY_SIZE = 8
    RECORD_ID_MAX_SIZE = 0x200000

    def to_details(self) -> dict:
        details = super().to_details()
        details.update({
            "packed_crc32": self.packed_crc32,
            "packed_sig_type_id": self.packed_sig_type_id,
            "packed_sig_type": self.packed_sig_type,
            "packed_size": self.packed_size,
            "has_record_id_layout": self.has_record_id_layout,
        })
        return details

    @property
    def packed_crc32(self) -> int:
        """Low 32 bits of the key: candidate packed-record-id CRC."""
        return self.record_key & 0xFFFFFFFF

    @property
    def packed_sig_type_id(self) -> int:
        """Bits 32..39 of the key: candidate record signature type."""
        return (self.record_key >> 32) & 0xFF

    @property
    def packed_sig_type(self) -> str:
        return SIG_TYPES.get(
            self.packed_sig_type_id,
            f"UNKNOWN(0x{self.packed_sig_type_id:02x})",
        )

    @property
    def packed_size(self) -> int:
        """Bits 40..63 of the key: candidate record payload size."""
        return (self.record_key >> 40) & 0xFFFFFF

    @property
    def has_record_id_layout(self) -> bool:
        """Heuristic: the key looks like a packed record id.

        True when the embedded type name is known and the embedded size is
        plausible for a VDM record (the largest shipped payload is ~1.3 MiB).
        This is a layout test only; resolve the key against a record database to
        know whether the record really exists.  Hashes/ids that are not packed
        record ids can still have a "known" type byte by coincidence.
        """
        return (
            0 < self.packed_size <= self.RECORD_ID_MAX_SIZE
            and self.packed_sig_type_id in SIG_TYPES
            and self.packed_sig_type_id != 0
        )
