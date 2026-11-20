"""Named-data signatures: NDAT (0xa9).

NDAT is the engine's container for **typed strings** used as conditions by the
rest of the pipeline.  It is not a file-byte pattern: each record carries a
blob of data (usually an ASCII/UTF-8 string, sometimes a raw byte regex) plus a
one-byte *data type* that selects the consumer.  The same type byte is also the
key for the engine's per-type commit-handler table.

On-disk payload (template ``0x180f073e0``, registered by the ``cksig`` module
init ``FUN_180a1d2b0`` as type ``0x4a9`` = ``0x400 | 0xa9``)::

    u32 data_length
    u8  data[data_length]      # length includes the terminating NUL for strings
    u8  type                   # NDAT type (1..~23)
    u8  name[name ... NUL]     # optional definition/feed label, NUL terminated

The in-memory table entry is 0x18 bytes::

    +0x00 u32  data length
    +0x04 u32  condition id
    +0x08 ptr  data (interned)
    +0x10 u8   type

The type names below come from the 14-entry ``NDAT_*`` string block at
``0x180c77f98`` (``NDAT_PROJECTPATH_REGEX`` .. ``NDAT_DBTAG``).  The enum is
one-based: type ``5`` is ``NDAT_LOGSKIP_ENTRY``, which the engine registers as
the ``RtpSkipRule`` handler (``FUN_180997cf0``: ``FUN_180997050(ctx, 5,
FUN_18046ae60)``) and type ``22`` is ``RtpSkipRuleEx``.  ``NdatRegExpMatch``
only accepts ``NDAT_REGEXP_GENERIC`` (type 13).  Types above 14 do not appear in
the mpengine name block; they are the NRI/AIMCP string classes that the shipped
data shows.

The optional label is NUL terminated and is preceded by a one-byte marker
(``!`` for internal feed labels, ``#`` for attribute/class labels).  This is
the template's ``0x1017`` opcode, the NUL-terminated name variant; ``0x1016``
is the length-prefixed variant used by KPAT/KPATEX.

Engine notes (x64 build 1.1.26100.4, see ``cache/functions_vdm.md`` section 22):
``FUN_180a1d2b0`` registers the table, ``FUN_180181cc4`` is the template
interpreter, ``FUN_180280ab0`` the commit callback (dispatches on the type
byte through ``DAT_181115430``), ``FUN_180997050`` registers a per-type
callback, ``FUN_18024ff68`` compares a record against a candidate string and
``FUN_180b1e590`` implements the ``NdatRegExpMatch`` definition command.
"""

from typing import Optional, Tuple

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


NDAT_SIG = "SIGNATURE_TYPE_NDAT"

# NDAT_* names from the string block at 0x180c77f98.  The enum is one-based.
NDAT_TYPE_NAMES = {
    1: "NDAT_PROJECTPATH_REGEX",
    2: "NDAT_PROJECTNAME_REGEX",
    3: "NDAT_DONTCOUNT_API",
    4: "NDAT_FIRE_EVENT",
    5: "NDAT_LOGSKIP_ENTRY",
    6: "NDAT_VFS_LINK",
    7: "NDAT_API_ATTRIBUTE",
    8: "NDAT_RKPAT",
    9: "NDAT_EBHASHDATA",
    10: "NDAT_PDBPATH_REGEX",
    11: "NDAT_PDBNAME_REGEX",
    12: "NDAT_INCLUDE_DNS_CACHE_INFO",
    13: "NDAT_REGEXP_GENERIC",
    14: "NDAT_DBTAG",
}

# Types above the mpengine name block.  Labels are inferred from the shipped
# data and from the components that register the handlers.
NDAT_EXTENDED_LABELS = {
    15: "NRI_DOMAIN_REGEX",
    16: "NRI_HTTP_HEADER_REGEX",
    17: "NRI_REGEXP",
    18: "NRI_CERT_SUBJECT_REGEX",
    19: "NRI_RESPONSE_REGEX",
    20: "NRI_CERT_BYTES",
    21: "NRI_AUDIT_RULE",
    22: "RTP_SKIP_RULE_EX",
    23: "NRI_TRANSPORT_REGEX",
}

# Consumers registered by name in this engine build.
NDAT_REGISTERED_HANDLERS = {
    5: "RtpSkipRule",
    13: "NdatRegExpMatch",
    22: "RtpSkipRuleEx",
}


def ndat_type_name(type_id: int) -> str:
    """Return the engine's NDAT_* name, an inferred NRI label, or hex."""
    if type_id in NDAT_TYPE_NAMES:
        return NDAT_TYPE_NAMES[type_id]
    if type_id in NDAT_EXTENDED_LABELS:
        return NDAT_EXTENDED_LABELS[type_id]
    return f"NDAT_TYPE_0x{type_id:02x}"


def _decode_label(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _is_text_like(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(
        1 for byte in data
        if 0x20 <= byte < 0x7F or byte in (0x00, 0x09, 0x0A, 0x0D)
    )
    return printable >= len(data) * 0.85


class NdatSig(BaseSig):
    """SIGNATURE_TYPE_NDAT (0xa9) - typed string / data condition.

    ``data`` is the raw payload string.  ``data_text`` is set when the blob is
    textual (most classes are regexes, paths, API names, header names, or
    certificate subjects); binary classes such as ``NDAT_RKPAT`` store code
    bytes and only expose ``data_hex``.  The optional ``label`` is a definition
    feed label (``!#NRI:...``, ``#NoApiCallCounting``, ...), never a threat
    name.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0xA9]

        payload = self.sig_data
        if len(payload) < 5:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(payload)} bytes"
            )
        self.data_length = int.from_bytes(payload[0:4], "little")
        data_end = 4 + self.data_length
        if data_end + 1 > len(payload):
            raise ValueError(
                f"Truncated {self.sig_type} data: need {self.data_length} "
                f"bytes, have {len(payload) - 4}"
            )
        self.data = bytes(payload[4:data_end])
        self.type_id = payload[data_end]
        self.type_name = ndat_type_name(self.type_id)
        self.handler_name = NDAT_REGISTERED_HANDLERS.get(self.type_id)

        self.label_raw, self.label, self.label_prefix, self.label_end = (
            self._read_label(payload, data_end + 1)
        )
        self.has_label = bool(self.label_raw)

        self.data_nul_terminated = self.data.endswith(b"\x00")
        self.data_is_text = _is_text_like(self.data)
        self.data_text = ""
        if self.data_is_text:
            raw = self.data[:-1] if self.data_nul_terminated else self.data
            self.data_text = _decode_label(raw)

        self.expected_size = self.label_end
        self.decode_warnings = []
        if self.expected_size != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: "
                f"{len(payload) - self.expected_size} bytes"
            )
        if not self.data_nul_terminated and self.data_is_text:
            self.decode_warnings.append("Text NDAT data is not NUL terminated")
        if self.type_id == 0:
            self.decode_warnings.append("NDAT type 0 is not a known class")

    @staticmethod
    def _read_label(payload: bytes, offset: int) -> Tuple[bytes, str, str, int]:
        if offset >= len(payload):
            return b"", "", "", offset
        end = payload.find(b"\x00", offset)
        if end < 0:
            raw = bytes(payload[offset:])
            end = len(payload)
        else:
            raw = bytes(payload[offset:end])
            end += 1
        prefix = ""
        if raw[:1] in (b"!", b"#"):
            prefix = raw[:1].decode()
        return raw, _decode_label(raw), prefix, end

    def to_details(self) -> dict:
        return {
            "layout": "ndat",
            "type_id": self.type_id,
            "type_name": self.type_name,
            "handler_name": self.handler_name,
            "data_length": self.data_length,
            "data_hex": self.data.hex(),
            "data_text": self.data_text,
            "data_is_text": self.data_is_text,
            "data_nul_terminated": self.data_nul_terminated,
            "record_name": self.label,
            "has_name": self.has_label,
            "label_prefix": self.label_prefix,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = f"NDAT {self.type_name}"
        body: Optional[str] = None
        if self.data_is_text:
            body = self.data_text
        if body:
            text += f" {body!r}"
        else:
            text += f" hex={self.data[:24].hex()}"
            if len(self.data) > 24:
                text += "..."
        if self.has_label:
            text += f" name={self.label!r}"
        return text
