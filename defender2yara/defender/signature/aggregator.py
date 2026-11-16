import re
import struct
from typing import List, Tuple

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# Byte substitution table used for AAGGREGATOR/AAGGREGATOREX record bodies.
#
#   decoded_byte = table[stored_byte]
#
# Taken from mpengine.dll build 1.1.26100.4 at VA 0x180d9e080 (256 bytes, a
# permutation).  The loader (FUN_180185410) maps both the optional name and the
# expression body through this table right after copying the record payload, so
# the on-disk form is a simple, static obfuscation, not compression.
AGGREGATOR_SUBSTITUTION = bytes.fromhex(
    "4bbaa3c0464384eda8973f7217adef54ddf9216442f18c49687677fc11b274d3"
    "dc040996d40df619fb357e9fd1e19dccdb63f53094407cf35dc7aae4e614676e"
    "d837a2b056a651dfb98539159e8d3e22cefe7a0ac17d9c93b313082a0c3d0682"
    "609bbd05c4241e50e5014f1cf48a982ccd3c5e6d328f2b472f1da5bb25b8d7b1"
    "659158c9be92e88b3355128eeaabf8261f711b52cbe2e786ae6231fdaf02d20eb"
    "7e3834816cfd579030fdab56f4d7bde079ad9a0c827a1d0c310bff76118eb382"
    "8a95f66c50b95535b00f07f81f26ad678731aac89a4fa4436b475c223bc59e92"
    "9ca5a416b34704ceeb66c873a5780a799ec69ffe0c64a3b4e205c2d45882e90"
)
assert len(AGGREGATOR_SUBSTITUTION) == 256
assert len(set(AGGREGATOR_SUBSTITUTION)) == 256, "table must be a permutation"


def decode_aggregator(data: bytes) -> bytes:
    """Undo the static byte substitution applied to aggregator payload bytes."""
    return bytes(AGGREGATOR_SUBSTITUTION[b] for b in data)


def decode_text(data: bytes) -> str:
    """
    Decode a de-obfuscated aggregator name/expression.

    The payload is UTF-8.  A handful of definitions embed non-ASCII characters
    on purpose (e.g. Cyrillic look-alikes in ``Lua:PeCompanyName!`` atoms), so
    fall back to latin-1 for malformed input instead of dropping bytes.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


# Inverse permutation, used when re-encoding a decoded expression.
AGGREGATOR_SUBSTITUTION_INVERSE = bytes(
    sorted(range(256), key=lambda i: AGGREGATOR_SUBSTITUTION[i])
)


def encode_aggregator(data: bytes) -> bytes:
    """Apply the byte substitution, i.e. the inverse of :func:`decode_aggregator`."""
    return bytes(AGGREGATOR_SUBSTITUTION_INVERSE[b] for b in data)


# A reference to another signature record: ``KIND:Threat:Platform/Family`` etc.
_REFERENCE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*:[^\s&|!()]+")


class AaAggregatorExSig(BaseSig):
    """
    SIGNATURE_TYPE_AAGGREGATOREX (0xe7), the "aggregator" signature.

    An aggregator does not look at the file itself.  It evaluates a boolean
    expression over *other* signature records, identified by their threat /
    attribute name.  It is Defender's rule-composition layer: ``HSTR:`` is a
    string signature, ``SIGATTR:`` a SIGATTR record, ``SCPT:`` a script
    signature, ``Lua:`` a Lua signature, ``PEPCODE:``/``FOP:`` a PE code /
    file-offset-pattern record, ``AGG:``/``AGGR:`` another aggregator, and so
    on.  Operators are ``&`` (and), ``|`` (or), ``!`` (not) and parentheses.

    On-disk layout (little endian), reverse engineered from the 0xe7 record
    handler FUN_180185410 in mpengine.dll 1.1.26100.4:

        u8   flags          observed 0x00, 0x01
        u8   name_length    always 0 in the shipped database
        u16  body_length
        u8   name[name_length]
        u8   body[body_length]

    ``name`` and ``body`` are byte-substituted with
    :data:`AGGREGATOR_SUBSTITUTION`; after decoding ``body`` is a plain ASCII
    expression such as::

        HSTR:PWS:Win32/Gina.dll&SIGATTR:PWS:Win32/Gina.dll

    The engine computes a CRC32 over the whole payload and registers the
    aggregator under the packed id ``crc | len << 40 | 0xe7 << 32`` plus a
    20-byte content hash (the same record-store scheme used by SNID).
    """

    FLAG_NONE = 0x00
    # 0x01 records always start with a SIGATTR: reference in the sample data;
    # the flag bit is forwarded verbatim to the expression compiler.  Its exact
    # meaning is not confirmed.
    FLAG_ATTRIBUTE = 0x01

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0xE7]

        sd = self.sig_data
        if len(sd) < 4:
            raise ValueError(f"Truncated AAGGREGATOREX header: {len(sd)} bytes")

        self.flags = sd[0]
        self.name_length = sd[1]
        self.body_length = struct.unpack_from("<H", sd, 2)[0]

        expected = 4 + self.name_length + self.body_length
        if expected > len(sd):
            raise ValueError(
                "AAGGREGATOREX payload shorter than its header declares: "
                f"{len(sd)} < {expected}"
            )

        raw_name = sd[4:4 + self.name_length]
        raw_body = sd[4 + self.name_length:expected]

        self.name = decode_text(decode_aggregator(raw_name))
        self.expression = decode_text(decode_aggregator(raw_body))

        # Everything after the declared body (normally nothing).
        self.extra = bytes(sd[expected:])

    @property
    def is_attribute(self) -> bool:
        return bool(self.flags & self.FLAG_ATTRIBUTE)

    @property
    def references(self) -> List[str]:
        """Signature/attribute names referenced by the expression."""
        return _REFERENCE_RE.findall(self.expression)

    def reference_kinds(self) -> List[Tuple[str, int]]:
        """Referenced record kinds ordered by number of uses."""
        counts = {}
        for ref in self.references:
            kind = ref.split(":", 1)[0]
            counts[kind] = counts.get(kind, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    def __repr__(self) -> str:
        return f"AaAggregatorExSig(flags={self.flags:#04x}, expression={self.expression!r})"
