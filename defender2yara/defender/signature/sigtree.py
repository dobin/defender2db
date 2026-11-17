import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


SIGTREE_SIGS = [
    "SIGNATURE_TYPE_SIGTREE",
    "SIGNATURE_TYPE_SIGTREE_EXT",
    "SIGNATURE_TYPE_SIGTREE_BM",
]

# Maximum length of the optional name at the start of the payload.
MAX_NAME_LEN = 0x40

# Condition opcodes.  The opcode is a single byte followed by a fixed-size
# blob (or, for opcode 1, a variable-size blob whose length comes from the
# edge record).
OPCODE_PATTERN = 1
OPCODE_HASHES = {
    2: ("md5", 0x10),
    3: ("sha1", 0x14),
    4: ("sha256", 0x20),
}

# The per-side flag that says "an inline pattern follows".
FLAG_INLINE = 0x10


def _decode_literal(data: bytes) -> str:
    """Decode a literal run as UTF-16LE when it looks like text, else latin-1."""
    if len(data) >= 2 and len(data) % 2 == 0 and data[1::2] == b"\x00" * (len(data) // 2):
        try:
            return data.decode("utf-16le")
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1", "replace")


def decode_tree_pattern(data: bytes) -> str:
    """
    Best-effort readable rendering of a sigtree condition blob.

    Sig-tree patterns are either byte strings or UTF-16LE strings with the
    single-byte ``0x90`` wildcard opcodes from the HSTR format embedded in
    them::

        90 00        end of pattern
        90 01 XX     skip exactly XX bytes
        90 02 XX     skip 0..XX bytes

    Opcodes 3..5 (alternatives / regex) are left verbatim.
    """
    out = []
    literal = bytearray()
    i = 0
    size = len(data)

    def flush():
        if literal:
            out.append(_decode_literal(bytes(literal)))
            literal.clear()

    while i < size:
        if data[i] == 0x90 and i + 1 < size:
            op = data[i + 1]
            if op == 0:
                flush()
                i += 2
                continue
            if op in (1, 2) and i + 2 < size:
                flush()
                if op == 1:
                    out.append(f"<skip {data[i + 2]}>")
                else:
                    out.append(f"<skip 0..{data[i + 2]}>")
                i += 3
                continue
        literal.append(data[i])
        i += 1

    flush()
    return "".join(out)


class SigTreeCondition:
    """One condition (left or right operand) of a sig-tree edge."""

    def __init__(self, side: str, kind: str, flags: int, data: bytes) -> None:
        self.side = side
        self.kind = kind  # "pattern", "md5", "sha1" or "sha256"
        self.flags = flags
        self.data = data

    def to_details(self) -> dict:
        return {
            "side": self.side,
            "kind": self.kind,
            "flags": self.flags,
            "data_hex": self.data.hex(),
            "text": self.text,
            "is_pattern": self.is_pattern,
            "is_hash": self.is_hash,
        }

    @property
    def is_pattern(self) -> bool:
        return self.kind == "pattern"

    @property
    def is_hash(self) -> bool:
        return self.kind in ("md5", "sha1", "sha256")

    @property
    def text(self) -> str:
        if self.is_pattern:
            return decode_tree_pattern(self.data)
        return self.data.hex()

    def __repr__(self) -> str:
        return (
            f"SigTreeCondition({self.side}, {self.kind}, "
            f"flags=0x{self.flags:02x}, data={self.data.hex()})"
        )


class SigTreeEdge:
    """
    One edge of a sig tree.

    ``x`` packs the two per-side flag bytes (``x & 0xff`` = right,
    ``x >> 8 & 0xff`` = left) and ``y`` packs the two inline pattern lengths
    (``y >> 16 & 0xff`` = right, ``y >> 24 & 0xff`` = left).  ``z``, ``w``
    and the optional ``extra`` / ``extra2`` words are node/action values that
    are not interpreted here.
    """

    def __init__(self, x: int, y: int, z: int, w: int,
                 extra: int = 0, extra2: int = 0,
                 conditions: list = None) -> None:
        self.x = x
        self.y = y
        self.z = z
        self.w = w
        self.extra = extra
        self.extra2 = extra2
        self.conditions = conditions or []

    def to_details(self) -> dict:
        return {
            "x": self.x,
            "y": self.y,
            "z": self.z,
            "w": self.w,
            "extra": self.extra,
            "extra2": self.extra2,
            "left_flags": self.left_flags,
            "right_flags": self.right_flags,
            "left_length": self.left_length,
            "right_length": self.right_length,
            "conditions": [condition.to_details() for condition in self.conditions],
        }

    @property
    def left_flags(self) -> int:
        return (self.x >> 8) & 0xFF

    @property
    def right_flags(self) -> int:
        return self.x & 0xFF

    @property
    def left_length(self) -> int:
        return (self.y >> 24) & 0xFF

    @property
    def right_length(self) -> int:
        return (self.y >> 16) & 0xFF

    def condition(self, side: str):
        for cond in self.conditions:
            if cond.side == side:
                return cond
        return None

    def __repr__(self) -> str:
        return (
            f"SigTreeEdge(x=0x{self.x:08x}, y=0x{self.y:08x}, "
            f"z=0x{self.z:08x}, w=0x{self.w:08x}, "
            f"conds={self.conditions!r})"
        )


class SigTreeSig(BaseSig):
    """
    SIGNATURE_TYPE_SIGTREE (0x40), SIGTREE_EXT (0x41) and SIGTREE_BM (0xb3).

    All three types share one parser in mpengine (the handlers registered by
    the ``sigtree`` module, ``FUN_1803a0220`` / ``FUN_1803a0190`` /
    ``FUN_1803a0100`` -> ``FUN_1803a02a8``).  On-disk layout::

        u8  edge_count
        u8  variant       0..4 (number of optional words per edge)
        u8  unknown
        u8  tree_kind     0..6 (per-kind generator state index)
        u8  name[]        NUL-terminated, normally empty
        u32 meta          only when variant > 2
        edge[edge_count]:
            u32 x         right flags (b0), left flags (b1),
                          right length (b2), left length (b3)
            u32 y         parallel data word; lengths for x are in b20/b30
            u32 z
            u32 w
            u32 extra     only when variant >= 1
                          bit 8 = right condition has an opcode blob
                          bit 16 = left condition has an opcode blob
            u32 extra2    only when variant >= 2
            condition blobs, left first then right:
                inline (flag 0x10): extra-length raw bytes
                opcode 1: one byte opcode + inline length bytes
                opcode 2: 16-byte MD5
                opcode 3: 20-byte SHA-1
                opcode 4: 32-byte SHA-256

    A condition blob is a byte pattern or a UTF-16LE string that may contain
    the usual ``0x90`` HSTR wildcard opcodes (see
    :func:`decode_tree_pattern`).

    ``SIGTREE_BM`` is the behaviour-monitoring flavour; in the shipped
    database every ``0xb3`` record uses ``tree_kind == 2``.  ``SIGTREE`` and
    ``SIGTREE_EXT`` use kinds 0..6 and add plain string patterns and MD5
    hashes to the tree.

    All 17,940 ``0xb3``, 15,058 ``0x40`` and 4,207 ``0x41`` records in the
    shipped database consume their payload exactly.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type in SIGTREE_SIGS

        payload = self.sig_data
        if len(payload) < 5:
            raise ValueError(
                f"Unexpected {self.sig_type} payload size: {len(payload)}"
            )

        self.edge_count = payload[0]
        self.variant = payload[1]
        self.unknown = payload[2]
        self.tree_kind = payload[3]

        if self.variant >= 5:
            raise ValueError(f"Unsupported sigtree variant: {self.variant}")
        if self.tree_kind >= 7:
            raise ValueError(f"Unsupported sigtree kind: {self.tree_kind}")

        name_end = payload.find(b"\x00", 4, 4 + MAX_NAME_LEN + 1)
        if name_end < 0:
            raise ValueError("Unterminated sigtree name")
        self.name_raw = payload[4:name_end]
        self.name = self.name_raw.decode("utf-8", "replace")
        pos = name_end + 1

        self.meta = None
        if self.variant > 2:
            self.meta, = struct.unpack_from("<I", payload, pos)
            pos += 4

        self.edges = []
        for _ in range(self.edge_count):
            pos = self._parse_edge(payload, pos)

        self.trailing = bytes(payload[pos:])

    def _parse_edge(self, payload: bytes, pos: int) -> int:
        if pos + 16 > len(payload):
            raise ValueError("Truncated sigtree edge")
        x, y, z, w = struct.unpack_from("<IIII", payload, pos)
        pos += 16

        extra = 0
        if self.variant >= 1:
            extra, = struct.unpack_from("<I", payload, pos)
            pos += 4
        extra2 = 0
        if self.variant >= 2:
            extra2, = struct.unpack_from("<I", payload, pos)
            pos += 4

        conditions = []
        pos = self._parse_condition(
            payload, pos, "left", x >> 8 & 0xFF, y >> 24 & 0xFF,
            extra >> 16 & 1, conditions,
        )
        pos = self._parse_condition(
            payload, pos, "right", x & 0xFF, y >> 16 & 0xFF,
            extra >> 8 & 1, conditions,
        )

        self.edges.append(
            SigTreeEdge(x, y, z, w, extra, extra2, conditions)
        )
        return pos

    def _parse_condition(self, payload: bytes, pos: int, side: str,
                         flags: int, length: int, has_opcode: int,
                         conditions: list) -> int:
        if flags & FLAG_INLINE:
            if pos + length > len(payload):
                raise ValueError("Truncated sigtree pattern")
            conditions.append(
                SigTreeCondition(side, "pattern", flags, payload[pos:pos + length])
            )
            return pos + length

        if not has_opcode:
            return pos

        if pos >= len(payload):
            raise ValueError("Truncated sigtree condition opcode")

        opcode = payload[pos]
        pos += 1
        if opcode == OPCODE_PATTERN:
            length = length * 2 if flags & 0x40 else length
            kind = "pattern"
        else:
            entry = OPCODE_HASHES.get(opcode)
            if entry is None:
                raise ValueError(f"Unknown sigtree condition opcode: {opcode}")
            kind, length = entry

        if pos + length > len(payload):
            raise ValueError("Truncated sigtree condition data")

        conditions.append(
            SigTreeCondition(side, kind, flags, payload[pos:pos + length])
        )
        return pos + length

    def to_details(self) -> dict:
        return {
            "edge_count": self.edge_count,
            "variant": self.variant,
            "unknown": self.unknown,
            "tree_kind": self.tree_kind,
            "name": self.name,
            "meta": self.meta,
            "is_behavior": self.is_behavior,
            "description": self.describe(),
            "edges": [edge.to_details() for edge in self.edges],
        }

    @property
    def is_behavior(self) -> bool:
        return self.sig_type == SIG_TYPES[0xB3]

    @property
    def patterns(self) -> list:
        return [c for e in self.edges for c in e.conditions if c.is_pattern]

    @property
    def hashes(self) -> list:
        return [c for e in self.edges for c in e.conditions if c.is_hash]

    def describe(self) -> str:
        text = (
            f"{self.sig_type} kind={self.tree_kind} variant={self.variant} "
            f"edges={self.edge_count}"
        )
        if self.name:
            text += f" name={self.name!r}"
        return text
