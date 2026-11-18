"""Key-pattern signatures: KPAT (0xbb) and KPATEX (0xbc).

These two types are Defender's **8-byte-anchored byte patterns**.  Unlike the
hash, reference and expression records their payload is a real pattern.  They
are not format-specific: the same tables are consulted from the boot-sector /
MBR-VBR scan, from the emulation and decompressed-buffer scan paths, and from
the VBA macro reader.  Among the types decoded here they are, together with
the HSTR family, the only ones that contain inline byte patterns.

On-disk payload::

    u8  pattern_length          total pattern length, >= 8 (9..197 observed)
    u8  anchor[8]               literal first 8 bytes (the pattern key)
    u8  tail[pattern_length-8]  remainder of the pattern
    u8  name_length             optional; absent/0 means anonymous
    u8  name[name_length]       definition label, not NUL terminated

``KPAT`` (0xbb) and ``KPATEX`` (0xbc) differ only in how the tail is encoded:

* ``KPAT``: plain bytes.  The engine's verifier (``FUN_1800fa880``) compares
  the tail byte by byte and treats a pattern byte of ``0x90`` as "any byte".
  The anchor is always literal.
* ``KPATEX``: the tail is a pattern in the engine's ``0x90`` wildcard language
  (``90 00`` terminator, ``90 01 n`` skip exactly *n*, ``90 02 n`` skip 0..n,
  ``90 03`` byte class, ...).  The loader validates it with ``FUN_1802b1974``
  and it must end with ``90 00``.

Engine notes (x64 build 1.1.26100.4; see ``cache/functions_vdm.md`` section 19):

* ``FUN_180a1f948`` - HSTR module init.  Besides the HSTR contexts it builds a
  matcher object tagged ``kpat`` (``DAT_181115ca8``, 0x80 bytes) and registers
  the two pattern tables ``DAT_181115ca0`` (type ``0x4bb`` = ``0xbb``) and
  ``DAT_181115c90`` (type ``0x4bc`` = ``0xbc``) through ``FUN_1804eae94``.
* ``FUN_1801835fc`` / ``FUN_180181cc4`` - the generic template record loader.
  KPAT/KPATEX have no dedicated parser: the type's registered template
  (``0x180f07500``) drives the field extraction.
* ``FUN_1802b0940`` - commit callback.  It interns the pattern strings and
  feeds both tables into the multi-pattern matcher (``FUN_1801b6ce4``).
* ``FUN_1800fa880`` - verifier: finds the 8-byte anchor with the
  Aho-Corasick matcher (``FUN_180047200``), then validates the tail, either
  byte-wise (KPAT) or with the wildcard matcher ``FUN_180049320`` (KPATEX).

The optional name is the reference label used by aggregator expressions
(``KPAT:<label>`` / ``KPATEX:<label>``).  In the shipped database it appears
only in ``!InfrastructureShared`` records, e.g. ``!#KPAT:PDF_Subtype``; records
owned by a real threat are anonymous because the aggregator references use the
owner's threat name instead.
"""

from typing import List, Tuple

from .base import BaseSig
from .hstr import decode_hstr_pattern
from .nscript import SCRIPT_OPCODE_TABLE
from defender2yara.defender.constant import SIG_TYPES


KPAT_SIG = "SIGNATURE_TYPE_KPAT"
KPATEX_SIG = "SIGNATURE_TYPE_KPATEX"
KPAT_SIGS = (KPAT_SIG, KPATEX_SIG)

ANCHOR_LENGTH = 8
WILDCARD_MARKER = 0x90
PATTERN_TERMINATOR = b"\x90\x00"


def _token_length(pattern: bytes, offset: int) -> int:
    """Length of the ``90 xx`` token at *offset* (mirrors ``FUN_1802b1974``)."""
    if offset + 1 >= len(pattern):
        return 1
    opcode = pattern[offset + 1]
    if opcode == WILDCARD_MARKER:
        return 2
    if opcode >= len(SCRIPT_OPCODE_TABLE):
        return 2
    kind, length, _ = SCRIPT_OPCODE_TABLE[opcode]
    if kind == 0x03 and offset + 3 < len(pattern):
        # byte-class opcode: 90 03 <consume> <mask_len> <mask...>
        length += pattern[offset + 3]
    elif kind in (0x04, 0x05, 0x19, 0x1A) and offset + 3 < len(pattern):
        length += pattern[offset + 3]
    elif kind == 0x17 and offset + 2 < len(pattern):
        length += pattern[offset + 2]
    return max(length, 2)


def iter_key_pattern_opcodes(pattern: bytes):
    """Yield ``(offset, opcode, token_bytes)`` for every ``90 xx`` token."""
    offset = 0
    size = len(pattern)
    while offset < size:
        if pattern[offset] == WILDCARD_MARKER and offset + 1 < size:
            length = _token_length(pattern, offset)
            yield offset, pattern[offset + 1], pattern[offset:offset + length]
            offset += length
        else:
            offset += 1


def _escape_byte(byte: int) -> str:
    char = chr(byte)
    if byte == 0:
        return "\\x00"
    if 0x20 <= byte < 0x7F:
        return char
    return f"\\x{byte:02x}"


def _render_bytes(data: bytes) -> str:
    return "".join(_escape_byte(byte) for byte in data)


def _mask_parts(mask: bytes) -> List[str]:
    """Render a ``90 03`` byte-class mask as hex alternatives."""
    parts = []
    index = 0
    while index < len(mask):
        if index + 2 < len(mask) and mask[index + 1] == 0x2D:
            parts.append(f"{mask[index]:02x}-{mask[index + 2]:02x}")
            index += 3
        else:
            parts.append(f"{mask[index]:02x}")
            index += 1
    return parts


def decode_kpat_hex(anchor: bytes, tail: bytes) -> str:
    """Render a KPAT pattern as hex, with ``??`` for the 0x90 wildcard."""
    tokens = [f"{byte:02x}" for byte in anchor]
    tokens.extend("??" if byte == WILDCARD_MARKER else f"{byte:02x}"
                  for byte in tail)
    return " ".join(tokens)


def decode_kpatex_hex(anchor: bytes, tail: bytes) -> str:
    """Render a KPATEX pattern as YARA-style hex with wildcard tokens.

    ``90 01 n`` becomes ``[n]``, ``90 02 n`` becomes ``[0-n]``, ``90 03``
    becomes an ``( aa | bb | cc-dd )`` alternation and repeats become
    ``( ... )`` groups.  Opcodes without a hex equivalent are rendered as
    ``<op XX ...>`` and the trailing ``90 00`` terminator is dropped.
    """
    tokens = [f"{byte:02x}" for byte in anchor]
    offset = 0
    size = len(tail)
    while offset < size:
        byte = tail[offset]
        if byte != WILDCARD_MARKER or offset + 1 >= size:
            tokens.append(f"{byte:02x}")
            offset += 1
            continue
        opcode = tail[offset + 1]
        length = _token_length(tail, offset)
        token = tail[offset:offset + length]
        if opcode == 0x00:
            break  # pattern terminator
        if opcode == WILDCARD_MARKER:
            tokens.append("90")
        elif opcode == 0x01 and len(token) >= 3:
            tokens.append(f"[{token[2]}]")
        elif opcode == 0x02 and len(token) >= 3:
            tokens.append(f"[0-{token[2]}]")
        elif opcode == 0x03 and len(token) >= 4:
            consume = token[2]
            mask = _mask_parts(token[4:4 + token[3]])
            body = "(" + " | ".join(mask) + ")" if mask else "<empty-class>"
            tokens.append(body if consume == 1 else f"({body} x{consume})")
        elif opcode in (0x04, 0x05) and len(token) >= 4:
            repeat, pattern_length = token[2], token[3]
            part = token[4:4 + pattern_length]
            body = " ".join(f"{byte:02x}" for byte in part) or "<empty>"
            label = "repeat" if opcode == 0x04 else "repeat 0.."
            tokens.append(f"<{label} {repeat} of {body}>")
        else:
            operands = token[2:]
            tokens.append(
                f"<op {opcode:02x}" + (f" {operands.hex()}" if operands else "") + ">"
            )
        offset += length
    return " ".join(tokens)


def decode_kpat_text(anchor: bytes, tail: bytes) -> str:
    """Best-effort text rendering of a KPAT pattern (``?`` per wildcard)."""
    return _render_bytes(anchor) + "".join(
        "?" if byte == WILDCARD_MARKER else _escape_byte(byte) for byte in tail
    )


class _KeyPatternSig(BaseSig):
    """Shared parser for the two key-pattern record types."""

    SIG_TYPE_ID = 0
    EXTENDED = False
    layout = "kpat"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[self.SIG_TYPE_ID]

        payload = self.sig_data
        if len(payload) < 1 + ANCHOR_LENGTH:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(payload)} bytes"
            )

        self.pattern_length = payload[0]
        if self.pattern_length < ANCHOR_LENGTH:
            raise ValueError(
                f"Invalid {self.sig_type} pattern length "
                f"{self.pattern_length} (smaller than the 8-byte anchor)"
            )
        pattern_end = 1 + self.pattern_length
        if pattern_end > len(payload):
            raise ValueError(
                f"Truncated {self.sig_type} pattern: need "
                f"{self.pattern_length} bytes, have {len(payload) - 1}"
            )

        self.anchor = bytes(payload[1:1 + ANCHOR_LENGTH])
        self.tail = bytes(payload[1 + ANCHOR_LENGTH:pattern_end])
        self.pattern = self.anchor + self.tail

        self.name_raw, self.name, name_end = self._read_name(payload, pattern_end)
        self.name_length = len(self.name_raw)
        self.expected_size = name_end

        self.opcode_counts = {}
        if self.EXTENDED:
            for _, opcode, _ in iter_key_pattern_opcodes(self.tail):
                self.opcode_counts[opcode] = self.opcode_counts.get(opcode, 0) + 1
            self.wildcard_count = sum(
                count for opcode, count in self.opcode_counts.items()
                if opcode not in (0x00, WILDCARD_MARKER)
            )
        else:
            self.wildcard_count = self.tail.count(WILDCARD_MARKER)
        self.uses_wildcards = self.wildcard_count > 0

        self.pattern_hex = (
            decode_kpatex_hex(self.anchor, self.tail) if self.EXTENDED
            else decode_kpat_hex(self.anchor, self.tail)
        )
        if self.EXTENDED:
            rendered_text = _render_bytes(self.anchor) + decode_hstr_pattern(
                self.tail
            )[0]
        else:
            rendered_text = decode_kpat_text(self.anchor, self.tail)
        self.text_like = self._is_text_like()
        self.pattern_text = rendered_text if self.text_like else ""

        self.decode_warnings = []
        if self.expected_size != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: "
                f"{len(payload) - self.expected_size} bytes"
            )
        if self.EXTENDED and not self.tail.endswith(PATTERN_TERMINATOR):
            self.decode_warnings.append(
                "Pattern does not end with the 0x90 0x00 terminator"
            )

    @staticmethod
    def _read_name(payload: bytes, offset: int) -> Tuple[bytes, str, int]:
        if offset == len(payload):
            return b"", "", offset
        if offset > len(payload):
            raise ValueError("Truncated key-pattern record")
        length = payload[offset]
        end = offset + 1 + length
        if end > len(payload):
            raise ValueError(
                f"Truncated key-pattern name: {length} bytes at offset {offset}"
            )
        raw = bytes(payload[offset + 1:end])
        if raw and raw[-1] == 0:
            raw = raw[:-1]
        return raw, raw.decode("utf-8", "replace"), end

    @property
    def name_present(self) -> bool:
        return self.name_length > 0

    def _is_text_like(self) -> bool:
        """True when most literal pattern bytes are printable text."""
        literals = list(self.anchor)
        if self.EXTENDED:
            offset = 0
            size = len(self.tail)
            while offset < size:
                byte = self.tail[offset]
                if byte != WILDCARD_MARKER or offset + 1 >= size:
                    literals.append(byte)
                    offset += 1
                    continue
                opcode = self.tail[offset + 1]
                if opcode == 0x00:
                    break
                if opcode == WILDCARD_MARKER:
                    literals.append(WILDCARD_MARKER)
                offset += _token_length(self.tail, offset)
        else:
            literals.extend(byte for byte in self.tail if byte != WILDCARD_MARKER)
        if not literals:
            return False
        printable = sum(
            1 for byte in literals
            if 0x20 <= byte < 0x7F or byte in (0x00, 0x09, 0x0A, 0x0D)
        )
        return printable >= len(literals) * 0.85

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "record_name": self.name,
            "has_name": self.name_present,
            "pattern_length": self.pattern_length,
            "anchor_length": ANCHOR_LENGTH,
            "anchor_hex": self.anchor.hex(),
            "tail_length": len(self.tail),
            "tail_hex": self.tail.hex(),
            "pattern_hex": self.pattern_hex,
            "pattern_text": self.pattern_text,
            "text_like": self.text_like,
            "wildcard_count": self.wildcard_count,
            "uses_wildcards": self.uses_wildcards,
            "opcode_counts": {
                f"{opcode:02x}": count
                for opcode, count in sorted(self.opcode_counts.items())
            },
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"{self.SHORT_NAME} len={self.pattern_length} "
            f"anchor={self.anchor.hex()} tail={self.tail.hex()}"
        )
        if self.name_length:
            text += f" name={self.name!r}"
        return text


class KpatSig(_KeyPatternSig):
    """SIGNATURE_TYPE_KPAT (0xbb) - literal key pattern.

    The tail is a plain byte sequence and the only wildcard is a literal
    ``0x90`` pattern byte, which the verifier accepts against any buffer byte.
    The 8-byte anchor is always matched literally (a ``0x90`` inside the anchor
    stays a literal ``0x90``).
    """

    SIG_TYPE_ID = 0xBB
    EXTENDED = False
    layout = "kpat"
    SHORT_NAME = "KPAT"


class KpatExSig(_KeyPatternSig):
    """SIGNATURE_TYPE_KPATEX (0xbc) - extended key pattern.

    The tail uses the engine's ``0x90`` wildcard opcode language (the same
    table as the HSTR family, ``0x180c94d50``): ``90 00`` terminates,
    ``90 01 n`` skips exactly *n* bytes, ``90 02 n`` skips 0..n bytes,
    ``90 03`` is a byte class and ``90 04``/``90 05`` repeat a sub-pattern.
    The loader rejects a tail that does not end with ``90 00``.
    """

    SIG_TYPE_ID = 0xBC
    EXTENDED = True
    layout = "kpatex"
    SHORT_NAME = "KPATEX"
