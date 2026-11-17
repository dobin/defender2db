"""Script-content signatures: NSCRIPT_SP (0x28) and NSCRIPT_BRUTE (0x29).

Both types are produced by the ``nscript`` module (``FUN_180a65d00``).  They
match byte-level features of *scripts* (JS/VBS/BAT/PowerShell/Python/IRC) that
the engine has already read as script text.  They are not file fingerprints and
do not contain a decodable threat name; the optional inline name is an engine
list/reference label (``!#SCPT:...``, ``!#JSON:...``, ``!#TEL:...``).

``NSCRIPT_BRUTE`` (0x29) is the readable form: a literal string with HSTR
``0x90`` wildcard opcodes, plus an optional script-type restriction and an
anchor mode.  The patterns are normalised source fragments (lower case, no
whitespace), so ``decode_script_pattern`` produces a good approximation of the
matched text.

``NSCRIPT_SP`` (0x28) is the compact hash form: two 32-bit script hashes, a
window length and a flags byte.  ``SP`` records are what the compiler emits for
the common "two normalised fragments" conditions; the engine builds the same
kind of in-memory condition vector as ``NSCRIPT_NORMAL`` (0x27).

Engine anchors (x64 build 1.1.26100.4, see ``cache/functions_vdm.md`` §13):
``FUN_180a65d00`` module init, ``FUN_1803f8320`` -> ``FUN_1803f8348`` BRUTE
parser, ``FUN_180180f0c`` SP/NORMAL condition parser, ``FUN_180149030`` /
``FUN_180148f08`` -> ``FUN_180550330`` matchers.
"""

import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


NSCRIPT_SP_SIG = "SIGNATURE_TYPE_NSCRIPT_SP"
NSCRIPT_BRUTE_SIG = "SIGNATURE_TYPE_NSCRIPT_BRUTE"

# ``Nscript:Type_*`` table at 0x180f130d0, in enum order.  ``0x29`` stores
# ``kind_byte & 0x7f`` as 1-based index + 1; 0 and 7 both mean "any".
SCRIPT_TYPES = ("vbs", "js", "bat", "irc", "ps", "py", "any")
SCRIPT_TYPE_ANY = 6

# Search direction / anchoring used by the ``nscript`` scanner.  Mode 1 scans
# forward from the start, mode 2 scans backward from the end, mode 0 does not
# care where the match is found.
SCRIPT_MATCH_MODES = {0: "anywhere", 1: "forward", 2: "backward"}

# Pattern compiler escape table from mpengine VA 0x180c94d50 (50 x 3 bytes).
# Entry layout: (token_kind, token_length, extra_operand_index).
# ``token_length`` includes the leading 0x90 and the opcode byte.  Kinds 4, 5,
# 0x19 and 0x1a add the byte at pattern[3]; kind 0x17 adds pattern[2].
SCRIPT_OPCODE_TABLE = (
    (0x00, 2, 0), (0x01, 3, 0), (0x02, 3, 0), (0x03, 4, 0),
    (0x04, 4, 2), (0x05, 4, 2), (0x06, 0, 0), (0x07, 4, 0),
    (0x08, 4, 0), (0x09, 4, 0), (0x0A, 4, 0), (0x0B, 4, 0),
    (0x0C, 4, 0), (0x0D, 4, 0), (0x0E, 4, 0), (0x0F, 4, 0),
    (0x10, 4, 0), (0x11, 4, 0), (0x12, 4, 0), (0x13, 2, 0),
    (0x14, 2, 0), (0x15, 2, 0), (0x16, 2, 0), (0x17, 3, 0),
    (0x18, 2, 0), (0x19, 4, 2), (0x1A, 4, 2), (0x1B, 3, 0),
    (0x1C, 4, 0), (0x1D, 4, 0), (0x1E, 4, 0), (0x1F, 4, 0),
    (0x20, 6, 0), (0x21, 6, 0), (0x04, 4, 3), (0x05, 4, 3),
    (0x0B, 4, 1), (0x0C, 4, 1), (0x0D, 4, 1), (0x0E, 4, 1),
    (0x0F, 4, 1), (0x10, 4, 1), (0x11, 4, 1), (0x12, 4, 1),
    (0x19, 4, 3), (0x1A, 4, 3), (0x1C, 4, 1), (0x1D, 4, 1),
    (0x1E, 4, 1), (0x1F, 4, 1),
)

WILDCARD_MARKER = 0x90
LOOSE_TOKEN_KIND = 0x1B


def _opcode_token_length(pattern: bytes, offset: int) -> int:
    """Length in bytes of the ``90 xx`` token at *offset* (at least 2)."""
    if offset + 1 >= len(pattern):
        return 1
    opcode = pattern[offset + 1]
    if opcode == WILDCARD_MARKER:
        return 2
    if opcode >= len(SCRIPT_OPCODE_TABLE):
        return 2
    kind, length, _ = SCRIPT_OPCODE_TABLE[opcode]
    if kind in (0x04, 0x05, 0x19, 0x1A) and offset + 3 < len(pattern):
        length += pattern[offset + 3]
    elif kind == 0x17 and offset + 2 < len(pattern):
        length += pattern[offset + 2]
    return max(length, 2)


def iter_script_opcodes(pattern: bytes):
    """Yield ``(offset, opcode, token_bytes)`` for every ``90 xx`` token."""
    offset = 0
    size = len(pattern)
    while offset < size:
        if pattern[offset] == WILDCARD_MARKER and offset + 1 < size:
            length = _opcode_token_length(pattern, offset)
            yield offset, pattern[offset + 1], pattern[offset:offset + length]
            offset += length
        else:
            offset += 1


def script_opcode_counts(pattern: bytes) -> dict:
    counts = {}
    for _, opcode, _ in iter_script_opcodes(pattern):
        counts[opcode] = counts.get(opcode, 0) + 1
    return counts


def has_loose_token(pattern: bytes) -> bool:
    """True when the pattern contains a ``90 1b`` token.

    The engine clears its "contiguous" bit (``0x0800``) when such a token is
    present, because the token can consume an arbitrary amount of text.
    """
    return any(
        SCRIPT_OPCODE_TABLE[opcode][0] == LOOSE_TOKEN_KIND
        for _, opcode, _ in iter_script_opcodes(pattern)
        if opcode < len(SCRIPT_OPCODE_TABLE)
    )


def _render_literal(data: bytes) -> str:
    """Decode pattern text, escaping NUL/control bytes for safe display."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return "".join(
        char if char >= " " and char != "\x7f" else f"\\x{ord(char):02x}"
        for char in text
    )


def decode_script_pattern(pattern: bytes) -> str:
    """Best-effort readable rendering of an NSCRIPT_BRUTE pattern.

    ``90 00`` represents a NUL byte, which in practice is the terminating NUL
    of the script string (so rendering stops there).  ``90 01 XX`` skips
    exactly ``XX`` bytes and ``90 02 XX`` skips 0..``XX`` bytes.  Every other
    opcode is rendered as a generic ``<op ..>`` token with its full operand
    bytes; the engine's opcode table at ``0x180c94d50`` defines their lengths.
    """
    out = []
    literal = bytearray()

    def flush() -> None:
        if literal:
            out.append(_render_literal(bytes(literal)))
            literal.clear()

    offset = 0
    size = len(pattern)
    while offset < size:
        if pattern[offset] == WILDCARD_MARKER and offset + 1 < size:
            opcode = pattern[offset + 1]
            if opcode == 0x00:
                break  # pattern terminator
            length = _opcode_token_length(pattern, offset)
            token = pattern[offset:offset + length]
            flush()
            if opcode == 0x01 and len(token) >= 3:
                out.append(f"<skip {token[2]}>")
            elif opcode == 0x02 and len(token) >= 3:
                out.append(f"<skip 0..{token[2]}>")
            elif opcode == WILDCARD_MARKER:
                literal.append(WILDCARD_MARKER)
            else:
                operands = token[2:]
                out.append(f"<op {opcode:02x}" + (f" {operands.hex()}" if operands else "") + ">")
            offset += length
            continue
        literal.append(pattern[offset])
        offset += 1

    flush()
    return "".join(out)


def script_type_index(kind_byte: int) -> int:
    """Map the on-disk kind byte to the internal 0..6 script-type enum."""
    low = kind_byte & 0x7F
    if low in (0, 7) or low > 7:
        return SCRIPT_TYPE_ANY
    return low - 1


def script_type_name(kind_byte: int) -> str:
    """Map the on-disk kind byte (low 7 bits) to its script type name."""
    return SCRIPT_TYPES[script_type_index(kind_byte)]


def _read_name(payload: bytes, limit: int) -> tuple:
    if not payload:
        raise ValueError("Empty NSCRIPT payload")
    name_length = payload[0]
    if name_length > limit:
        raise ValueError(f"Invalid NSCRIPT name length {name_length}")
    if len(payload) < 1 + name_length:
        raise ValueError("Truncated NSCRIPT name")
    raw = payload[1:1 + name_length]
    return raw, raw.decode("utf-8", "replace"), 1 + name_length


class NscriptSpSig(BaseSig):
    """SIGNATURE_TYPE_NSCRIPT_SP (0x28) — compact script hash condition.

    Layout::

        u8   name_length      0..0x3f (0 = no inline name)
        u8   name[name_length]
        u32  hash1            first normalised-script hash
        u8   flags            bit 7 = extra flag; low bits 0..4 observed
        u32  hash2            second normalised-script hash
        u32  match_length     script window length, 0x1000 cap

    The engine parser (``FUN_180181720``) copies ``{hash1, match_length,
    hash2, record_id, flags}`` into the shared script-condition vector, so the
    first two dwords are the two hashes and the trailing dword is the length of
    the script window the hashes cover.  ``match_length`` is always non-zero in
    the shipped database and never exceeds ``0x1000`` (the engine's per-script
    ring-buffer size); 1,184 records use exactly ``0x1000``.

    ``flags & 0x7f`` in ``{1, 2}`` triggers a legacy IRC special case that
    synthesises an ``NSCRIPT_NORMAL`` record for names containing ``:IRC/``.
    Bit ``0x80`` is preserved by the engine as an extra bit in its in-memory
    flag word.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x28]

        raw_name, self.name, base = _read_name(self.sig_data, 0x3F)
        if len(self.sig_data) < base + 13:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(self.sig_data)} bytes"
            )

        self.hash1 = struct.unpack_from("<I", self.sig_data, base)[0]
        self.flags = self.sig_data[base + 4]
        self.hash2 = struct.unpack_from("<I", self.sig_data, base + 5)[0]
        self.match_length = struct.unpack_from("<I", self.sig_data, base + 9)[0]

        self.name_raw = raw_name
        self.name_length = len(raw_name)
        self.flag_high = bool(self.flags & 0x80)
        self.flags_low = self.flags & 0x7F
        self.irc_special_case = self.flags_low in (1, 2)
        self.expected_size = base + 13

        self.decode_warnings = []
        if len(self.sig_data) != self.expected_size:
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(self.sig_data) - self.expected_size} bytes"
            )
        if self.match_length == 0 or self.match_length > 0x1000:
            self.decode_warnings.append(
                "Script window length outside the expected 1..0x1000 range"
            )

    def to_details(self) -> dict:
        return {
            "record_name": self.name,
            "has_name": self.name_length > 0,
            "hash1": self.hash1,
            "hash2": self.hash2,
            "match_length": self.match_length,
            "flags": self.flags,
            "flags_low": self.flags_low,
            "flag_0x80": self.flag_high,
            "irc_special_case": self.irc_special_case,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"NSCRIPT_SP hash1=0x{self.hash1:08x} hash2=0x{self.hash2:08x} "
            f"window={self.match_length} flags=0x{self.flags:02x}"
        )
        if self.name_length:
            text += f" name={self.name!r}"
        return text


class NscriptBruteSig(BaseSig):
    """SIGNATURE_TYPE_NSCRIPT_BRUTE (0x29) — script string brute pattern.

    Layout::

        u8   name_length      0..0x3f (0 = no inline name)
        u8   name[name_length]
        u8   kind_and_flag    low 7 bits = script type, bit 7 = extra flag
        u8   mode             0..2 (search direction / anchoring)
        u32  any_length       low 16 bits; 0xffffffff = unset
        u32  pattern_length
        u8   pattern[pattern_length]   literal text + 0x90 wildcards, ends 90 00

    ``kind`` values are one-based indexes into the ``Nscript:Type_*`` table:
    1 = vbs, 2 = js, 3 = bat, 4 = irc, 5 = ps, 6 = py; 0 and 7 mean "any"
    (the internal enum value is ``kind - 1``, or 6 for "any").  83% of the
    shipped records use "any".

    ``mode`` is the search direction: 1 = scan forward from the start, 2 =
    scan backward from the end, 0 = no anchor.  The engine stores it in bits
    5..6 of its flag word; bits 7..9 hold the script kind, bit ``0x0400`` is
    the kind byte's high bit and bit ``0x0800`` means the pattern has no
    ``90 1b`` token (i.e. it is contiguous and can be matched as-is).
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x29]

        raw_name, self.name, base = _read_name(self.sig_data, 0x3F)
        if len(self.sig_data) < base + 10:
            raise ValueError(
                f"Truncated {self.sig_type} header: {len(self.sig_data)} bytes"
            )

        self.kind_byte = self.sig_data[base]
        self.mode = self.sig_data[base + 1]
        self.any_length, self.pattern_length = struct.unpack_from(
            "<II", self.sig_data, base + 2
        )
        pattern_start = base + 10
        pattern_end = pattern_start + self.pattern_length
        if self.pattern_length == 0 or self.pattern_length > 0xFFFF:
            raise ValueError(
                f"Invalid {self.sig_type} pattern length {self.pattern_length}"
            )
        if pattern_end > len(self.sig_data):
            raise ValueError(
                f"Truncated {self.sig_type} pattern: need {self.pattern_length} bytes"
            )

        self.pattern = bytes(self.sig_data[pattern_start:pattern_end])
        self.name_raw = raw_name
        self.name_length = len(raw_name)
        self.kind = script_type_index(self.kind_byte)
        self.script_type = SCRIPT_TYPES[self.kind]
        self.kind_high_flag = bool(self.kind_byte & 0x80)
        self.loose_pattern = has_loose_token(self.pattern)
        self.wildcard_count = sum(1 for _ in iter_script_opcodes(self.pattern))
        self.opcode_counts = script_opcode_counts(self.pattern)
        self.uses_wildcards = any(
            opcode != 0x00 for _, opcode, _ in iter_script_opcodes(self.pattern)
        )

        # Mirror the engine's in-memory flag word (FUN_1803f8348).
        self.flags = (self.mode << 5) | (self.kind << 7)
        if self.kind_high_flag:
            self.flags |= 0x0400
        if not self.loose_pattern:
            self.flags |= 0x0800

        self.pattern_text = decode_script_pattern(self.pattern)

        self.decode_warnings = []
        if pattern_end != len(self.sig_data):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(self.sig_data) - pattern_end} bytes"
            )
        if not self.pattern.endswith(b"\x90\x00"):
            self.decode_warnings.append("Pattern does not end with the 0x90 0x00 terminator")
        if self.mode not in SCRIPT_MATCH_MODES:
            self.decode_warnings.append(f"Unknown script match mode {self.mode}")
        if self.kind_byte & 0x7F > 7:
            self.decode_warnings.append(
                f"Unknown script type byte 0x{self.kind_byte:02x}"
            )

    def to_details(self) -> dict:
        return {
            "record_name": self.name,
            "has_name": self.name_length > 0,
            "script_type": self.script_type,
            "script_type_id": self.kind,
            "kind_byte": self.kind_byte,
            "kind_high_flag": self.kind_high_flag,
            "mode": self.mode,
            "mode_label": SCRIPT_MATCH_MODES.get(self.mode, "unknown"),
            "any_length": self.any_length,
            "any_length_set": self.any_length != 0xFFFFFFFF,
            "pattern_length": self.pattern_length,
            "pattern_text": self.pattern_text,
            "wildcard_count": self.wildcard_count,
            "uses_wildcards": self.uses_wildcards,
            "loose_pattern": self.loose_pattern,
            "flag_word": self.flags,
            "opcode_counts": {f"{opcode:02x}": count
                              for opcode, count in sorted(self.opcode_counts.items())},
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"NSCRIPT_BRUTE {self.script_type} mode={self.mode} "
            f"len={self.pattern_length} {self.pattern_text!r}"
        )
        if self.name_length:
            text += f" name={self.name!r}"
        return text
