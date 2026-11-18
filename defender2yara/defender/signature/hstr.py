from typing import Tuple,List
import struct
from .base import BaseSig
from .nscript import SCRIPT_OPCODE_TABLE
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
    "SIGNATURE_TYPE_CMDHSTR_FAST_EXT",
    "SIGNATURE_TYPE_MDBHSTR_EXT",
    "SIGNATURE_TYPE_DMGHSTR_EXT"
]

#: ``*HSTR_EXT`` types whose sub-rule bytes are human-readable strings rather
#: than code fragments / raw bytes.
TEXTUAL_HSTR_SIGS = (
    "SIGNATURE_TYPE_DEXHSTR_EXT",
    "SIGNATURE_TYPE_JAVAHSTR_EXT",
    "SIGNATURE_TYPE_CMDHSTR_EXT",
    "SIGNATURE_TYPE_CMDHSTR_FAST_EXT",
    "SIGNATURE_TYPE_ELFHSTR_EXT",
    "SIGNATURE_TYPE_MACHOHSTR_EXT",
    "SIGNATURE_TYPE_DOSHSTR_EXT",
    "SIGNATURE_TYPE_MACROHSTR_EXT",
    "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    "SIGNATURE_TYPE_INNOHSTR_EXT",
    "SIGNATURE_TYPE_ARHSTR_EXT",
    "SIGNATURE_TYPE_ARHSTR_POSIX_EXT",
    "SIGNATURE_TYPE_MDBHSTR_EXT",
    "SIGNATURE_TYPE_DMGHSTR_EXT",
    "SIGNATURE_TYPE_WASMHSTR_EXT",
)

WILDCARD_MARKER = 0x90


def _opcode_token_length(pattern: bytes, offset: int) -> int:
    """Length in bytes of the ``90 xx`` wildcard token at *offset*.

    Mirrors ``FUN_180183298`` / ``FUN_180181a7c`` in mpengine: the 50-entry
    table at ``0x180c94d50`` gives ``(kind, length, operand_index)`` per
    opcode; opcode 3 carries a byte-class mask length at +3, kinds
    4/5/0x19/0x1a append the length byte at +3 and kind 0x17 the byte at +2.
    """
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


def _looks_like_utf16(data: bytes) -> bool:
    """Heuristic: UTF-16LE ASCII text (every second byte is zero)."""
    if len(data) < 4:
        return False
    pairs = len(data) // 2
    if not pairs:
        return False
    zeros = sum(1 for i in range(pairs) if data[2 * i + 1] == 0)
    printable = sum(
        1 for i in range(pairs)
        if data[2 * i] == 0 or 0x20 <= data[2 * i] < 0x7F
    )
    return zeros >= pairs * 0.8 and printable >= pairs * 0.8


def _decode_literal(data: bytes, wide: bool) -> str:
    if not data:
        return ""
    if wide:
        if len(data) % 2:
            data = data[:-1]
        try:
            text = data.decode("utf-16-le")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
    return "".join(
        char if char >= " " and char != "\x7f" else f"\\x{ord(char):02x}"
        for char in text
    )


def decode_hstr_pattern(pattern: bytes) -> Tuple[str, str]:
    """Render an ``*HSTR_EXT`` sub-rule pattern as text.

    Returns ``(text, encoding)`` where *encoding* is ``"utf-16-le"``,
    ``"ascii"`` or ``"binary"``.  ASCII and UTF-16LE string fragments are both
    common: command-line patterns (``CMDHSTR_EXT``) are normally UTF-16LE,
    DEX/Java string-table patterns are UTF-8, and the remaining types hold code
    fragments.

    Wildcard opcodes from the engine table at ``0x180c94d50`` are rendered as
    ``<skip N>`` / ``<skip 0..N>`` and other opcodes as ``<op XX ...>``.
    """
    literals = bytearray()
    chunks: List[Tuple[str, bytes]] = []
    offset = 0
    size = len(pattern)
    while offset < size:
        if pattern[offset] == WILDCARD_MARKER and offset + 1 < size:
            opcode = pattern[offset + 1]
            if opcode == 0x00:
                break  # NUL terminator
            length = _opcode_token_length(pattern, offset)
            token = pattern[offset:offset + length]
            if literals:
                chunks.append(("literal", bytes(literals)))
                literals.clear()
            if opcode == 0x01 and len(token) >= 3:
                chunks.append(("skip", token))
            elif opcode == 0x02 and len(token) >= 3:
                chunks.append(("skip_range", token))
            elif opcode == WILDCARD_MARKER:
                literals.append(WILDCARD_MARKER)
            else:
                chunks.append(("op", token))
            offset += length
            continue
        literals.append(pattern[offset])
        offset += 1
    if literals:
        chunks.append(("literal", bytes(literals)))

    literal_bytes = b"".join(payload for kind, payload in chunks if kind == "literal")
    wide = _looks_like_utf16(literal_bytes)
    encoding = "utf-16-le" if wide else "ascii"

    out: List[str] = []
    binary = False
    for kind, payload in chunks:
        if kind == "literal":
            text = _decode_literal(payload, wide)
            if not text and payload:
                binary = True
            out.append(text)
        elif kind == "skip":
            n = payload[2]
            out.append(f"<skip {n}>")
            if wide and n % 2:
                out.append("?")
        elif kind == "skip_range":
            n = payload[2]
            out.append(f"<skip 0..{n}>")
        elif kind == "op":
            opcode = payload[1]
            if opcode == 0x03 and len(payload) >= 4:
                # 90 03 <consume> <mask_len> <mask bytes>
                consume = payload[2]
                mask_len = payload[3]
                mask = payload[4:4 + mask_len]
                parts = []
                i = 0
                while i < len(mask):
                    if i + 2 < len(mask) and mask[i + 1] == 0x2D:
                        parts.append(f"{mask[i]:02x}-{mask[i + 2]:02x}")
                        i += 3
                    else:
                        parts.append(f"{mask[i]:02x}")
                        i += 1
                out.append(
                    f"<any-of {{{','.join(parts)}}} x{consume}>"
                )
            elif opcode in (0x04, 0x05) and len(payload) >= 4:
                repeat, plen = payload[2], payload[3]
                part = payload[4:4 + plen]
                body = _decode_literal(part, wide) or part.hex()
                if opcode == 0x04:
                    out.append(f"<repeat {repeat} of {body}>")
                else:
                    out.append(f"<repeat 0..{repeat} of {body}>")
            else:
                operands = payload[2:]
                out.append(
                    f"<op {opcode:02x}"
                    + (f" {operands.hex()}" if operands else "")
                    + ">"
                )
    if binary and not any(ord(c) > 0x7F or c.isprintable() for c in "".join(out)):
        encoding = "binary"
    return "".join(out), encoding


class HStrSig(BaseSig):
    def to_details(self) -> dict:
        return {
            "unknown_u16_1": self.unknown_u16_1,
            "threshold": self.threshold,
            "rule_numbers": self.rule_numbers,
            "unknown_u8_1": self.unknown_u8_1,
            "decode_warnings": list(self.decode_warnings),
            "subrules": [rule.to_details() for rule in self.subrules],
        }

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
        self.decode_warnings = []
        self.subrules = []
        pos = 7
        while pos < len(self.sig_data):
            subrule = HStrSubRule(self.sig_data,pos)
            # no more subrule
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            pos += 3 + subrule.rule_size
            if pos > len(self.sig_data):
                self.decode_warnings.append("Truncated HSTR subrule pattern")
        if self.rule_numbers and len(self.subrules) < self.rule_numbers:
            self.decode_warnings.append("Fewer HSTR subrules than declared")


class HStrExtSig(BaseSig):
    """
    Generic ``*HSTR_EXT`` signature (0x78, 0x8c, 0x8d, 0x8e, 0x8f, 0xbe, ...).

    Layout, confirmed against every ``*HSTR_EXT`` record in the shipped
    database and against the mpengine parser ``FUN_180182d14``::

        u16  unknown        total positive weight in most records (== threshold)
        u16  threshold      minimum total sub-rule weight
        u16  rule_numbers   number of sub-rules that follow
        u8   name[]         NUL-terminated label / definition name
        sub-rule[rule_numbers]:
            i16  weight
            u8   size
            u8   flags      bit 0 case-sensitive, bit 1 wildcard pattern,
                            bit 7 extended header
            u8   extra      only when flags & 0x80
            u8   bytes[size]
        u16  tail_word1     optional; engine stores it at record+0x10
        u16  tail_word2     optional; engine stores it at record+0x0c

    The byte at offset 6 is *not* a reserved byte: it is the first byte of a
    NUL-terminated name string.  In compiled records the name is empty, so the
    byte is simply ``0x00`` and the sub-rules start at offset 7.  In
    ``!InfrastructureShared`` records the field holds the definition/name
    reference, e.g. ``!#HSTR:StringCodeForMshta.A!pli``; the sub-rules still
    follow the NUL.  ``FUN_180184898`` strips this label when it builds the
    packed record id, which confirms byte 6 is the name start.

    Bounding the sub-rule loop with ``rule_numbers`` (instead of scanning for
    a zero weight) keeps several malformed-looking records from overrunning
    their payload, e.g. ``VirTool:Win32/CeeInject.gen!HP``.

    ``PEHSTR_EXT``/``PEHSTR_EXT2`` bytes are PE code fragments and wildcard
    opcodes, not strings.  Their details therefore contain only the hex
    pattern; the other ``*HSTR_EXT`` kinds (e.g. DEX/Java/command-line string
    fragments) keep the best-effort text rendering.
    """

    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type in HSTR_EXT_SIGS

        if len(self.sig_data) < 7:
            raise ValueError(
                f"Unexpected {self.sig_type} payload size: {len(self.sig_data)}"
            )

        # parse signature data header
        self.unknown_u16_1 = struct.unpack('<H',self.sig_data[0:2])[0]
        self.threshold = struct.unpack('<H',self.sig_data[2:4])[0]
        self.rule_numbers = struct.unpack('<H',self.sig_data[4:6])[0]
        self.unknown_u8_1 = self.sig_data[6]

        self.decode_warnings = []
        # byte 6 starts an optional NUL-terminated name
        name_end = self.sig_data.find(b"\x00", 6)
        if name_end < 0:
            # Malformed / legacy: keep the old "reserved byte" assumption.
            self.decode_warnings.append("Unterminated HSTR_EXT name; used legacy layout")
            self.name_raw = b""
            self.name = ""
            rules_pos = 7
        else:
            self.name_raw = self.sig_data[6:name_end]
            self.name = self.name_raw.decode("utf-8", "replace")
            rules_pos = name_end + 1

        # parse subrules
        self.subrules = []
        if self.rule_numbers:
            self.subrules_end = self._parse_counted_subrules(rules_pos)
            if len(self.subrules) < self.rule_numbers:
                self.decode_warnings.append("Fewer HSTR_EXT subrules than declared")
        else:
            self.subrules_end = self._parse_terminated_subrules(rules_pos)

        if self.subrules_end > len(self.sig_data):
            self.decode_warnings.append("Truncated HSTR_EXT subrule pattern")

        # trailing data: up to two u16 option words.  The engine reads the
        # first into record+0x10 (named ``end_marker`` here for compatibility)
        # and the second into record+0x0c (``flags``).  There is no explicit
        # terminator between the last sub-rule and these words.
        self.tail = bytes(self.sig_data[self.subrules_end:])
        self.tail_words: List[int] = []
        for offset in range(0, len(self.tail) - 1, 2):
            self.tail_words.append(struct.unpack_from('<H', self.tail, offset)[0])
        self.end_marker = self.tail_words[0] if self.tail_words else None
        self.flags = self.tail_words[1] if len(self.tail_words) > 1 else 0
        self.flags_present = len(self.tail_words) > 1

    @property
    def name_present(self) -> bool:
        return len(self.name_raw) > 0

    @property
    def textual(self) -> bool:
        return self.sig_type in TEXTUAL_HSTR_SIGS

    @property
    def patterns(self) -> List[str]:
        """Best-effort text rendering of every sub-rule pattern."""
        return [rule.pattern_text for rule in self.subrules]

    def to_details(self) -> dict:
        include_text = self.textual
        return {
            "unknown_u16_1": self.unknown_u16_1,
            "threshold": self.threshold,
            "rule_numbers": self.rule_numbers,
            "unknown_u8_1": self.unknown_u8_1,
            "name": self.name,
            "name_present": self.name_present,
            "decode_warnings": list(self.decode_warnings),
            "end_marker": self.end_marker,
            "flags": self.flags,
            "flags_present": self.flags_present,
            "tail_words": list(self.tail_words),
            "patterns": self.patterns if include_text else [],
            "subrules": [
                rule.to_details(include_text=include_text)
                for rule in self.subrules
            ],
        }

    def _parse_counted_subrules(self, ptr: int) -> int:
        data = self.sig_data
        for _ in range(self.rule_numbers):
            if ptr + 4 > len(data):
                break
            subrule = HStrExtSubRule(data, ptr)
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            ptr += subrule.entry_size
        return ptr

    def _parse_terminated_subrules(self, ptr: int) -> int:
        """Fallback for records without a usable rule count."""
        data = self.sig_data
        while ptr + 4 <= len(data):
            subrule = HStrExtSubRule(data, ptr)
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            ptr += subrule.entry_size
        return ptr


class DexHStrExtSig(HStrExtSig):
    """
    SIGNATURE_TYPE_DEXHSTR_EXT (0xbe).

    This is the DEX / Android (Dalvik ``classes.dex``) flavour of the generic
    ``HSTR_EXT`` string pattern signature.  It is kind 5 in the engine's HSTR
    type table (``0x180c8b800``, see ``FUN_180a1f948``); the layout is
    identical to the other ``*HSTR_EXT`` types.

    The patterns are string-table fragments: UTF-8 text (or binary uleb128
    string headers) with HSTR ``0x90`` wildcards.  DEX's ``string_data_item``
    prefixes every string with a uleb128 length, so DEX signatures often skip
    those bytes explicitly::

        68 69 2c 78 69 61 6f 6c 75 90 01 02 68 69 2c 6c 69 71 69 61 6e
        "hi,xiaolu"                skip 2         "hi,liqian"

    Two details over the plain HSTR_EXT layout are common:

    * About 14% of records carry one more ``u16`` after the sub-rule list
      (``flags`` / :attr:`tail_words`).  It behaves like a small option
      bitmask (observed 1..46); the engine stores it at record+0x0c.  Its
      exact meaning is not confirmed (likely a scan/weight option).
    * Records in the ``!InfrastructureShared`` bucket use the name field:
      byte 6 starts a NUL-terminated reference such as
      ``!#Tel:Trojan:AndroidOS/Fakecalls.YU``.  The sub-rules still follow the
      name and are valid patterns (older versions of this parser dropped
      them).  Exposed as :attr:`name_reference` / :attr:`is_name_reference`
      while the patterns remain available.
    """

    def to_details(self) -> dict:
        details = super().to_details()
        details.update({
            "is_name_reference": self.is_name_reference,
            "name_reference": self.name_reference,
            "dex_patterns": self.patterns,
        })
        return details

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        super().__init__(data, ptr)
        assert self.sig_type == SIG_TYPES[0xBE]

        self.is_name_reference = self.name_present
        self.name_reference = ""
        if self.name_present:
            # In !InfrastructureShared the name is a definition/list label
            # (e.g. "!#Tel:Trojan:AndroidOS/Fakecalls.YU").  The patterns
            # after it are still real DEX string patterns.
            self.name_reference = (
                self.name[1:] if self.name.startswith("!") else self.name
            )


class CmdHStrExtSig(HStrExtSig):
    """
    SIGNATURE_TYPE_CMDHSTR_EXT (0xd7) / CMDHSTR_FAST_EXT (0xdd).

    Command-line content signatures.  They are kind 11 (0xd7) and kind 16
    (0xdd) in the engine's HSTR type table (``0x180c8b800``, initialised by
    ``FUN_180a1f948``) and use exactly the same record layout as the other
    ``*HSTR_EXT`` types.

    The patterns are matched against the **command line of a process**, not
    against file bytes.  The ``cmdlinescan`` module (``FUN_180afde40``) builds
    command-line candidates and calls the kind-11 matcher
    (``FUN_18024af38`` -> ``FUN_180249264(0xb, ...)``); the scan callback is
    ``FUN_180afce70``.  Candidate strings include the raw UTF-16 command line,
    an extracted argument, the NormalizationKC form, and base64-decoded
    PowerShell.  The engine reports these hits with caller ids
    ``HSTR_CALLER_CMDLINE``, ``HSTR_CALLER_TSKSCHED_CMDLINE`` and
    ``HSTR_CALLER_BITS_CMDLINE``; ``#ClnCmdLine`` is the clean-verdict tag.

    Command-line patterns are usually UTF-16LE (Windows command lines are wide
    strings) and about a third use HSTR wildcards.  ``CMDHSTR_FAST_EXT`` is
    the same format registered for the fast/low-fi command-line path; the
    shipped definitions contain only two test records.
    """

    SCAN_TARGETS = (
        "command_line",
        "task_scheduler_command_line",
        "bits_command_line",
    )

    SCAN_CALLERS = (
        "HSTR_CALLER_CMDLINE",
        "HSTR_CALLER_TSKSCHED_CMDLINE",
        "HSTR_CALLER_BITS_CMDLINE",
    )

    def to_details(self) -> dict:
        details = super().to_details()
        details.update({
            "scan_target": "command_line",
            "scan_callers": list(self.SCAN_CALLERS),
            "scan_targets": list(self.SCAN_TARGETS),
            "command_line_patterns": self.patterns,
            "variant": "fast" if self.sig_type.endswith("_FAST_EXT") else "normal",
        })
        return details

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        super().__init__(data, ptr)
        assert self.sig_type in (
            SIG_TYPES[0xD7],
            SIG_TYPES[0xDD],
        )
