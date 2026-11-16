"""
PEHSTR and PEHSTR_EXT Signature Handler

Parses PE string pattern signatures from Microsoft Defender.
Based on documentation from "An unexpected journey into Microsoft Defender's signature World"

Key structures from PDF:

PEHSTR Header:
    typedef struct _STRUCT_PEHSTR_HEADER {
        UINT16 ui16Unknown;
        UINT8 ui8TresholdRequiredLow;
        UINT8 ui8TresholdRequiredHigh;
        UINT8 ui8SubRulesNumberLow;
        UINT8 ui8SubRulesNumberHigh;
        BYTE bEmpty;
        BYTE pbRuleData[];
    }

PEHSTR Sub-rule:
    typedef struct _STRUCT_RULE_PEHSTR {
        UINT8 ui8SubRuleWeightLow;
        UINT8 ui8SubRuleWeightHigh;
        UINT8 ui8SubRuleSize;
        BYTE pbSubRuleBytesToMatch[];
    }

PEHSTR_EXT Sub-rule (has extra code byte):
    typedef struct _STRUCT_RULE_PEHSTR_EXT {
        UINT8 ui8SubRuleWeightLow;
        UINT8 ui8SubRuleWeightHigh;
        UINT8 ui8SubRuleSize;
        UINT8 ui8CodeUnknown;
        BYTE pbSubRuleBytesToMatch[];
    }

Wildcard patterns in PEHSTR_EXT bytes_to_match:
    90 01 XX       - Match exactly XX bytes (any value) at this position
    90 02 XX       - Match 0 to XX bytes (variable length)
    90 03 XX YY    - Match Sequence_A (XX bytes) OR Sequence_B (YY bytes) following
    90 04 XX YY    - Regex-like pattern, XX = length, YY = pattern length (case sensitive)
    90 05 XX YY    - Regex-like pattern (case insensitive)
    90 00          - End marker
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Iterator
from io import BytesIO
import re


# Wildcard opcodes found in PEHSTR_EXT byte patterns
WILDCARD_PREFIX = 0x90
WC_SINGLE = 0x01      # 90 01 XX - Match exactly XX bytes
WC_RANGE = 0x02       # 90 02 XX - Match up to XX bytes
WC_OR = 0x03          # 90 03 XX YY - OR pattern
WC_REGEX = 0x04       # 90 04 XX YY - Regex pattern (case sensitive)
WC_REGEX_ICASE = 0x05 # 90 05 XX YY - Regex pattern (case insensitive)
WC_END = 0x00         # 90 00 - End marker


@dataclass
class WildcardPattern:
    """Represents a wildcard pattern in PEHSTR_EXT."""
    opcode: int
    param1: int = 0
    param2: int = 0
    data: bytes = b''

    @property
    def pattern_type(self) -> str:
        if self.opcode == WC_SINGLE:
            return "SINGLE_BYTE"
        elif self.opcode == WC_RANGE:
            return "RANGE"
        elif self.opcode == WC_OR:
            return "OR"
        elif self.opcode == WC_REGEX:
            return "REGEX"
        elif self.opcode == WC_REGEX_ICASE:
            return "REGEX_ICASE"
        elif self.opcode == WC_END:
            return "END"
        return f"UNKNOWN_{self.opcode:02X}"

    def to_yara(self) -> str:
        """Convert wildcard pattern to YARA syntax."""
        if self.opcode == WC_SINGLE:
            # Match exactly N bytes (any value)
            return " ".join(["??" for _ in range(self.param1)])
        elif self.opcode == WC_RANGE:
            # Match 0 to N bytes
            return f"[0-{self.param1}]"
        elif self.opcode == WC_OR:
            # OR pattern - need to show both sequences
            seq_a = self.data[:self.param1].hex()
            seq_b = self.data[self.param1:self.param1 + self.param2].hex()
            return f"({seq_a}|{seq_b})"
        elif self.opcode in (WC_REGEX, WC_REGEX_ICASE):
            # Regex-like pattern
            pattern = self.data[:self.param2].decode('ascii', errors='replace')
            return f"[{pattern}]" + ("{0," + str(self.param1) + "}")
        return ""


@dataclass
class PEHSTRSubRule:
    """Sub-rule within PEHSTR/PEHSTR_EXT signature."""
    weight_low: int
    weight_high: int
    size: int
    code_unknown: int  # Only meaningful in PEHSTR_EXT
    bytes_to_match: bytes
    wildcards: List[WildcardPattern] = field(default_factory=list)

    @property
    def weight(self) -> int:
        return self.weight_low | (self.weight_high << 8)

    def parse_wildcards(self) -> None:
        """Parse wildcard patterns from bytes_to_match."""
        self.wildcards = list(parse_wildcards(self.bytes_to_match))

    def to_yara_pattern(self) -> str:
        """Convert sub-rule to YARA hex pattern."""
        if not self.wildcards:
            self.parse_wildcards()

        if not self.wildcards:
            # No wildcards, simple hex pattern
            return "{ " + self.bytes_to_match.hex() + " }"

        # Build pattern with wildcards
        parts = []
        offset = 0

        for wc in self.wildcards:
            # Check for literal bytes before this wildcard
            wc_offset = self.bytes_to_match.find(bytes([WILDCARD_PREFIX]), offset)
            if wc_offset > offset:
                literal = self.bytes_to_match[offset:wc_offset]
                parts.append(literal.hex())

            parts.append(wc.to_yara())

            # Calculate offset after wildcard
            if wc.opcode == WC_SINGLE:
                offset = wc_offset + 3
            elif wc.opcode == WC_RANGE:
                offset = wc_offset + 3
            elif wc.opcode == WC_OR:
                offset = wc_offset + 4 + wc.param1 + wc.param2
            elif wc.opcode in (WC_REGEX, WC_REGEX_ICASE):
                offset = wc_offset + 4 + wc.param2
            elif wc.opcode == WC_END:
                offset = wc_offset + 2

        # Any remaining literal bytes
        if offset < len(self.bytes_to_match):
            parts.append(self.bytes_to_match[offset:].hex())

        return "{ " + " ".join(parts) + " }"

    def to_dict(self) -> dict:
        return {
            "weight": self.weight,
            "size": self.size,
            "code": self.code_unknown,
            "bytes_hex": self.bytes_to_match.hex(),
            "bytes_ascii": self.bytes_to_match.decode('ascii', errors='replace'),
            "yara_pattern": self.to_yara_pattern(),
            "wildcards": [{"type": w.pattern_type, "param1": w.param1, "param2": w.param2} for w in self.wildcards],
        }


@dataclass
class PEHSTRSignature:
    """Parsed PEHSTR or PEHSTR_EXT signature."""
    sig_type: int
    unknown: int
    threshold_low: int
    threshold_high: int
    num_subrules_low: int
    num_subrules_high: int
    subrules: List[PEHSTRSubRule] = field(default_factory=list)

    @property
    def threshold(self) -> int:
        return self.threshold_low | (self.threshold_high << 8)

    @property
    def num_subrules(self) -> int:
        return self.num_subrules_low | (self.num_subrules_high << 8)

    @property
    def type_name(self) -> str:
        if self.sig_type == 0x61:
            return "PEHSTR"
        elif self.sig_type == 0x78:
            return "PEHSTR_EXT"
        elif self.sig_type == 0x85:
            return "PEHSTR_EXT2"
        return f"UNKNOWN_0x{self.sig_type:02X}"

    def total_weight(self) -> int:
        """Calculate total weight of all sub-rules."""
        return sum(sr.weight for sr in self.subrules)

    def to_yara_rule(self, rule_name: str = "defender_rule") -> str:
        """Generate a YARA rule from this signature."""
        lines = [f'rule {rule_name} {{']
        lines.append('    meta:')
        lines.append(f'        threshold = {self.threshold}')
        lines.append(f'        type = "{self.type_name}"')
        lines.append('    strings:')

        for i, sr in enumerate(self.subrules):
            pattern = sr.to_yara_pattern()
            lines.append(f'        $sub_{i} = {pattern}  // weight={sr.weight}')

        lines.append('    condition:')
        # Build weighted condition
        weights = [f"({sr.weight} * #sub_{i})" for i, sr in enumerate(self.subrules)]
        lines.append(f'        ({" + ".join(weights)}) >= {self.threshold}')
        lines.append('}')

        return '\n'.join(lines)

    def to_dict(self) -> dict:
        return {
            "type": self.type_name,
            "threshold": self.threshold,
            "total_weight": self.total_weight(),
            "num_subrules": self.num_subrules,
            "subrules": [sr.to_dict() for sr in self.subrules],
        }


def parse_wildcards(data: bytes) -> Iterator[WildcardPattern]:
    """
    Parse wildcard patterns from PEHSTR_EXT bytes.

    Wildcard format from PDF:
        90 01 XX       - Match exactly XX bytes
        90 02 XX       - Match up to XX bytes (0 to XX)
        90 03 XX YY    - OR: match XX-byte seq OR YY-byte seq
        90 04 XX YY ZZ - Regex: XX=expected len, YY=pattern len, ZZ...=pattern
        90 05 XX YY ZZ - Same but case insensitive
        90 00          - End marker
    """
    offset = 0
    while offset < len(data) - 1:
        # Find next 0x90 prefix
        try:
            idx = data.index(WILDCARD_PREFIX, offset)
        except ValueError:
            break

        if idx + 1 >= len(data):
            break

        opcode = data[idx + 1]

        if opcode == WC_END:
            yield WildcardPattern(opcode=WC_END)
            offset = idx + 2

        elif opcode == WC_SINGLE and idx + 2 < len(data):
            param = data[idx + 2]
            yield WildcardPattern(opcode=WC_SINGLE, param1=param)
            offset = idx + 3

        elif opcode == WC_RANGE and idx + 2 < len(data):
            param = data[idx + 2]
            yield WildcardPattern(opcode=WC_RANGE, param1=param)
            offset = idx + 3

        elif opcode == WC_OR and idx + 3 < len(data):
            xx = data[idx + 2]
            yy = data[idx + 3]
            # Following bytes are the two sequences
            seq_data = data[idx + 4:idx + 4 + xx + yy]
            yield WildcardPattern(opcode=WC_OR, param1=xx, param2=yy, data=seq_data)
            offset = idx + 4 + xx + yy

        elif opcode == WC_REGEX and idx + 3 < len(data):
            xx = data[idx + 2]
            yy = data[idx + 3]
            pattern_data = data[idx + 4:idx + 4 + yy]
            yield WildcardPattern(opcode=WC_REGEX, param1=xx, param2=yy, data=pattern_data)
            offset = idx + 4 + yy

        elif opcode == WC_REGEX_ICASE and idx + 3 < len(data):
            xx = data[idx + 2]
            yy = data[idx + 3]
            pattern_data = data[idx + 4:idx + 4 + yy]
            yield WildcardPattern(opcode=WC_REGEX_ICASE, param1=xx, param2=yy, data=pattern_data)
            offset = idx + 4 + yy

        else:
            # Unknown pattern or not enough data, skip
            offset = idx + 1


def parse_pehstr_header(data: bytes) -> Tuple[int, int, int, int, int, int]:
    """
    Parse PEHSTR/PEHSTR_EXT header.

    Returns: (unknown, threshold_low, threshold_high, num_rules_low, num_rules_high, header_size)
    """
    if len(data) < 7:
        return 0, 0, 0, 0, 0, 0

    unknown = struct.unpack_from('<H', data, 0)[0]
    threshold_low = data[2]
    threshold_high = data[3]
    num_rules_low = data[4]
    num_rules_high = data[5]
    # byte 6 is empty/padding

    return unknown, threshold_low, threshold_high, num_rules_low, num_rules_high, 7


def parse_pehstr_subrules(data: bytes, num_rules: int, is_ext: bool = False) -> List[PEHSTRSubRule]:
    """
    Parse PEHSTR/PEHSTR_EXT sub-rules.

    PEHSTR uses 3-byte header per sub-rule.
    PEHSTR_EXT uses 4-byte header per sub-rule (extra code byte).
    """
    subrules = []
    offset = 0
    header_size = 4 if is_ext else 3

    for _ in range(num_rules):
        if offset + header_size > len(data):
            break

        weight_low = data[offset]
        weight_high = data[offset + 1]
        size = data[offset + 2]
        code_unknown = data[offset + 3] if is_ext else 0

        bytes_start = offset + header_size
        bytes_end = bytes_start + size

        if bytes_end > len(data):
            break

        bytes_to_match = data[bytes_start:bytes_end]

        sr = PEHSTRSubRule(
            weight_low=weight_low,
            weight_high=weight_high,
            size=size,
            code_unknown=code_unknown,
            bytes_to_match=bytes_to_match,
        )

        # Parse wildcards if this is an EXT type
        if is_ext:
            sr.parse_wildcards()

        subrules.append(sr)
        offset = bytes_end

    return subrules


def parse_pehstr_signature(sig_type: int, data: bytes) -> PEHSTRSignature:
    """Parse complete PEHSTR or PEHSTR_EXT signature."""
    unknown, thr_lo, thr_hi, nr_lo, nr_hi, hdr_size = parse_pehstr_header(data)

    num_rules = nr_lo | (nr_hi << 8)
    is_ext = sig_type in (0x78, 0x85)  # PEHSTR_EXT or PEHSTR_EXT2

    rule_data = data[hdr_size:]
    subrules = parse_pehstr_subrules(rule_data, num_rules, is_ext)

    return PEHSTRSignature(
        sig_type=sig_type,
        unknown=unknown,
        threshold_low=thr_lo,
        threshold_high=thr_hi,
        num_subrules_low=nr_lo,
        num_subrules_high=nr_hi,
        subrules=subrules,
    )


def analyze_pehstr_bytes(data: bytes) -> dict:
    """Analyze bytes for string patterns and wildcards."""
    result = {
        "length": len(data),
        "printable_ratio": sum(1 for b in data if 32 <= b < 127) / len(data) if data else 0,
        "has_wildcards": WILDCARD_PREFIX in data,
        "wildcards": [],
        "ascii_strings": [],
    }

    # Extract wildcards
    if result["has_wildcards"]:
        result["wildcards"] = [
            {"type": w.pattern_type, "param1": w.param1, "param2": w.param2}
            for w in parse_wildcards(data)
        ]

    # Extract ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{4,}')
    result["ascii_strings"] = [
        m.group(0).decode('ascii') for m in ascii_pattern.finditer(data)
    ]

    return result
