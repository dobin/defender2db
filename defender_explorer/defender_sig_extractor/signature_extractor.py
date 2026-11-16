"""
Comprehensive Microsoft Defender Signature Extractor

Extracts ALL signature types from VDM files, grouping them by threat.
Based on the TLV format documented in the Retooling.io PDF.

TLV Entry format:
    typedef struct _STRUCT_COMMON_SIGNATURE_TYPE {
        UINT8 ui8SignatureType;   // defines the type of the signature
        UINT8 ui8SizeLow;         // low byte size of the signature
        UINT16 ui16SizeHigh;      // high byte size of the signature
        BYTE pbRuleContent[];     // content of the rule
    };
    // Size = ui8SizeLow | (ui16SizeHigh << 8)

Threat structure:
    THREAT_BEGIN (0x5C) -> contains threat name
        SIGNATURE 1
        SIGNATURE 2
        ...
    THREAT_END (0x5D) -> contains signature ID
"""

import struct
from dataclasses import dataclass, field
from typing import List, Iterator, Optional, Dict, Any, Tuple
from pathlib import Path
import json

from .signature_types import get_type_name


# Signature type codes
THREAT_BEGIN = 0x5C
THREAT_END = 0x5D
PEHSTR = 0x61
PEHSTR_EXT = 0x78
PEHSTR_EXT2 = 0x85
DELTA_BLOB = 0x73
LUA_STANDALONE = 0x4C
LUA_SCRIPT = 0xBD  # Lua bytecode with 8-byte header (most common type)


@dataclass
class TLVEntry:
    """Raw TLV entry from signature stream."""
    sig_type: int
    size: int
    data: bytes
    offset: int

    @property
    def type_name(self) -> str:
        return get_type_name(self.sig_type)


@dataclass
class PEHSTRSubRule:
    """Sub-rule within PEHSTR/PEHSTR_EXT signature."""
    weight_low: int
    weight_high: int
    size: int
    code_unknown: int  # Only in PEHSTR_EXT
    bytes_to_match: bytes

    @property
    def weight(self) -> int:
        return self.weight_low | (self.weight_high << 8)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "weight": self.weight,
            "size": self.size,
            "bytes_hex": self.bytes_to_match.hex(),
            "bytes_ascii": self.bytes_to_match.decode('ascii', errors='replace'),
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
        return get_type_name(self.sig_type)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type_name,
            "threshold": self.threshold,
            "num_subrules": self.num_subrules,
            "subrules": [sr.to_dict() for sr in self.subrules],
        }


@dataclass
class ThreatDefinition:
    """A complete threat definition from THREAT_BEGIN to THREAT_END."""
    signature_id: int
    threat_name: str
    signatures: List[TLVEntry] = field(default_factory=list)
    pehstr_signatures: List[PEHSTRSignature] = field(default_factory=list)
    lua_scripts: List[bytes] = field(default_factory=list)
    raw_data: bytes = b''

    def to_dict(self) -> Dict[str, Any]:
        sig_types = {}
        for sig in self.signatures:
            type_name = sig.type_name
            if type_name not in sig_types:
                sig_types[type_name] = 0
            sig_types[type_name] += 1

        return {
            "signature_id": f"0x{self.signature_id:08X}",
            "threat_name": self.threat_name,
            "signature_count": len(self.signatures),
            "signature_types": sig_types,
            "pehstr_count": len(self.pehstr_signatures),
            "lua_script_count": len(self.lua_scripts),
        }


def parse_tlv_stream(data: bytes) -> Iterator[TLVEntry]:
    """
    Parse TLV (Type-Length-Value) signature stream.

    TLV Entry format:
    - sig_type: uint8   (signature type code)
    - size_low: uint8   (low byte of size)
    - size_high: uint16 (high bytes of size, little-endian)
    - value: bytes[size] (payload data)

    Size = size_low | (size_high << 8)
    """
    offset = 0
    while offset + 4 <= len(data):
        # Read TLV header
        sig_type = data[offset]
        size_low = data[offset + 1]
        size_high = struct.unpack_from('<H', data, offset + 2)[0]

        size = size_low | (size_high << 8)

        # Sanity check
        if size > len(data) - offset - 4:
            break

        # Extract payload
        payload_offset = offset + 4
        payload = data[payload_offset:payload_offset + size]

        yield TLVEntry(
            sig_type=sig_type,
            size=size,
            data=payload,
            offset=offset
        )

        offset = payload_offset + size


def parse_threat_begin(data: bytes) -> Tuple[int, str]:
    """
    Parse THREAT_BEGIN (0x5C) payload to extract threat name.

    Structure from PDF:
        typedef struct _STRUCT_SIG_TYPE_THREAT_BEGIN {
            UINT32 ui32SignatureId;
            BYTE unknownBytes1[6];
            UINT8 ui8SizeThreatName;
            BYTE unknownBytes2[2];
            CHAR lpszThreatName[ui8SizeThreatName];
            BYTE unknownBytes3[9];
        }
    """
    if len(data) < 13:
        return 0, ""

    # Signature ID is first 4 bytes
    sig_id = struct.unpack_from('<I', data, 0)[0]

    # Skip 6 unknown bytes, then threat name size at offset 10
    if len(data) > 10:
        name_size = data[10]
        # Skip 2 more bytes, name starts at offset 13
        if len(data) >= 13 + name_size:
            threat_name = data[13:13 + name_size].decode('ascii', errors='replace').rstrip('\x00')
            return sig_id, threat_name

    return sig_id, ""


def parse_threat_end(data: bytes) -> int:
    """Parse THREAT_END (0x5D) payload to extract signature ID."""
    if len(data) >= 4:
        return struct.unpack_from('<I', data, 0)[0]
    return 0


def parse_pehstr_header(data: bytes) -> Tuple[int, int, int, int, int, int]:
    """
    Parse PEHSTR/PEHSTR_EXT header.

    Structure from PDF:
        typedef struct _STRUCT_PEHSTR_HEADER {
            UINT16 ui16Unknown;
            UINT8 ui8TresholdRequiredLow;
            UINT8 ui8TresholdRequiredHigh;
            UINT8 ui8SubRulesNumberLow;
            UINT8 ui8SubRulesNumberHigh;
            BYTE bEmpty;
            BYTE pbRuleData[];
        }

    Returns: (unknown, threshold_low, threshold_high, num_rules_low, num_rules_high, header_size)
    """
    if len(data) < 7:
        return 0, 0, 0, 0, 0, 0

    unknown = struct.unpack_from('<H', data, 0)[0]
    threshold_low = data[2]
    threshold_high = data[3]
    num_rules_low = data[4]
    num_rules_high = data[5]
    # byte 6 is empty

    return unknown, threshold_low, threshold_high, num_rules_low, num_rules_high, 7


def parse_pehstr_subrules(data: bytes, num_rules: int, is_ext: bool = False) -> List[PEHSTRSubRule]:
    """
    Parse PEHSTR/PEHSTR_EXT sub-rules.

    PEHSTR sub-rule (3 bytes header):
        - ui8SubRuleWeightLow
        - ui8SubRuleWeightHigh
        - ui8SubRuleSize
        - pbSubRuleBytesToMatch[]

    PEHSTR_EXT sub-rule (4 bytes header):
        - ui8SubRuleWeightLow
        - ui8SubRuleWeightHigh
        - ui8SubRuleSize
        - ui8CodeUnknown
        - pbSubRuleBytesToMatch[]
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

        subrules.append(PEHSTRSubRule(
            weight_low=weight_low,
            weight_high=weight_high,
            size=size,
            code_unknown=code_unknown,
            bytes_to_match=bytes_to_match,
        ))

        offset = bytes_end

    return subrules


def parse_pehstr_signature(sig_type: int, data: bytes) -> PEHSTRSignature:
    """Parse complete PEHSTR or PEHSTR_EXT signature."""
    unknown, thr_lo, thr_hi, nr_lo, nr_hi, hdr_size = parse_pehstr_header(data)

    num_rules = nr_lo | (nr_hi << 8)
    is_ext = sig_type in (PEHSTR_EXT, PEHSTR_EXT2)

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


def extract_threats(data: bytes) -> Iterator[ThreatDefinition]:
    """
    Extract all threat definitions from decompressed VDM data.

    Groups signatures between THREAT_BEGIN and THREAT_END markers.
    """
    current_threat: Optional[ThreatDefinition] = None

    for entry in parse_tlv_stream(data):
        if entry.sig_type == THREAT_BEGIN:
            # Start of new threat
            sig_id, threat_name = parse_threat_begin(entry.data)
            current_threat = ThreatDefinition(
                signature_id=sig_id,
                threat_name=threat_name,
            )

        elif entry.sig_type == THREAT_END:
            # End of threat - yield it
            if current_threat is not None:
                yield current_threat
                current_threat = None

        elif current_threat is not None:
            # Add signature to current threat
            current_threat.signatures.append(entry)

            # Parse specific signature types
            if entry.sig_type in (PEHSTR, PEHSTR_EXT, PEHSTR_EXT2):
                try:
                    pehstr = parse_pehstr_signature(entry.sig_type, entry.data)
                    current_threat.pehstr_signatures.append(pehstr)
                except Exception:
                    pass

            elif entry.sig_type in (LUA_STANDALONE, LUA_SCRIPT):
                # Lua bytecode - extract it
                # LUA_SCRIPT (0xBD) has 8-byte header before Lua magic
                # LUA_STANDALONE (0x4C) may also have header
                lua_magic = b'\x1bLuaQ'
                idx = entry.data.find(lua_magic)
                if idx >= 0:
                    current_threat.lua_scripts.append(entry.data[idx:])
                else:
                    current_threat.lua_scripts.append(entry.data)


def count_signature_types(data: bytes) -> Dict[str, int]:
    """Count occurrences of each signature type in VDM data."""
    counts: Dict[str, int] = {}

    for entry in parse_tlv_stream(data):
        type_name = entry.type_name
        if type_name not in counts:
            counts[type_name] = 0
        counts[type_name] += 1

    return counts


def extract_all_signatures(data: bytes) -> List[TLVEntry]:
    """Extract all raw TLV signatures from VDM data."""
    return list(parse_tlv_stream(data))


def extract_lua_signatures(data: bytes) -> List[bytes]:
    """Extract all Lua bytecode from VDM data."""
    lua_scripts = []
    lua_magic = b'\x1bLuaQ'

    for entry in parse_tlv_stream(data):
        if entry.sig_type in (LUA_STANDALONE, LUA_SCRIPT):
            idx = entry.data.find(lua_magic)
            if idx >= 0:
                lua_scripts.append(entry.data[idx:])
            else:
                lua_scripts.append(entry.data)

    return lua_scripts


def export_threats_json(threats: List[ThreatDefinition], output_path: str) -> None:
    """Export threats to JSON file."""
    data = [t.to_dict() for t in threats]
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)


class SignatureExtractor:
    """High-level signature extractor for VDM files."""

    def __init__(self, vdm_data: bytes):
        self.data = vdm_data

    def get_signature_counts(self) -> Dict[str, int]:
        """Get counts of each signature type."""
        return count_signature_types(self.data)

    def extract_threats(self) -> List[ThreatDefinition]:
        """Extract all threat definitions."""
        return list(extract_threats(self.data))

    def extract_lua_scripts(self) -> List[bytes]:
        """Extract all Lua bytecode."""
        return extract_lua_signatures(self.data)

    def extract_pehstr_signatures(self) -> List[PEHSTRSignature]:
        """Extract and parse all PEHSTR/PEHSTR_EXT signatures."""
        sigs = []
        for entry in parse_tlv_stream(self.data):
            if entry.sig_type in (PEHSTR, PEHSTR_EXT, PEHSTR_EXT2):
                try:
                    sig = parse_pehstr_signature(entry.sig_type, entry.data)
                    sigs.append(sig)
                except Exception:
                    pass
        return sigs

    def get_raw_signatures(self) -> List[TLVEntry]:
        """Get all raw TLV entries."""
        return extract_all_signatures(self.data)

    def summary(self) -> Dict[str, Any]:
        """Get summary of VDM contents."""
        counts = self.get_signature_counts()
        total = sum(counts.values())

        return {
            "total_signatures": total,
            "signature_types": len(counts),
            "type_counts": dict(sorted(counts.items(), key=lambda x: -x[1])),
            "has_threats": counts.get("SIGNATURE_TYPE_THREAT_BEGIN", 0) > 0,
            "threat_count": counts.get("SIGNATURE_TYPE_THREAT_BEGIN", 0),
            "lua_count": (
                counts.get("SIGNATURE_TYPE_LUASTANDALONE", 0) +
                counts.get("LUA_STANDALONE", 0) +
                counts.get("LUASCRIPT", 0) +
                counts.get("LUA_SCRIPT", 0) +
                counts.get("UNKNOWN_0xBD", 0)  # Before we add proper name
            ),
            "pehstr_count": (
                counts.get("SIGNATURE_TYPE_PEHSTR", 0) +
                counts.get("SIGNATURE_TYPE_PEHSTR_EXT", 0) +
                counts.get("SIGNATURE_TYPE_PEHSTR_EXT2", 0)
            ),
        }
