"""
Lua Signature Handler

Parses and decompiles Lua signatures from Microsoft Defender.
"""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from io import BytesIO

from ..signature_types import SigType
from ..lua_decompiler.undump import undump, is_lua_bytecode
from ..lua_decompiler.mplua_converter import (
    is_mplua, convert_mplua_to_lua51, extract_lua_from_signature
)
from ..lua_decompiler.backend import decompile as backend_decompile


@dataclass
class LuaSignature:
    """Parsed Lua signature."""
    threat_name: str
    attribute: str
    category: str
    lua_bytecode: bytes
    decompiled_source: Optional[str] = None
    sig_type: SigType = SigType.LUA_STANDALONE
    raw_data: bytes = b''

    @property
    def has_bytecode(self) -> bool:
        return len(self.lua_bytecode) > 0 and is_lua_bytecode(self.lua_bytecode)


class LuaSignatureParser:
    """
    Parser for Lua signature entries.

    Lua signatures have varying formats depending on subtype.
    Common structure:
    - Threat name (null-terminated string)
    - Attribute flags
    - Category
    - Lua bytecode
    """

    def __init__(self, sig_type: SigType, data: bytes):
        self.sig_type = sig_type
        self.data = data
        self.stream = BytesIO(data)

    def _read_null_string(self) -> str:
        """Read null-terminated string."""
        chars = []
        while True:
            b = self.stream.read(1)
            if not b or b == b'\x00':
                break
            chars.append(b)
        return b''.join(chars).decode('utf-8', errors='replace')

    def _read_uint16(self) -> int:
        """Read 16-bit unsigned integer."""
        data = self.stream.read(2)
        if len(data) < 2:
            return 0
        return struct.unpack('<H', data)[0]

    def _read_uint32(self) -> int:
        """Read 32-bit unsigned integer."""
        data = self.stream.read(4)
        if len(data) < 4:
            return 0
        return struct.unpack('<I', data)[0]

    def _find_lua_bytecode(self) -> Tuple[int, bytes]:
        """Find Lua bytecode in the signature data."""
        # Search for Lua signature
        lua_sig = b'\x1bLua'
        idx = self.data.find(lua_sig)
        if idx == -1:
            return -1, b''

        return idx, self.data[idx:]

    def parse(self) -> LuaSignature:
        """Parse the Lua signature."""
        # Try to extract metadata first
        threat_name = ""
        attribute = ""
        category = ""

        # Check for common header patterns
        # Pattern 1: Direct threat name at start
        if not self.data.startswith(b'\x1bLua'):
            # Try to read threat name
            threat_name = self._read_null_string()

            # Try to read attribute
            try:
                attr_len = self._read_uint16()
                if attr_len < 256:  # Sanity check
                    attribute = self.stream.read(attr_len).decode('utf-8', errors='replace')
            except Exception:
                pass

            # Try to read category
            try:
                cat_len = self._read_uint16()
                if cat_len < 256:
                    category = self.stream.read(cat_len).decode('utf-8', errors='replace')
            except Exception:
                pass

        # Find and extract Lua bytecode
        bytecode_offset, bytecode = self._find_lua_bytecode()

        return LuaSignature(
            threat_name=threat_name,
            attribute=attribute,
            category=category,
            lua_bytecode=bytecode,
            sig_type=self.sig_type,
            raw_data=self.data
        )


def parse_lua_signature(sig_type: int, data: bytes) -> LuaSignature:
    """Parse a Lua signature from raw data."""
    try:
        st = SigType(sig_type)
    except ValueError:
        st = SigType.LUA_STANDALONE

    parser = LuaSignatureParser(st, data)
    return parser.parse()


def decompile_lua_signature(sig: LuaSignature) -> str:
    """Decompile a Lua signature to source code.

    Uses the configured backend (Python or Docker luadec) with MpLua format
    auto-conversion.

    Args:
        sig: The Lua signature to decompile

    Returns:
        Decompiled Lua source code with metadata header
    """
    if not sig.has_bytecode:
        return "-- No valid Lua bytecode found"

    try:
        bytecode = sig.lua_bytecode

        # Add metadata as comments
        header_lines = []
        if sig.threat_name:
            header_lines.append(f"-- Threat: {sig.threat_name}")
        if sig.attribute:
            header_lines.append(f"-- Attribute: {sig.attribute}")
        if sig.category:
            header_lines.append(f"-- Category: {sig.category}")
        header_lines.append(f"-- Type: {sig.sig_type.name}")
        header_lines.append("")

        # Decompile using the configured backend (handles MpLua conversion)
        source = backend_decompile(bytecode)

        return "\n".join(header_lines) + source

    except Exception as e:
        return f"-- Decompilation failed: {e}\n-- Raw bytecode: {sig.lua_bytecode[:100].hex()}..."


def extract_lua_from_raw(data: bytes) -> Optional[bytes]:
    """Extract Lua bytecode from arbitrary data."""
    return extract_lua_from_signature(data)


def get_lua_info(data: bytes) -> dict:
    """Get information about Lua bytecode."""
    if not is_lua_bytecode(data):
        # Try to find embedded bytecode
        extracted = extract_lua_from_signature(data)
        if extracted:
            data = extracted
        else:
            return {"valid": False, "error": "No Lua bytecode found"}

    info = {
        "valid": True,
        "is_mplua": is_mplua(data),
        "size": len(data),
    }

    try:
        if is_mplua(data):
            data = convert_mplua_to_lua51(data)

        chunk = undump(data)
        info.update({
            "name": chunk.name or "(main)",
            "num_params": chunk.num_params,
            "is_vararg": chunk.is_vararg,
            "max_stack": chunk.max_stack,
            "num_instructions": len(chunk.instructions),
            "num_constants": len(chunk.constants),
            "num_protos": len(chunk.protos),
            "num_locals": len(chunk.locals),
            "num_upvalues": chunk.num_upvalues,
        })
    except Exception as e:
        info["parse_error"] = str(e)

    return info


def analyze_lua_signature(sig: LuaSignature) -> dict:
    """
    Analyze a Lua signature and extract logic summary.

    Uses the LuaLogicAnalyzer to extract human-readable detection logic
    including rule name, GUID, functions, conditions, and actions.

    Args:
        sig: The Lua signature to analyze

    Returns:
        Dictionary with logic summary
    """
    from ..services.lua_logic_analyzer import analyze_lua_script

    # First decompile if not already done
    source = sig.decompiled_source
    if not source and sig.has_bytecode:
        source = decompile_lua_signature(sig)

    if not source:
        return {"error": "No decompiled source available"}

    return analyze_lua_script(source)


def extract_lua_patterns(sig: LuaSignature, primary_guid: Optional[str] = None) -> dict:
    """
    Extract detection patterns from a Lua signature.

    Uses the LuaPatternExtractor to extract:
    - Exclusion and detection paths
    - Process names
    - File extensions
    - MITRE techniques
    - Registry keys
    - Native functions
    - Related ASR GUIDs
    - Domains
    - Command patterns
    - Vulnerable drivers

    Args:
        sig: The Lua signature to analyze
        primary_guid: Optional primary ASR GUID to exclude from related GUIDs

    Returns:
        Dictionary with extracted patterns
    """
    from ..services.lua_pattern_extractor import LuaPatternExtractor

    # First decompile if not already done
    source = sig.decompiled_source
    if not source and sig.has_bytecode:
        source = decompile_lua_signature(sig)

    if not source:
        return {"error": "No decompiled source available"}

    extractor = LuaPatternExtractor(primary_guid)
    patterns = extractor.extract_from_source(source)
    return patterns.to_dict()


def get_full_lua_analysis(sig: LuaSignature, primary_guid: Optional[str] = None) -> dict:
    """
    Perform full analysis on a Lua signature.

    Combines decompilation, logic analysis, and pattern extraction
    into a single comprehensive result.

    Args:
        sig: The Lua signature to analyze
        primary_guid: Optional primary ASR GUID to exclude from related GUIDs

    Returns:
        Dictionary with:
        - decompiled_source: The decompiled Lua source code
        - bytecode_info: Information about the bytecode
        - logic_summary: Human-readable logic analysis
        - patterns: Extracted detection patterns
    """
    result = {
        "threat_name": sig.threat_name,
        "attribute": sig.attribute,
        "category": sig.category,
        "sig_type": sig.sig_type.name,
    }

    # Get bytecode info
    if sig.has_bytecode:
        result["bytecode_info"] = get_lua_info(sig.lua_bytecode)
    else:
        result["bytecode_info"] = {"valid": False, "error": "No bytecode"}

    # Decompile
    source = decompile_lua_signature(sig)
    result["decompiled_source"] = source

    # Store for reuse
    sig.decompiled_source = source

    # Analyze logic
    result["logic_summary"] = analyze_lua_signature(sig)

    # Extract patterns
    result["patterns"] = extract_lua_patterns(sig, primary_guid)

    return result
