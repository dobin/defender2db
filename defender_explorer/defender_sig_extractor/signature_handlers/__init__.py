"""Signature type handlers for various Defender signature formats."""

from .lua_handler import (
    LuaSignature,
    LuaSignatureParser,
    parse_lua_signature,
    decompile_lua_signature,
    extract_lua_from_raw,
    get_lua_info,
    analyze_lua_signature,
    extract_lua_patterns,
    get_full_lua_analysis,
)

from .pehstr_handler import (
    PEHSTRSignature,
    PEHSTRSubRule,
    WildcardPattern,
    parse_pehstr_signature,
    parse_wildcards,
    analyze_pehstr_bytes,
)

from .hash_handler import parse_hash_signature
from .generic_handler import parse_generic_signature
from .standalone_handler import (
    StandaloneSignature,
    SemanticGroup,
    StandaloneSignatureGrouper,
    extract_standalone_signatures,
    classify_standalone_signature,
)

__all__ = [
    # Lua
    'LuaSignature',
    'LuaSignatureParser',
    'parse_lua_signature',
    'decompile_lua_signature',
    'extract_lua_from_raw',
    'get_lua_info',
    'analyze_lua_signature',
    'extract_lua_patterns',
    'get_full_lua_analysis',
    # PEHSTR
    'PEHSTRSignature',
    'PEHSTRSubRule',
    'WildcardPattern',
    'parse_pehstr_signature',
    'parse_wildcards',
    'analyze_pehstr_bytes',
    # Hash
    'parse_hash_signature',
    # Generic
    'parse_generic_signature',
    # Standalone
    'StandaloneSignature',
    'SemanticGroup',
    'StandaloneSignatureGrouper',
    'extract_standalone_signatures',
    'classify_standalone_signature',
]
