"""
Microsoft Defender Signature Extractor & Lua Decompiler

Pure Python tool to download, extract, and decompile all signatures
from Microsoft Defender signature databases.

Usage:
    # As a module:
    python -m defender_sig_extractor --download --output ./signatures/

    # As a library:
    from defender_sig_extractor import VDMParser, decompile_bytecode
    parser = VDMParser("mpavbase.vdm")
    for sig in parser.extract_lua_signatures():
        print(sig.type_name, sig.size)
"""

__version__ = "1.0.0"

# Core components
from .vdm_parser import VDMParser, Signature, parse_vdm_file, decompress_vdm
from .delta_patcher import DeltaPatcher, apply_delta, combine_vdm_files
from .signature_types import SigType, is_lua_type, get_type_name

# Downloader
from .downloader import download_mpam, download_mpam_to_temp

# PE/CAB extraction
from .pe_extractor import extract_vdm_files, extract_cab_from_pe

# Lua decompiler (uses luadec engine, auto-detects native binary)
from .lua_decompiler import decompile_bytecode
from .lua_decompiler import undump, undump_file, is_lua_bytecode
from .lua_decompiler import convert_mplua_to_lua51, is_mplua

# Signature handlers
from .signature_handlers.lua_handler import (
    parse_lua_signature, decompile_lua_signature,
    analyze_lua_signature, extract_lua_patterns, get_full_lua_analysis
)
from .signature_handlers.hash_handler import parse_hash_signature
from .signature_handlers.generic_handler import parse_generic_signature

# Analysis services
from .services.lua_logic_analyzer import (
    LuaLogicAnalyzer, LogicSummary, analyze_lua_script
)
from .services.lua_pattern_extractor import (
    LuaPatternExtractor, ExtractedPatterns, extract_patterns_from_scripts
)

# Comprehensive signature extraction
from .signature_extractor import (
    SignatureExtractor,
    ThreatDefinition,
    TLVEntry,
    PEHSTRSignature,
    parse_tlv_stream,
    extract_threats,
    count_signature_types,
)

__all__ = [
    # Version
    '__version__',

    # Core
    'VDMParser',
    'Signature',
    'parse_vdm_file',
    'decompress_vdm',
    'DeltaPatcher',
    'apply_delta',
    'combine_vdm_files',
    'SigType',
    'is_lua_type',
    'get_type_name',

    # Downloader
    'download_mpam',
    'download_mpam_to_temp',

    # Extraction
    'extract_vdm_files',
    'extract_cab_from_pe',

    # Lua decompiler
    'decompile_bytecode',
    'undump',
    'undump_file',
    'is_lua_bytecode',
    'convert_mplua_to_lua51',
    'is_mplua',

    # Handlers
    'parse_lua_signature',
    'decompile_lua_signature',
    'analyze_lua_signature',
    'extract_lua_patterns',
    'get_full_lua_analysis',
    'parse_hash_signature',
    'parse_generic_signature',

    # Analysis services
    'LuaLogicAnalyzer',
    'LogicSummary',
    'analyze_lua_script',
    'LuaPatternExtractor',
    'ExtractedPatterns',
    'extract_patterns_from_scripts',

    # Signature extraction
    'SignatureExtractor',
    'ThreatDefinition',
    'TLVEntry',
    'PEHSTRSignature',
    'parse_tlv_stream',
    'extract_threats',
    'count_signature_types',
]
