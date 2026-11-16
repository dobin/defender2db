"""
Microsoft Defender Signature Type Definitions

Contains signature type codes used in VDM signature databases.
Based on reverse engineering of Defender's mpengine.dll and signature formats.

References:
- "An unexpected journey into Microsoft Defender's signature World" (Retooling.io)
- "Windows Defender: Demystifying and Bypassing ASR" (Black Hat EU - Mougey Camille)
"""

from enum import IntEnum
from dataclasses import dataclass
from typing import Optional


# PEHSTR_EXT Wildcard pattern codes (from Retooling PDF)
# Used in sub-rules for flexible byte matching
WILDCARD_SINGLE_BYTE = 0x9001  # 90 01 XX - Match exactly XX bytes following
WILDCARD_RANGE = 0x9002        # 90 02 XX - Match up to XX bytes (variable length)
WILDCARD_OR = 0x9003           # 90 03 XX YY - Match Sequence_A (XX bytes) OR Sequence_B (YY bytes)
WILDCARD_REGEX = 0x9004        # 90 04 XX YY - Regex-like pattern (case sensitive)
WILDCARD_REGEX_ICASE = 0x9005  # 90 05 XX YY - Regex-like pattern (case insensitive)


class SigType(IntEnum):
    """
    Signature type codes found in VDM TLV entries.

    From PDF documentation and mpengine.dll reverse engineering.
    """

    # Threat markers - CORRECT values from PDF
    THREAT_BEGIN = 0x5C  # Defines start of threat with detection name
    THREAT_END = 0x5D    # Defines end of threat

    # String pattern signatures - CORRECT values from PDF
    PEHSTR = 0x61        # PE string matching (readable strings)
    PEHSTR_EXT = 0x78    # Extended PE byte matching (opcodes, wildcards)
    PEHSTR_EXT2 = 0x85   # Second extended PE string type

    # Delta signatures
    DELTA_BLOB = 0x73
    DELTA_BLOB_RECINFO = 0x74

    # Common signature types from mpengine.dll
    STATIC = 0x03
    KCRCE = 0x04
    SNID = 0x05
    CKSM = 0x06
    BRUTE = 0x07
    ICRC = 0x08
    PCODE = 0x09
    MACRO = 0x0A
    MACRO_SOURCE = 0x0B
    MACRO_PCODE = 0x0C
    NSCRIPT = 0x0D

    # ELF/Macho/other format signatures
    ELFHSTR = 0x10
    ELFHSTR_EXT = 0x11
    MACHOHSTR = 0x12
    MACHOHSTR_EXT = 0x13

    # Virtual DLL types
    VDLL_X86 = 0x79
    VDLL_X64 = 0x7A
    VDLL_ARM = 0x7B
    VDLL_MSIL = 0x7C

    # Certificate signatures
    WVT_EXCEPTION = 0x6B
    REVOKED_CERTIFICATE = 0x6C
    TRUSTED_PUBLISHER = 0x70

    # File path signatures
    ASEP_FILEPATH = 0x71
    ASEP_FOLDERNAME = 0x75

    # Pattern matching
    PATTMATCH_V2 = 0x77

    # Sigtree
    SIGTREE = 0x14
    SIGTREE_BM = 0x15
    SIGTREE_EXT = 0x16

    # Script signatures
    NSCRIPT_SP = 0x17
    NSCRIPT_BRUTE = 0x18
    NSCRIPT_EXT = 0x19

    # Java/AutoIT signatures
    JAVAHSTR = 0x1A
    AUTOITHSTR = 0x1B

    # Archive signatures
    ARHSTR = 0x1C
    ARHSTR_EXT = 0x1D

    # Aggregator types
    AGGREGATOR = 0x1E
    AGGREGATOREX = 0x1F

    # AMSI types
    AMSI_JSCRIPT = 0x20
    AMSI_POWERSHELL = 0x21
    AMSI_VBS = 0x22
    AMSI_GENERIC = 0x23

    # Command line signatures
    CMDHSTR = 0x24
    CMDHSTR_EXT = 0x25

    # Database signatures
    DBHSTR = 0x26
    DBHSTR_EXT = 0x27

    # URL signatures
    URLHSTR = 0x28
    URLHSTR_EXT = 0x29

    # Friendly/Threat hashes
    FRIENDLY_FILE_HASH = 0x44
    THREAT_FILE_HASH = 0x45
    FRIENDLYHASH_SHA256 = 0x46
    FRIENDLYHASH_SHA512 = 0x47
    THREATHASH_SHA256 = 0x48
    THREATHASH_SHA512 = 0x49
    FRIENDLYHASH_CTPH = 0x4A
    THREATHASH_CTPH = 0x4B

    # Unknown/fallback type (must be defined for generic handler)
    UNKNOWN = 0x00

    # Lua script types
    LUA_STANDALONE = 0x4C
    LUASTANDALONE = 0x4C  # Alias
    LUA_SCRIPT = 0xBD  # Lua bytecode with 8-byte header (most common type)
    LUASCRIPT = 0xBD  # Alias

    # Behavior monitoring
    BM_INFO = 0x60
    BM_RULE = 0x62

    # Normal (non-extended) signature types
    NORMAL = 0x63

    # Extended type marker
    EXTENDED = 0x64
    EXPLICITNID = 0x65

    # Clean script types
    CLEANSCRIPT = 0x66
    INNOSCRIPT = 0x67

    # PDF types
    PDFTTHSTR = 0x68
    PDFTTHSTR_EXT = 0x69

    # Folder name
    FOLDERNAME = 0x6A

    # Process/File operations
    FOP = 0x6D
    FOP64 = 0x6E
    FOPEX = 0x6F

    # PEB memory signatures
    PEBMPAT = 0x80
    PEBMPAT_EXT = 0x81

    # AutoIT heuristic
    AUTOIT_HSTR = 0x82
    AUTOIT_HSTR_EXT = 0x83

    # NID (numeric ID) types
    NID64 = 0x84

    # Macrohstr
    MACROHSTR = 0x86
    MACROHSTR_EXT = 0x87

    # Defaults/MSI
    DEFAULTS = 0x88
    MSIHSTR = 0x89
    MSIHSTR_EXT = 0x8A

    # Dex (Android)
    DEXHSTR = 0x8B
    DEXHSTR_EXT = 0x8C

    # JavaScript
    JSHSTR = 0x8D
    JSHSTR_EXT = 0x8E

    # VBScript
    VBSHSTR = 0x8F
    VBSHSTR_EXT = 0x90

    # Powershell
    PSHSTR = 0x91
    PSHSTR_EXT = 0x92

    # DOS heuristic
    DOSHSTR = 0x93
    DOSHSTR_EXT = 0x94

    # PHP
    PHPHSTR = 0x95
    PHPHSTR_EXT = 0x96

    # Python
    PYHSTR = 0x97
    PYHSTR_EXT = 0x98

    # Ruby
    RBHSTR = 0x99
    RBHSTR_EXT = 0x9A

    # SWF (Flash)
    SWFHSTR = 0x9B
    SWFHSTR_EXT = 0x9C

    # Inno setup
    INNOHSTR = 0x9D
    INNOHSTR_EXT = 0x9E

    # Various other types from mpengine switch statement
    POLYVIR32 = 0x9F
    REGKEY = 0xA0
    REGVAL = 0xA1
    FILEPATH = 0xA2
    FILENAME = 0xA3
    MUTEX = 0xA4
    EVENT = 0xA5
    SEMAPHORE = 0xA6
    ATOM = 0xA7
    SECTION = 0xA8
    PIPE = 0xA9
    MAILSLOT = 0xAA
    CLSID = 0xAB
    CMODINFO = 0xAC
    CMODNHSTR = 0xAD
    CMODSHSTR = 0xAE
    CMODATTR = 0xAF


# Mapping of type code to name string
TYPE_NAMES = {
    0x5C: "SIGNATURE_TYPE_THREAT_BEGIN",
    0x5D: "SIGNATURE_TYPE_THREAT_END",
    0x61: "SIGNATURE_TYPE_PEHSTR",
    0x78: "SIGNATURE_TYPE_PEHSTR_EXT",
    0x85: "SIGNATURE_TYPE_PEHSTR_EXT2",
    0x73: "SIGNATURE_TYPE_DELTA_BLOB",
    0x74: "SIGNATURE_TYPE_DELTA_BLOB_RECINFO",
    0x79: "SIGNATURE_TYPE_VDLL_X86",
    0x7A: "SIGNATURE_TYPE_VDLL_X64",
    0x6B: "SIGNATURE_TYPE_WVT_EXCEPTION",
    0x6C: "SIGNATURE_TYPE_REVOKED_CERTIFICATE",
    0x70: "SIGNATURE_TYPE_TRUSTED_PUBLISHER",
    0x71: "SIGNATURE_TYPE_ASEP_FILEPATH",
    0x75: "SIGNATURE_TYPE_ASEP_FOLDERNAME",
    0x77: "SIGNATURE_TYPE_PATTMATCH_V2",
    0x03: "SIGNATURE_TYPE_STATIC",
    0x04: "SIGNATURE_TYPE_KCRCE",
    0x05: "SIGNATURE_TYPE_SNID",
    0x4C: "SIGNATURE_TYPE_LUASTANDALONE",
    0xBD: "SIGNATURE_TYPE_LUASCRIPT",  # Lua bytecode with 8-byte header
    0x44: "SIGNATURE_TYPE_FRIENDLY_FILE_HASH",
    0x45: "SIGNATURE_TYPE_THREAT_FILE_HASH",
}


@dataclass
class SignatureInfo:
    """Metadata about a signature type."""
    sig_type: int
    name: str
    category: str
    description: str
    has_payload: bool = True
    is_lua: bool = False


# Signature type metadata
SIGNATURE_INFO = {
    SigType.THREAT_BEGIN: SignatureInfo(
        SigType.THREAT_BEGIN, "THREAT_BEGIN", "marker",
        "Marks start of threat definition block with threat name"
    ),
    SigType.THREAT_END: SignatureInfo(
        SigType.THREAT_END, "THREAT_END", "marker",
        "Marks end of threat definition block"
    ),
    SigType.PEHSTR: SignatureInfo(
        SigType.PEHSTR, "PEHSTR", "string",
        "PE file string pattern matching"
    ),
    SigType.PEHSTR_EXT: SignatureInfo(
        SigType.PEHSTR_EXT, "PEHSTR_EXT", "string",
        "Extended PE byte pattern with wildcards"
    ),
    SigType.PEHSTR_EXT2: SignatureInfo(
        SigType.PEHSTR_EXT2, "PEHSTR_EXT2", "string",
        "Second extended PE pattern type"
    ),
    SigType.LUA_STANDALONE: SignatureInfo(
        SigType.LUA_STANDALONE, "LUASTANDALONE", "lua",
        "Standalone Lua detection script", True, True
    ),
    SigType.DELTA_BLOB: SignatureInfo(
        SigType.DELTA_BLOB, "DELTA_BLOB", "delta",
        "Delta update blob"
    ),
    SigType.FRIENDLY_FILE_HASH: SignatureInfo(
        SigType.FRIENDLY_FILE_HASH, "FRIENDLY_FILE_HASH", "hash",
        "Known good file hash (whitelist)"
    ),
    SigType.THREAT_FILE_HASH: SignatureInfo(
        SigType.THREAT_FILE_HASH, "THREAT_FILE_HASH", "hash",
        "Known malicious file hash (blacklist)"
    ),
}


def get_signature_info(sig_type: int) -> Optional[SignatureInfo]:
    """Get metadata for a signature type."""
    try:
        st = SigType(sig_type)
        return SIGNATURE_INFO.get(st)
    except ValueError:
        return None


def is_lua_type(sig_type: int) -> bool:
    """Check if signature type contains Lua bytecode."""
    return sig_type in (0x4C, 0xBD)  # LUA_STANDALONE, LUA_SCRIPT


def get_type_name(sig_type: int) -> str:
    """Get human-readable name for signature type."""
    if sig_type in TYPE_NAMES:
        return TYPE_NAMES[sig_type]
    try:
        return SigType(sig_type).name
    except ValueError:
        return f"UNKNOWN_0x{sig_type:02X}"
