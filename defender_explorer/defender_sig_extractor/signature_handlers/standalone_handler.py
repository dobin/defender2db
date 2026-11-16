"""
Standalone Signature Handler

Handles signatures that exist outside of THREAT_BEGIN/END blocks.
Groups them semantically by what they detect.

Signature types handled:
- PEBMPAT (0x80): PE bitmap patterns - grouped by packer/protector
- INNOSCRIPT (0x67): Inno Setup patterns - grouped by behavior
- REGKEY (0xA0): Registry patterns - grouped by registry path
- FILEPATH (0xA2): File path patterns - grouped by location
- And other standalone types
"""

import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Any, Iterator, Optional, Tuple
from collections import defaultdict

from ..signature_types import SigType


# Known packer/protector signatures for PEBMPAT grouping
PACKER_SIGNATURES = {
    # UPX variants
    b'UPX0': 'UPX',
    b'UPX1': 'UPX',
    b'UPX2': 'UPX',
    b'UPX!': 'UPX',
    b'.UPX': 'UPX',

    # VMProtect
    b'.vmp0': 'VMProtect',
    b'.vmp1': 'VMProtect',
    b'.vmp2': 'VMProtect',
    b'VMProtect': 'VMProtect',

    # Themida/WinLicense
    b'.themida': 'Themida',
    b'Themida': 'Themida',
    b'WinLicense': 'Themida',
    b'.winlice': 'Themida',

    # ASPack
    b'.aspack': 'ASPack',
    b'.adata': 'ASPack',
    b'ASPack': 'ASPack',

    # PECompact
    b'PEC2': 'PECompact',
    b'.pec': 'PECompact',
    b'PECompact': 'PECompact',

    # NSPack
    b'.nsp0': 'NSPack',
    b'.nsp1': 'NSPack',
    b'.nsp2': 'NSPack',
    b'nsPack': 'NSPack',

    # Armadillo
    b'.text1': 'Armadillo',
    b'.adata1': 'Armadillo',
    b'Armadillo': 'Armadillo',

    # Enigma Protector
    b'.enigma': 'Enigma',
    b'ENIGMA': 'Enigma',

    # Obsidium
    b'.obsidiu': 'Obsidium',
    b'Obsidium': 'Obsidium',

    # MPRESS
    b'.MPRESS': 'MPRESS',
    b'MPRESS1': 'MPRESS',
    b'MPRESS2': 'MPRESS',

    # Petite
    b'.petite': 'Petite',
    b'petite': 'Petite',

    # FSG
    b'FSG!': 'FSG',

    # MEW
    b'MEW': 'MEW',

    # kkrunchy
    b'kkrunchy': 'kkrunchy',

    # .NET obfuscators
    b'ConfuserEx': 'ConfuserEx',
    b'Confuser': 'Confuser',
    b'Dotfuscator': 'Dotfuscator',
    b'Eazfuscator': 'Eazfuscator',
    b'SmartAssembly': 'SmartAssembly',
    b'Babel': 'BabelObfuscator',
    b'Crypto Obfuscator': 'CryptoObfuscator',
    b'Agile.NET': 'AgileNET',
    b'DeepSea': 'DeepSea',

    # PyInstaller / Python packers
    b'PYZ-': 'PyInstaller',
    b'pyiboot': 'PyInstaller',
    b'_pyi_': 'PyInstaller',
    b'Nuitka': 'Nuitka',
    b'py2exe': 'py2exe',
    b'cx_Freeze': 'cx_Freeze',

    # AutoIt
    b'AU3!': 'AutoIt',
    b'AutoIt': 'AutoIt',

    # NSIS
    b'Nullsoft': 'NSIS',
    b'NSIS': 'NSIS',

    # Inno Setup
    b'Inno Setup': 'InnoSetup',
    b'JRsplash': 'InnoSetup',

    # InstallShield
    b'InstallShield': 'InstallShield',

    # Electron/Node
    b'electron.asar': 'Electron',
    b'app.asar': 'Electron',

    # Generic suspicious sections
    b'.packed': 'GenericPacker',
    b'.crypted': 'GenericCrypter',
}

# Registry path categories for REGKEY grouping
REGISTRY_CATEGORIES = {
    # Persistence
    r'\\Run$': 'Persistence/Run',
    r'\\RunOnce$': 'Persistence/RunOnce',
    r'\\RunServices': 'Persistence/RunServices',
    r'Winlogon\\': 'Persistence/Winlogon',
    r'\\Shell\\': 'Persistence/Shell',
    r'\\Userinit': 'Persistence/Userinit',
    r'AppInit_DLLs': 'Persistence/AppInit',
    r'\\Services\\': 'Persistence/Services',
    r'\\Drivers\\': 'Persistence/Drivers',
    r'Scheduled Tasks': 'Persistence/ScheduledTasks',
    r'\\Explorer\\ShellExecuteHooks': 'Persistence/ShellHooks',
    r'\\Browser Helper': 'Persistence/BHO',
    r'ActiveSetup\\Installed': 'Persistence/ActiveSetup',
    r'\\Policies\\Explorer\\Run': 'Persistence/PolicyRun',

    # COM/CLSID
    r'\\CLSID\\': 'COM/CLSID',
    r'\\InprocServer': 'COM/InprocServer',
    r'\\LocalServer': 'COM/LocalServer',
    r'\\TypeLib\\': 'COM/TypeLib',
    r'\\Interface\\': 'COM/Interface',

    # Security
    r'\\Security\\': 'Security/Settings',
    r'\\Policies\\': 'Security/Policies',
    r'\\Firewall\\': 'Security/Firewall',
    r'Windows Defender': 'Security/Defender',
    r'AntiVirus': 'Security/Antivirus',

    # Network
    r'\\Tcpip\\': 'Network/TCP',
    r'\\Winsock': 'Network/Winsock',
    r'\\NetworkProvider': 'Network/Provider',
    r'\\Internet Settings': 'Network/InternetSettings',
    r'ProxyServer': 'Network/Proxy',
    r'\\Hosts\\': 'Network/Hosts',

    # Browser
    r'\\Chrome\\': 'Browser/Chrome',
    r'\\Firefox\\': 'Browser/Firefox',
    r'\\Edge\\': 'Browser/Edge',
    r'\\Internet Explorer': 'Browser/IE',
    r'StartPage': 'Browser/Homepage',
    r'SearchScopes': 'Browser/Search',

    # System
    r'\\Environment': 'System/Environment',
    r'\\Session Manager': 'System/SessionManager',
    r'BootExecute': 'System/BootExecute',
    r'\\Image File Execution': 'System/IFEO',
    r'\\KnownDLLs': 'System/KnownDLLs',

    # Uninstall/Software
    r'\\Uninstall\\': 'Software/Uninstall',
    r'\\Microsoft\\Windows\\CurrentVersion': 'Software/WindowsSettings',
}

# File path categories for FILEPATH grouping
FILEPATH_CATEGORIES = {
    # System paths
    r'\\Windows\\System32': 'System/System32',
    r'\\Windows\\SysWOW64': 'System/SysWOW64',
    r'\\Windows\\Temp': 'System/Temp',
    r'\\Windows\\Tasks': 'System/Tasks',

    # User paths
    r'\\AppData\\Local\\Temp': 'User/Temp',
    r'\\AppData\\Roaming': 'User/Roaming',
    r'\\AppData\\Local': 'User/Local',
    r'\\Desktop\\': 'User/Desktop',
    r'\\Documents\\': 'User/Documents',
    r'\\Downloads\\': 'User/Downloads',
    r'\\Startup': 'User/Startup',

    # Program paths
    r'\\Program Files': 'Programs/ProgramFiles',
    r'\\ProgramData': 'Programs/ProgramData',

    # Suspicious paths
    r'\\Recycle': 'Suspicious/RecycleBin',
    r'\\$Recycle': 'Suspicious/RecycleBin',
    r'\\.tmp$': 'Suspicious/TempFile',
    r'\\.scr$': 'Suspicious/Screensaver',
    r'\\Fonts\\.*\\.exe': 'Suspicious/FontsExe',
}

# Inno Setup / installer behavior categories
INSTALLER_CATEGORIES = {
    # Silent install
    b'/SILENT': 'Behavior/SilentInstall',
    b'/VERYSILENT': 'Behavior/SilentInstall',
    b'/quiet': 'Behavior/SilentInstall',
    b'/qn': 'Behavior/SilentInstall',
    b'-silent': 'Behavior/SilentInstall',

    # Network activity
    b'http://': 'Behavior/NetworkDownload',
    b'https://': 'Behavior/NetworkDownload',
    b'ftp://': 'Behavior/NetworkDownload',
    b'URLDownloadToFile': 'Behavior/NetworkDownload',
    b'InternetOpen': 'Behavior/NetworkDownload',

    # Registry modification
    b'RegWrite': 'Behavior/RegistryMod',
    b'RegDelete': 'Behavior/RegistryMod',
    b'WriteRegStr': 'Behavior/RegistryMod',
    b'WriteRegDWORD': 'Behavior/RegistryMod',

    # Service installation
    b'CreateService': 'Behavior/ServiceInstall',
    b'sc create': 'Behavior/ServiceInstall',
    b'InstallService': 'Behavior/ServiceInstall',

    # Scheduled task
    b'schtasks': 'Behavior/ScheduledTask',
    b'TaskScheduler': 'Behavior/ScheduledTask',

    # Disable security
    b'DisableAntiSpyware': 'Behavior/DisableSecurity',
    b'DisableRealtimeMonitoring': 'Behavior/DisableSecurity',
    b'Windows Defender': 'Behavior/DisableSecurity',
    b'netsh firewall': 'Behavior/DisableSecurity',
    b'Set-MpPreference': 'Behavior/DisableSecurity',

    # Bundled software
    b'toolbar': 'Bundleware/Toolbar',
    b'browser extension': 'Bundleware/Extension',
    b'homepage': 'Bundleware/Homepage',
    b'search provider': 'Bundleware/Search',
}


@dataclass
class StandaloneSignature:
    """A standalone signature with semantic grouping."""
    sig_type: int
    data: bytes
    offset: int
    category: str = "Unknown"
    subcategory: str = ""
    matched_pattern: str = ""
    strings: List[str] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        try:
            return SigType(self.sig_type).name
        except ValueError:
            return f"UNKNOWN_0x{self.sig_type:02X}"

    @property
    def full_category(self) -> str:
        if self.subcategory:
            return f"{self.category}/{self.subcategory}"
        return self.category


@dataclass
class SemanticGroup:
    """A group of semantically related signatures."""
    category: str
    subcategory: str
    sig_type: int
    signatures: List[StandaloneSignature] = field(default_factory=list)
    matched_patterns: Dict[str, int] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.signatures)

    @property
    def type_name(self) -> str:
        try:
            return SigType(self.sig_type).name
        except ValueError:
            return f"UNKNOWN_0x{self.sig_type:02X}"


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = []

    for b in data:
        if 0x20 <= b <= 0x7e:
            current.append(chr(b))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []

    if len(current) >= min_length:
        strings.append(''.join(current))

    return strings


def classify_pebmpat(data: bytes) -> Tuple[str, str, str]:
    """
    Classify a PEBMPAT signature by packer/protector.

    Returns: (category, subcategory, matched_pattern)
    """
    # Check for known packer signatures
    for pattern, packer_name in PACKER_SIGNATURES.items():
        if pattern in data:
            return "Packer", packer_name, pattern.decode('ascii', errors='replace')

    # Extract strings for further analysis
    strings = extract_strings(data)
    strings_lower = [s.lower() for s in strings]

    # Check strings for packer indicators
    packer_keywords = {
        'upx': 'UPX',
        'aspack': 'ASPack',
        'pecompact': 'PECompact',
        'themida': 'Themida',
        'vmprotect': 'VMProtect',
        'armadillo': 'Armadillo',
        'obsidium': 'Obsidium',
        'enigma': 'Enigma',
        'mpress': 'MPRESS',
        'petite': 'Petite',
        'fsg': 'FSG',
        '.packed': 'GenericPacker',
        'packed': 'GenericPacker',
        'crypter': 'GenericCrypter',
        'obfuscator': 'GenericObfuscator',
    }

    for keyword, packer_name in packer_keywords.items():
        for s in strings_lower:
            if keyword in s:
                return "Packer", packer_name, keyword

    # Check PE section patterns
    section_patterns = [
        (b'.text\x00', 'PE/TextSection'),
        (b'.data\x00', 'PE/DataSection'),
        (b'.rdata\x00', 'PE/RdataSection'),
        (b'.rsrc\x00', 'PE/ResourceSection'),
        (b'.reloc\x00', 'PE/RelocSection'),
        (b'.idata\x00', 'PE/ImportSection'),
        (b'.edata\x00', 'PE/ExportSection'),
    ]

    for pattern, section_type in section_patterns:
        if pattern in data:
            return "PE", section_type.split('/')[1], pattern.decode('ascii', errors='replace').strip('\x00')

    # Default: unknown PE pattern
    return "PE", "UnknownPattern", ""


def classify_regkey(data: bytes) -> Tuple[str, str, str]:
    """
    Classify a REGKEY signature by registry path category.

    Returns: (category, subcategory, matched_pattern)
    """
    # Try multiple decoding methods - prefer ASCII/UTF-8 first
    reg_path = ""

    # First, extract printable strings (most reliable)
    strings = extract_strings(data, min_length=3)
    if strings:
        # Find the longest string that looks like a registry path
        for s in sorted(strings, key=len, reverse=True):
            if '\\' in s or 'HKEY' in s.upper() or 'Software' in s or 'Microsoft' in s:
                reg_path = s
                break
        if not reg_path:
            reg_path = max(strings, key=len)

    # If no good strings found, try direct decoding
    if not reg_path or len(reg_path) < 5:
        # Try ASCII first
        try:
            decoded = data.decode('ascii', errors='ignore').strip('\x00')
            if '\\' in decoded and len(decoded) > len(reg_path):
                reg_path = decoded
        except:
            pass

        # Try UTF-16 LE as fallback (Windows wide strings)
        if not reg_path or ('\\' not in reg_path):
            try:
                decoded = data.decode('utf-16-le', errors='ignore').strip('\x00')
                if '\\' in decoded and len(decoded) > 3:
                    reg_path = decoded
            except:
                pass

    # Check against known patterns
    for pattern, category in REGISTRY_CATEGORIES.items():
        if re.search(pattern, reg_path, re.IGNORECASE):
            parts = category.split('/')
            return parts[0], parts[1] if len(parts) > 1 else "", pattern

    # Try to categorize by hive or keywords
    reg_upper = reg_path.upper()
    if 'HKLM' in reg_upper or 'HKEY_LOCAL_MACHINE' in reg_upper:
        return "Registry", "HKLM", reg_path[:50]
    elif 'HKCU' in reg_upper or 'HKEY_CURRENT_USER' in reg_upper:
        return "Registry", "HKCU", reg_path[:50]
    elif 'HKCR' in reg_upper or 'HKEY_CLASSES_ROOT' in reg_upper:
        return "Registry", "HKCR", reg_path[:50]
    elif 'CURRENTVERSION' in reg_upper:
        return "Registry", "CurrentVersion", reg_path[:50]
    elif 'RUN' in reg_upper and 'UNINSTALL' not in reg_upper:
        return "Persistence", "Run", reg_path[:50]
    elif 'SERVICE' in reg_upper:
        return "Persistence", "Services", reg_path[:50]
    elif 'CLSID' in reg_upper:
        return "COM", "CLSID", reg_path[:50]

    return "Registry", "Other", reg_path[:50] if reg_path else ""


def classify_filepath(data: bytes) -> Tuple[str, str, str]:
    """
    Classify a FILEPATH signature by path category.

    Returns: (category, subcategory, matched_pattern)
    """
    # Decode the path
    try:
        file_path = data.decode('utf-16-le', errors='ignore').strip('\x00')
    except:
        try:
            file_path = data.decode('ascii', errors='ignore').strip('\x00')
        except:
            file_path = ""

    if not file_path:
        strings = extract_strings(data)
        file_path = strings[0] if strings else ""

    # Check against known patterns
    for pattern, category in FILEPATH_CATEGORIES.items():
        if re.search(pattern, file_path, re.IGNORECASE):
            parts = category.split('/')
            return parts[0], parts[1] if len(parts) > 1 else "", pattern

    # Categorize by extension
    ext_match = re.search(r'\.(\w{2,4})$', file_path.lower())
    if ext_match:
        ext = ext_match.group(1)
        if ext in ('exe', 'dll', 'sys', 'scr'):
            return "Executable", ext.upper(), file_path[-50:]
        elif ext in ('bat', 'cmd', 'ps1', 'vbs', 'js'):
            return "Script", ext.upper(), file_path[-50:]
        elif ext in ('doc', 'docx', 'xls', 'xlsx', 'ppt'):
            return "Document", ext.upper(), file_path[-50:]

    return "FilePath", "Unknown", file_path[:50] if file_path else ""


def classify_innoscript(data: bytes) -> Tuple[str, str, str]:
    """
    Classify an INNOSCRIPT signature by behavior.

    Returns: (category, subcategory, matched_pattern)
    """
    # Check for known behavior patterns
    for pattern, category in INSTALLER_CATEGORIES.items():
        if pattern in data:
            parts = category.split('/')
            return parts[0], parts[1] if len(parts) > 1 else "", pattern.decode('ascii', errors='replace')

    # Extract strings for analysis
    strings = extract_strings(data)
    strings_text = ' '.join(strings).lower()

    # Check string content
    if any(x in strings_text for x in ['download', 'http', 'url', 'internet']):
        return "Behavior", "NetworkActivity", "network keywords"
    elif any(x in strings_text for x in ['registry', 'regwrite', 'hkey']):
        return "Behavior", "RegistryMod", "registry keywords"
    elif any(x in strings_text for x in ['service', 'driver']):
        return "Behavior", "ServiceInstall", "service keywords"
    elif any(x in strings_text for x in ['task', 'schedule']):
        return "Behavior", "ScheduledTask", "task keywords"
    elif any(x in strings_text for x in ['silent', 'quiet', 'hidden']):
        return "Behavior", "SilentInstall", "silent keywords"
    elif any(x in strings_text for x in ['toolbar', 'addon', 'extension', 'plugin']):
        return "Bundleware", "Addon", "addon keywords"

    return "Installer", "Generic", ""


def classify_standalone_signature(sig_type: int, data: bytes, offset: int) -> StandaloneSignature:
    """
    Classify a standalone signature and return semantic grouping.
    """
    strings = extract_strings(data)

    # Route to appropriate classifier based on type
    if sig_type == 0x80:  # PEBMPAT
        category, subcategory, matched = classify_pebmpat(data)
    elif sig_type == 0xA0:  # REGKEY
        category, subcategory, matched = classify_regkey(data)
    elif sig_type == 0xA2:  # FILEPATH
        category, subcategory, matched = classify_filepath(data)
    elif sig_type == 0x67:  # INNOSCRIPT
        category, subcategory, matched = classify_innoscript(data)
    elif sig_type == 0xA3:  # FILENAME
        category, subcategory, matched = classify_filepath(data)  # Similar logic
    elif sig_type == 0xA4:  # MUTEX
        category, subcategory, matched = "Mutex", "Named", extract_strings(data)[0] if strings else ""
    elif sig_type == 0xA9:  # PIPE
        category, subcategory, matched = "Pipe", "Named", extract_strings(data)[0] if strings else ""
    elif sig_type == 0x28:  # URLHSTR
        category, subcategory, matched = "URL", "Pattern", extract_strings(data)[0][:50] if strings else ""
    else:
        # Generic classification based on content
        if strings:
            category, subcategory, matched = "Generic", f"Type_0x{sig_type:02X}", strings[0][:30]
        else:
            category, subcategory, matched = "Generic", f"Type_0x{sig_type:02X}", ""

    return StandaloneSignature(
        sig_type=sig_type,
        data=data,
        offset=offset,
        category=category,
        subcategory=subcategory,
        matched_pattern=matched,
        strings=strings[:10]  # Keep first 10 strings
    )


class StandaloneSignatureGrouper:
    """
    Groups standalone signatures by semantic category.
    """

    def __init__(self):
        self.groups: Dict[Tuple[str, str, int], SemanticGroup] = {}
        self.total_processed = 0
        self.by_type: Dict[int, int] = defaultdict(int)

    def add_signature(self, sig: StandaloneSignature) -> None:
        """Add a signature to the appropriate group."""
        key = (sig.category, sig.subcategory, sig.sig_type)

        if key not in self.groups:
            self.groups[key] = SemanticGroup(
                category=sig.category,
                subcategory=sig.subcategory,
                sig_type=sig.sig_type,
            )

        group = self.groups[key]
        group.signatures.append(sig)

        if sig.matched_pattern:
            group.matched_patterns[sig.matched_pattern] = \
                group.matched_patterns.get(sig.matched_pattern, 0) + 1

        self.total_processed += 1
        self.by_type[sig.sig_type] += 1

    def get_groups(self) -> List[SemanticGroup]:
        """Get all groups sorted by count."""
        return sorted(self.groups.values(), key=lambda g: g.count, reverse=True)

    def get_groups_by_category(self) -> Dict[str, List[SemanticGroup]]:
        """Get groups organized by top-level category."""
        by_category: Dict[str, List[SemanticGroup]] = defaultdict(list)
        for group in self.groups.values():
            by_category[group.category].append(group)

        # Sort groups within each category
        for category in by_category:
            by_category[category].sort(key=lambda g: g.count, reverse=True)

        return dict(by_category)

    def summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        by_category = self.get_groups_by_category()

        category_counts = {
            cat: sum(g.count for g in groups)
            for cat, groups in by_category.items()
        }

        return {
            "total_signatures": self.total_processed,
            "total_groups": len(self.groups),
            "categories": len(by_category),
            "by_category": category_counts,
            "by_type": dict(self.by_type),
        }


def extract_standalone_signatures(
    data: bytes,
    progress_callback=None
) -> StandaloneSignatureGrouper:
    """
    Extract and group standalone signatures from VDM data.

    Standalone signatures are those outside of THREAT_BEGIN/END blocks.
    """
    from ..signature_extractor import parse_tlv_stream, THREAT_BEGIN, THREAT_END

    grouper = StandaloneSignatureGrouper()
    in_threat = False
    total_entries = 0
    standalone_count = 0

    # First pass: count entries for progress
    entries = list(parse_tlv_stream(data))
    total_entries = len(entries)

    # Second pass: classify standalone signatures
    for i, entry in enumerate(entries):
        if entry.sig_type == THREAT_BEGIN:
            in_threat = True
        elif entry.sig_type == THREAT_END:
            in_threat = False
        elif not in_threat:
            # This is a standalone signature
            classified = classify_standalone_signature(
                entry.sig_type,
                entry.data,
                entry.offset
            )
            grouper.add_signature(classified)
            standalone_count += 1

        if progress_callback and (i + 1) % 10000 == 0:
            progress_callback(i + 1, total_entries)

    if progress_callback:
        progress_callback(total_entries, total_entries)

    return grouper
