"""
ASR (Attack Surface Reduction) Rule Organizer

Extracts and organizes Defender Lua scripts by ASR rule GUID.
Lua scripts use mp.IsHipsRuleEnabled(GUID) to check ASR rule status.

Reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

from ..signature_extractor import (
    ThreatDefinition, extract_threats,
    LUA_STANDALONE, LUA_SCRIPT
)
from ..lua_decompiler.mplua_converter import extract_lua_from_signature, is_mplua
from ..lua_decompiler import is_lua_bytecode
from ..lua_decompiler.backend import decompile as decompile_bytecode


# Complete ASR Rule GUID mapping from Microsoft documentation
ASR_RULES = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": {
        "name": "Block abuse of exploited vulnerable signed drivers",
        "short_name": "VulnerableDrivers",
        "description": "Prevents applications from writing vulnerable signed drivers to disk",
    },
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": {
        "name": "Block Adobe Reader from creating child processes",
        "short_name": "AdobeReaderChildProcess",
        "description": "Blocks Adobe Reader from spawning child processes",
    },
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": {
        "name": "Block all Office applications from creating child processes",
        "short_name": "OfficeChildProcess",
        "description": "Prevents Office apps from creating child processes",
    },
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": {
        "name": "Block credential stealing from lsass.exe",
        "short_name": "LsassCredentialTheft",
        "description": "Blocks processes from accessing LSASS memory",
    },
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": {
        "name": "Block executable content from email client and webmail",
        "short_name": "EmailExecutableContent",
        "description": "Blocks execution of files dropped from email",
    },
    "01443614-cd74-433a-b99e-2ecdc07bfc25": {
        "name": "Block executable files from running unless they meet prevalence criteria",
        "short_name": "PrevalenceCheck",
        "description": "Prevents untrusted executables from launching",
    },
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": {
        "name": "Block execution of potentially obfuscated scripts",
        "short_name": "ObfuscatedScripts",
        "description": "Blocks suspicious obfuscated scripts",
    },
    "d3e037e1-3eb8-44c8-a917-57927947596d": {
        "name": "Block JavaScript or VBScript from launching downloaded executable content",
        "short_name": "ScriptDownloadedExe",
        "description": "Prevents scripts from launching downloaded content",
    },
    "3b576869-a4ec-4529-8536-b80a7769e899": {
        "name": "Block Office applications from creating executable content",
        "short_name": "OfficeExecutableContent",
        "description": "Prevents Office from creating executable files",
    },
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": {
        "name": "Block Office applications from injecting code into other processes",
        "short_name": "OfficeCodeInjection",
        "description": "Blocks code injection from Office apps",
    },
    "26190899-1602-49e8-8b27-eb1d0a1ce869": {
        "name": "Block Office communication application from creating child processes",
        "short_name": "OutlookChildProcess",
        "description": "Prevents Outlook from creating child processes",
    },
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": {
        "name": "Block persistence through WMI event subscription",
        "short_name": "WMIPersistence",
        "description": "Prevents WMI-based persistence mechanisms",
    },
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": {
        "name": "Block process creations originating from PSExec and WMI commands",
        "short_name": "PSExecWMI",
        "description": "Blocks processes from PsExec and WMI",
    },
    "33ddedf1-c6e0-47cb-833e-de6133960387": {
        "name": "Block rebooting machine in Safe Mode",
        "short_name": "SafeModeReboot",
        "description": "Prevents Safe Mode restart commands",
    },
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": {
        "name": "Block untrusted and unsigned processes that run from USB",
        "short_name": "USBUntrusted",
        "description": "Blocks unsigned executables from USB",
    },
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": {
        "name": "Block use of copied or impersonated system tools",
        "short_name": "ImpersonatedTools",
        "description": "Blocks duplicate system tool execution",
    },
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": {
        "name": "Block Webshell creation for Servers",
        "short_name": "WebshellCreation",
        "description": "Prevents web shell creation on servers",
    },
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": {
        "name": "Block Win32 API calls from Office macros",
        "short_name": "OfficeMacroWin32API",
        "description": "Prevents VBA macros from calling Win32 APIs",
    },
    "c1db55ab-c21a-4637-bb3f-a12568109d35": {
        "name": "Use advanced protection against ransomware",
        "short_name": "RansomwareProtection",
        "description": "Extra ransomware protection heuristics",
    },
    # Additional ASR rules found via IsHipsRuleEnabled
    "1081f0b6-3e1e-4f44-acce-816d65112d99": {
        "name": "Block execution of files related to Remote Monitoring & Management Tools",
        "short_name": "RMMTools",
        "description": "Blocks execution of files associated with Remote Monitoring and Management (RMM) tools",
    },
}

# Known external functions that may have definitions in separate scripts
# This is the priority list - other functions with data tables will also be auto-discovered
EXTERNAL_FUNCTION_NAMES = [
    'IsRmmToolFilePath',
    'IsRmmToolVersionInfo',
    'IsRmmToolOFN',
    'IsSuspiciousFileExt',
    'IsArchiveFileExt',
    'IsExecutableFileExt',
    'IsOfficeProcess',
    'IsScriptInterpreter',
    'GetPathExclusions',
    'GetMonitoredLocations',
]

# Pattern to match function definitions: FuncName = function(...)...end
# Matches Is* and Get* functions which commonly contain data tables
FUNCTION_DEFINITION_PATTERN = re.compile(
    r'((?:Is|Get)[A-Za-z]+)\s*=\s*function\s*\([^)]*\)(.*?)(?:\nend|\bend\b)',
    re.DOTALL
)

# Pattern to extract data entries from function bodies: {}[n] = "value"
DATA_ENTRY_PATTERN = re.compile(r'\{\}\[\d+\]\s*=\s*"([^"]+)"')


@dataclass
class FunctionDefinition:
    """A function definition found in a Lua script."""
    name: str
    source_script: str  # Path or identifier
    body: str           # Full function body text
    data_entries: List[str] = field(default_factory=list)


class FunctionRegistry:
    """Registry for tracking function definitions across all scripts."""

    def __init__(self):
        self.functions: Dict[str, FunctionDefinition] = {}

    def register_from_source(self, source: str, script_id: str, auto_discover: bool = True) -> int:
        """
        Find and register all function definitions in decompiled source.

        Args:
            source: Decompiled Lua source code
            script_id: Identifier for the source script
            auto_discover: If True, discover ALL functions with data tables,
                          not just known ones (default: True)

        Returns:
            Number of functions registered
        """
        if not source:
            return 0

        count = 0
        discovered_unknown = set()

        for match in FUNCTION_DEFINITION_PATTERN.finditer(source):
            func_name = match.group(1)
            func_body = match.group(2)

            # Extract data entries from the function body
            data_entries = extract_function_data_entries(func_body)

            # Only register if we found data entries (indicates this is a data-carrying function)
            if not data_entries:
                continue

            # Check if this is a known function or auto-discovery is enabled
            if func_name in EXTERNAL_FUNCTION_NAMES or auto_discover:
                func_def = FunctionDefinition(
                    name=func_name,
                    source_script=script_id,
                    body=func_body,
                    data_entries=data_entries
                )
                self.functions[func_name] = func_def
                count += 1
                logger.debug(f"Registered function {func_name} with {len(data_entries)} data entries from {script_id}")

                # Track functions not in our known list for potential additions
                if func_name not in EXTERNAL_FUNCTION_NAMES:
                    discovered_unknown.add(func_name)

        if discovered_unknown:
            logger.info(f"Discovered unknown functions with data tables: {discovered_unknown}")

        return count

    def get_function(self, name: str) -> Optional[FunctionDefinition]:
        """Get a function definition by name."""
        return self.functions.get(name)

    def get_all_functions(self) -> Dict[str, FunctionDefinition]:
        """Get all registered functions."""
        return self.functions.copy()


def extract_function_data_entries(body: str) -> List[str]:
    """
    Extract data entries from function body like {}[n] = "value".

    Args:
        body: Function body text

    Returns:
        List of extracted string values
    """
    entries = []
    for match in DATA_ENTRY_PATTERN.finditer(body):
        entries.append(match.group(1))
    return entries


def extract_function_calls(source: str, known_functions: List[str] = None) -> Set[str]:
    """
    Find calls to external functions that may have separate definitions.

    Args:
        source: Decompiled Lua source code
        known_functions: Optional list of functions to look for.
                        If None, uses EXTERNAL_FUNCTION_NAMES.

    Returns:
        Set of function names that are called
    """
    if known_functions is None:
        known_functions = EXTERNAL_FUNCTION_NAMES

    calls = set()
    for func in known_functions:
        if f'{func}(' in source:
            calls.add(func)
    return calls


# Regex patterns to find ASR GUID references in Lua code
GUID_PATTERN = re.compile(
    r'["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']?',
    re.IGNORECASE
)

# Pattern for mp.IsHipsRuleEnabled calls
HIPS_PATTERN = re.compile(
    r'mp\.IsHipsRuleEnabled\s*\(\s*["\']?([0-9a-fA-F-]{36})["\']?\s*\)',
    re.IGNORECASE
)


@dataclass
class ASRScript:
    """A Lua script associated with ASR rules."""
    threat_name: str
    bytecode: bytes
    source: Optional[str]
    asr_guids: Set[str]
    raw_data: bytes
    external_function_data: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class ASRWriterStats:
    """Statistics from ASR extraction."""
    total_lua_scripts: int = 0
    scripts_with_asr: int = 0
    asr_rules_found: Dict[str, int] = field(default_factory=dict)
    unknown_guids: Set[str] = field(default_factory=set)
    decompiled: int = 0
    failed: int = 0


def extract_guids_from_bytecode(data: bytes) -> Set[str]:
    """Extract GUIDs from raw bytecode (in string constants)."""
    guids = set()
    # Search for GUID patterns in the raw bytes
    text = data.decode('latin-1', errors='replace')
    for match in GUID_PATTERN.finditer(text):
        guid = match.group(1).lower()
        guids.add(guid)
    return guids


def extract_guids_from_source(source: str) -> Set[str]:
    """Extract GUIDs from decompiled Lua source."""
    guids = set()

    # Look for mp.IsHipsRuleEnabled calls
    for match in HIPS_PATTERN.finditer(source):
        guid = match.group(1).lower()
        guids.add(guid)

    # Also look for any GUID strings
    for match in GUID_PATTERN.finditer(source):
        guid = match.group(1).lower()
        guids.add(guid)

    return guids


def decompile_lua_safe(bytecode: bytes) -> Optional[str]:
    """Safely attempt to decompile Lua bytecode.

    Uses the improved luadec Python decompiler with MpLua format auto-conversion.

    Args:
        bytecode: Lua bytecode (MpLua or standard Lua 5.1)

    Returns:
        Decompiled Lua source or None on failure
    """
    try:
        # decompile_bytecode handles MpLua conversion automatically
        return decompile_bytecode(bytecode)
    except Exception:
        return None


def process_lua_signature(sig_data: bytes, threat_name: str) -> Optional[ASRScript]:
    """Process a Lua signature and extract ASR information."""
    # Extract Lua bytecode
    bytecode = extract_lua_from_signature(sig_data)
    if not bytecode:
        # Try using data directly
        if is_lua_bytecode(sig_data) or is_mplua(sig_data):
            bytecode = sig_data
        else:
            return None

    # Extract GUIDs from bytecode
    guids = extract_guids_from_bytecode(bytecode)

    # Try to decompile
    source = decompile_lua_safe(bytecode)
    if source:
        # Extract more GUIDs from source
        guids.update(extract_guids_from_source(source))

    # Filter to only known ASR GUIDs
    asr_guids = {g for g in guids if g in ASR_RULES}

    return ASRScript(
        threat_name=threat_name,
        bytecode=bytecode,
        source=source,
        asr_guids=asr_guids,
        raw_data=sig_data
    )


class ASRWriter:
    """
    Organizes Lua scripts by ASR rule.

    Uses two-pass processing:
    - Pass 1: Index all scripts and register function definitions
    - Pass 2: Resolve function calls to their definitions and extract data
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.stats = ASRWriterStats()
        self._asr_scripts: Dict[str, List[ASRScript]] = defaultdict(list)
        self._hips_enabled_scripts: List[ASRScript] = []
        self._all_scripts: List[ASRScript] = []  # All processed scripts for function resolution
        self.function_registry = FunctionRegistry()

    def process_threat(self, threat: ThreatDefinition) -> int:
        """
        Process a threat and extract ASR-related Lua scripts.

        This is PASS 1: Index all scripts and register function definitions.

        Returns number of ASR scripts found.
        """
        asr_count = 0

        for entry in threat.signatures:
            if entry.sig_type not in (LUA_STANDALONE, LUA_SCRIPT):
                continue

            self.stats.total_lua_scripts += 1

            script = process_lua_signature(entry.data, threat.threat_name)
            if not script:
                self.stats.failed += 1
                continue

            if script.source:
                self.stats.decompiled += 1

                # PASS 1: Register any function definitions found in this script
                self.function_registry.register_from_source(
                    script.source,
                    threat.threat_name
                )

            # Store all scripts for later function resolution
            self._all_scripts.append(script)

            if script.asr_guids:
                self.stats.scripts_with_asr += 1
                asr_count += 1

                for guid in script.asr_guids:
                    self._asr_scripts[guid].append(script)
                    self.stats.asr_rules_found[guid] = self.stats.asr_rules_found.get(guid, 0) + 1

            # Check for any HIPS-related scripts (may use unknown GUIDs)
            if script.source and 'IsHipsRuleEnabled' in script.source:
                self._hips_enabled_scripts.append(script)

                # Track unknown GUIDs
                all_guids = extract_guids_from_source(script.source)
                unknown = all_guids - set(ASR_RULES.keys())
                self.stats.unknown_guids.update(unknown)

        return asr_count

    def resolve_function_data(self) -> int:
        """
        PASS 2: Link function calls to definitions and extract data.

        For each ASR script that calls external functions, look up the
        function definitions and attach the extracted data.

        Returns number of scripts with resolved function data.
        """
        resolved_count = 0

        for guid, scripts in self._asr_scripts.items():
            for script in scripts:
                if not script.source:
                    continue

                # Find function calls in this script
                calls = extract_function_calls(script.source)

                if not calls:
                    continue

                # Look up definitions and extract data
                for func_name in calls:
                    func_def = self.function_registry.get_function(func_name)
                    if func_def and func_def.data_entries:
                        script.external_function_data[func_name] = func_def.data_entries
                        logger.debug(
                            f"Resolved {func_name} for ASR {guid}: "
                            f"{len(func_def.data_entries)} entries from {func_def.source_script}"
                        )

                if script.external_function_data:
                    resolved_count += 1

        return resolved_count

    def write_all(self) -> None:
        """Write all ASR-organized scripts."""
        asr_dir = self.output_dir / 'asr'
        asr_dir.mkdir(parents=True, exist_ok=True)

        # Write scripts organized by ASR GUID
        for guid, scripts in self._asr_scripts.items():
            rule_info = ASR_RULES.get(guid, {"short_name": "Unknown", "name": guid})
            rule_dir = asr_dir / guid
            rule_dir.mkdir(parents=True, exist_ok=True)

            # Write rule info
            info_file = rule_dir / 'README.md'
            with open(info_file, 'w') as f:
                f.write(f"# {rule_info['name']}\n\n")
                f.write(f"**GUID:** `{guid}`\n\n")
                if 'description' in rule_info:
                    f.write(f"**Description:** {rule_info['description']}\n\n")
                f.write(f"**Scripts:** {len(scripts)}\n\n")
                f.write("## Scripts\n\n")
                for i, script in enumerate(scripts):
                    f.write(f"- `{i+1}.lua` - {script.threat_name}\n")

            # Write each script
            for i, script in enumerate(scripts):
                # Write decompiled source
                if script.source:
                    src_file = rule_dir / f'{i+1}.lua'
                    with open(src_file, 'w') as f:
                        f.write(f"-- Threat: {script.threat_name}\n")
                        f.write(f"-- ASR Rule: {rule_info['name']}\n")
                        f.write(f"-- GUID: {guid}\n\n")
                        f.write(script.source)

                # Write bytecode
                bc_file = rule_dir / f'{i+1}.luac'
                with open(bc_file, 'wb') as f:
                    f.write(script.bytecode)

        # Write HipsEnabled scripts (all scripts using IsHipsRuleEnabled)
        hips_dir = asr_dir / 'HipsEnabled'
        hips_dir.mkdir(parents=True, exist_ok=True)

        for i, script in enumerate(self._hips_enabled_scripts):
            if script.source:
                src_file = hips_dir / f'{i+1}.lua'
                with open(src_file, 'w') as f:
                    f.write(f"-- Threat: {script.threat_name}\n")
                    f.write(f"-- ASR GUIDs: {', '.join(script.asr_guids) or 'Unknown'}\n\n")
                    f.write(script.source)

    def write_index(self) -> str:
        """Write index and summary files."""
        asr_dir = self.output_dir / 'asr'
        asr_dir.mkdir(parents=True, exist_ok=True)

        # Main README
        readme_path = asr_dir / 'README.md'
        lines = []
        lines.append("# Attack Surface Reduction (ASR) Rules")
        lines.append("")
        lines.append("Lua scripts organized by ASR rule GUID.")
        lines.append("")
        lines.append("## Statistics")
        lines.append("")
        lines.append(f"- Total Lua scripts: {self.stats.total_lua_scripts}")
        lines.append(f"- Scripts with ASR rules: {self.stats.scripts_with_asr}")
        lines.append(f"- Successfully decompiled: {self.stats.decompiled}")
        lines.append(f"- Decompilation failed: {self.stats.failed}")
        lines.append("")
        lines.append("## ASR Rules Found")
        lines.append("")
        lines.append("| GUID | Rule Name | Scripts |")
        lines.append("|------|-----------|---------|")

        for guid in sorted(self.stats.asr_rules_found.keys()):
            count = self.stats.asr_rules_found[guid]
            rule = ASR_RULES.get(guid, {"name": "Unknown"})
            lines.append(f"| `{guid}` | {rule['name']} | {count} |")

        lines.append("")
        lines.append("## Folder Structure")
        lines.append("")
        lines.append("```")
        lines.append("asr/")
        lines.append("├── HipsEnabled/           # All scripts using IsHipsRuleEnabled")
        for guid in sorted(self._asr_scripts.keys()):
            rule = ASR_RULES.get(guid, {"short_name": "Unknown"})
            lines.append(f"├── {guid}/  # {rule['short_name']}")
        lines.append("└── README.md")
        lines.append("```")

        if self.stats.unknown_guids:
            lines.append("")
            lines.append("## Unknown GUIDs")
            lines.append("")
            lines.append("These GUIDs were found but are not in the known ASR list:")
            lines.append("")
            for guid in sorted(self.stats.unknown_guids):
                lines.append(f"- `{guid}`")

        with open(readme_path, 'w') as f:
            f.write('\n'.join(lines))

        # Write CSV of ASR exemptions/detections
        csv_path = asr_dir / 'asr_summary.csv'
        with open(csv_path, 'w') as f:
            f.write("GUID,RuleName,ShortName,ScriptCount\n")
            for guid, count in sorted(self.stats.asr_rules_found.items()):
                rule = ASR_RULES.get(guid, {"name": "Unknown", "short_name": "Unknown"})
                f.write(f'"{guid}","{rule["name"]}","{rule.get("short_name", "")}",{count}\n')

        return str(readme_path)


def write_asr_rules(vdm_data: bytes, output_dir: str,
                    progress_callback=None) -> Tuple[ASRWriterStats, FunctionRegistry]:
    """
    Extract and organize ASR-related Lua scripts.

    Uses two-pass processing:
    - Pass 1: Index all scripts and register function definitions
    - Pass 2: Resolve function calls to their definitions

    Args:
        vdm_data: Decompressed VDM signature data
        output_dir: Output directory
        progress_callback: Optional callback(current, total)

    Returns:
        Tuple of (statistics, function_registry) for use by import service
    """
    writer = ASRWriter(output_dir)
    threats = list(extract_threats(vdm_data))

    # PASS 1: Process all threats and register function definitions
    for i, threat in enumerate(threats):
        writer.process_threat(threat)
        if progress_callback and i % 1000 == 0:
            progress_callback(i, len(threats))

    # PASS 2: Resolve function calls to definitions
    resolved = writer.resolve_function_data()
    logger.info(f"Resolved function data for {resolved} scripts")
    logger.info(f"Function registry contains: {list(writer.function_registry.functions.keys())}")

    writer.write_all()
    writer.write_index()

    return writer.stats, writer.function_registry


def get_asr_rule_info(guid: str) -> Optional[Dict]:
    """Get information about an ASR rule by GUID."""
    return ASR_RULES.get(guid.lower())


def list_asr_rules() -> Dict[str, Dict]:
    """Get all known ASR rules."""
    return ASR_RULES.copy()
