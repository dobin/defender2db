"""
Lua Logic Analyzer Service

Analyzes decompiled Lua scripts and generates human-readable summaries
of the detection logic flow.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class LogicBlock:
    """A block of detection logic."""
    type: str  # 'condition', 'action', 'function', 'return'
    description: str
    indent: int = 0
    children: List['LogicBlock'] = field(default_factory=list)


@dataclass
class LogicSummary:
    """Summary of script logic."""
    rule_name: Optional[str] = None
    rule_guid: Optional[str] = None
    entry_point: Optional[str] = None
    functions: List[Dict] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    flow: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "rule_name": self.rule_name,
            "rule_guid": self.rule_guid,
            "entry_point": self.entry_point,
            "functions": self.functions,
            "conditions": self.conditions,
            "actions": self.actions,
            "flow": self.flow,
        }


class LuaLogicAnalyzer:
    """Analyzes Lua scripts to extract readable logic summaries."""

    # Known function patterns and their meanings
    FUNCTION_MEANINGS = {
        'GetRuleInfo': 'Returns rule metadata (name, GUID, description)',
        'GetPathExclusions': 'Returns paths where this rule does NOT apply',
        'GetMonitoredLocations': 'Returns paths monitored for suspicious activity',
        'GetCommandLineRegExp': 'Returns regex pattern for command line detection',
        'GetCommandLineExclusions': 'Returns command patterns to exclude',
        'GetMonitoredExtensions': 'Returns file extensions to monitor',
        'OnBmHit': 'Main detection entry point - called when behavior is detected',
        'OnCreatedProcess': 'Called when a new process is created',
        'OnImageLoad': 'Called when a DLL/image is loaded',
        'OnFileCreated': 'Called when a file is created',
        'OnFileRenamed': 'Called when a file is renamed',
        'OnRegistryValueSet': 'Called when a registry value is modified',
        'OnScriptContent': 'Called to analyze script content',
    }

    # Known API calls and their meanings
    API_MEANINGS = {
        'mp.set_mpattribute': 'Sets detection attribute for reporting',
        'mp.INFECTED': 'Marks as malicious/infected',
        'mp.CLEAN': 'Marks as clean/safe',
        'bm.get': 'Gets behavior monitoring context data',
        'bm.add': 'Adds behavior to monitoring list',
        'bm.trigger_sig': 'Triggers a signature/detection',
        'string.find': 'Searches for pattern in string',
        'string.lower': 'Converts string to lowercase',
        'string.match': 'Matches regex pattern',
        'IsHipsRuleEnabled': 'Checks if ASR rule is enabled',
        'GetTaintLevelHR': 'Gets threat/taint level of file',
        'IsRmmToolFilePath': 'Checks if path is an RMM tool',
        'IsRmmToolVersionInfo': 'Checks version info for RMM tool',
        'IsRmmToolOFN': 'Checks original filename for RMM tool',
        'IsOfficeProcess': 'Checks if process is Microsoft Office',
        'IsScriptInterpreter': 'Checks if process is a script interpreter',
        'TrackPidAndTechniqueBM': 'Tracks PID with MITRE technique',
    }

    def analyze(self, source: str) -> LogicSummary:
        """Analyze Lua source and return a logic summary."""
        summary = LogicSummary()

        if not source:
            return summary

        # Extract rule metadata
        self._extract_rule_info(source, summary)

        # Extract function definitions
        self._extract_functions(source, summary)

        # Extract main detection conditions
        self._extract_conditions(source, summary)

        # Extract actions (what happens on detection)
        self._extract_actions(source, summary)

        # Build logic flow description
        self._build_flow(source, summary)

        return summary

    def _extract_rule_info(self, source: str, summary: LogicSummary) -> None:
        """Extract rule name and GUID from GetRuleInfo."""
        # Look for Name assignment
        name_match = re.search(r'\.Name\s*=\s*["\']([^"\']+)["\']', source)
        if name_match:
            summary.rule_name = name_match.group(1)

        # Look for GUID in IsHipsRuleEnabled
        guid_match = re.search(r'IsHipsRuleEnabled\s*\)?\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', source)
        if guid_match:
            summary.rule_guid = guid_match.group(1).lower()

    def _extract_functions(self, source: str, summary: LogicSummary) -> None:
        """Extract function definitions and their purposes."""
        # Find all function definitions
        func_pattern = re.compile(r'(\w+)\s*=\s*function\s*\(([^)]*)\)')

        for match in func_pattern.finditer(source):
            func_name = match.group(1)
            params = match.group(2).strip()

            meaning = self.FUNCTION_MEANINGS.get(func_name, None)

            # Skip internal/helper functions
            if func_name.startswith('l_') or func_name.startswith('_'):
                continue

            summary.functions.append({
                "name": func_name,
                "params": params,
                "description": meaning,
            })

        # Identify entry point
        for entry in ['OnBmHit', 'OnCreatedProcess', 'OnImageLoad', 'OnFileCreated']:
            if f'{entry} = function' in source or f'{entry}=function' in source:
                summary.entry_point = entry
                break

    def _extract_conditions(self, source: str, summary: LogicSummary) -> None:
        """Extract key conditional checks."""
        conditions = []

        # Check for rule enabled condition
        if 'IsHipsRuleEnabled' in source:
            guid = summary.rule_guid or 'rule GUID'
            conditions.append(f"IF ASR rule {guid} is enabled")

        # Check for path exclusions
        if 'GetPathExclusions' in source:
            conditions.append("IF file path is NOT in exclusion list")

        # Check for monitored locations
        if 'GetMonitoredLocations' in source:
            conditions.append("IF file is in monitored location")

        # Check for process type conditions
        if 'IsOfficeProcess' in source:
            conditions.append("IF parent process is Microsoft Office")
        if 'IsScriptInterpreter' in source:
            conditions.append("IF process is a script interpreter (cmd, powershell, etc.)")

        # Check for RMM tool detection
        if 'IsRmmTool' in source:
            conditions.append("IF file is identified as an RMM tool")

        # Check for taint level
        if 'GetTaintLevelHR' in source:
            conditions.append("IF file has low trust/prevalence")

        # Check for command line patterns
        if 'GetCommandLineRegExp' in source or 'commandline' in source.lower():
            conditions.append("IF command line matches suspicious pattern")

        # Check for extension monitoring
        ext_match = re.findall(r'(?:extension|ext)\s*==\s*["\'](\w+)["\']', source, re.IGNORECASE)
        if ext_match:
            exts = list(set(ext_match))[:5]  # Limit to 5
            conditions.append(f"IF file extension is: {', '.join(exts)}")

        summary.conditions = conditions

    def _extract_actions(self, source: str, summary: LogicSummary) -> None:
        """Extract what actions are taken on detection."""
        actions = []

        # Check for INFECTED return
        if 'mp.INFECTED' in source or 'return 0' in source:
            actions.append("BLOCK: Return INFECTED status (block execution)")

        # Check for attribute setting
        attr_matches = re.findall(r'mp\.set_mpattribute\s*\([^)]*["\']([^"\']+)["\']', source)
        for attr in attr_matches[:3]:  # Limit to 3
            actions.append(f"LOG: Set attribute '{attr}' for telemetry")

        # Check for MITRE technique tracking
        mitre_matches = re.findall(r'TrackPidAndTechnique\w*\s*\([^,]+,\s*["\']([Tt]\d{4}(?:\.\d{3})?)["\']', source)
        for tech in mitre_matches[:3]:
            actions.append(f"TRACK: Log MITRE technique {tech.upper()}")

        # Check for behavior monitoring additions
        if 'bm.add' in source:
            actions.append("MONITOR: Add to behavior monitoring for further analysis")

        # Check for trigger_sig
        if 'bm.trigger_sig' in source or 'trigger_sig' in source:
            actions.append("ALERT: Trigger signature detection")

        # Check for CLEAN return
        if 'mp.CLEAN' in source or 'return 1' in source:
            actions.append("ALLOW: Return CLEAN status (allow execution)")

        summary.actions = actions

    def _build_flow(self, source: str, summary: LogicSummary) -> None:
        """Build a simplified logic flow description."""
        flow = []

        # Start with entry point
        if summary.entry_point:
            flow.append(f"1. Entry: {summary.entry_point}() is called by Defender")

        # Add rule check
        if 'IsHipsRuleEnabled' in source:
            flow.append("2. Check if this ASR rule is enabled in policy")

        # Add exclusion check
        if 'GetPathExclusions' in source or 'exclusion' in source.lower():
            flow.append("3. Check if file/path is in exclusion list -> ALLOW if excluded")

        # Add main detection logic
        if summary.conditions:
            flow.append("4. Evaluate detection conditions:")
            for i, cond in enumerate(summary.conditions[:4]):
                flow.append(f"   {chr(97+i)}. {cond}")

        # Add outcome
        has_block = 'mp.INFECTED' in source or 'return 0' in source
        has_allow = 'mp.CLEAN' in source or 'return 1' in source

        if has_block and has_allow:
            flow.append("5. Outcome: BLOCK if conditions match, otherwise ALLOW")
        elif has_block:
            flow.append("5. Outcome: BLOCK execution if conditions match")
        elif has_allow:
            flow.append("5. Outcome: ALLOW with monitoring")

        summary.flow = flow


def analyze_lua_script(source: str) -> Dict:
    """
    Analyze a Lua script and return a logic summary.

    Args:
        source: Decompiled Lua source code

    Returns:
        Dictionary with logic summary
    """
    analyzer = LuaLogicAnalyzer()
    summary = analyzer.analyze(source)
    return summary.to_dict()
