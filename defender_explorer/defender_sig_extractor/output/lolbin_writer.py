"""
LOLBin (Living Off The Land Binaries) Extractor

Extracts detection rules for LOLBins - legitimate Windows binaries
that can be abused for malicious purposes.

Reference: https://lolbas-project.github.io/
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from ..signature_extractor import (
    ThreatDefinition, extract_threats,
    LUA_STANDALONE, LUA_SCRIPT, PEHSTR, PEHSTR_EXT, PEHSTR_EXT2
)
from ..lua_decompiler.mplua_converter import extract_lua_from_signature
from ..lua_decompiler.undump import is_lua_bytecode
from ..lua_decompiler.backend import decompile as backend_decompile


# Known LOLBins with their categories and MITRE mappings
LOLBINS = {
    # Execution
    "cmd.exe": {"category": "Execution", "mitre": "T1059.003"},
    "powershell.exe": {"category": "Execution", "mitre": "T1059.001"},
    "pwsh.exe": {"category": "Execution", "mitre": "T1059.001"},
    "wscript.exe": {"category": "Execution", "mitre": "T1059.005"},
    "cscript.exe": {"category": "Execution", "mitre": "T1059.005"},
    "mshta.exe": {"category": "Execution", "mitre": "T1218.005"},
    "rundll32.exe": {"category": "Execution", "mitre": "T1218.011"},
    "regsvr32.exe": {"category": "Execution", "mitre": "T1218.010"},
    "msiexec.exe": {"category": "Execution", "mitre": "T1218.007"},
    "installutil.exe": {"category": "Execution", "mitre": "T1218.004"},
    "regasm.exe": {"category": "Execution", "mitre": "T1218.009"},
    "regsvcs.exe": {"category": "Execution", "mitre": "T1218.009"},
    "msbuild.exe": {"category": "Execution", "mitre": "T1127.001"},
    "cmstp.exe": {"category": "Execution", "mitre": "T1218.003"},
    "control.exe": {"category": "Execution", "mitre": "T1218.002"},
    "explorer.exe": {"category": "Execution", "mitre": "T1218"},
    "forfiles.exe": {"category": "Execution", "mitre": "T1202"},
    "pcalua.exe": {"category": "Execution", "mitre": "T1202"},
    "syncappvpublishingserver.exe": {"category": "Execution", "mitre": "T1218"},
    "bash.exe": {"category": "Execution", "mitre": "T1202"},
    "scriptrunner.exe": {"category": "Execution", "mitre": "T1218"},

    # Download
    "certutil.exe": {"category": "Download", "mitre": "T1105"},
    "bitsadmin.exe": {"category": "Download", "mitre": "T1197"},
    "curl.exe": {"category": "Download", "mitre": "T1105"},
    "wget.exe": {"category": "Download", "mitre": "T1105"},
    "desktopimgdownldr.exe": {"category": "Download", "mitre": "T1105"},
    "esentutl.exe": {"category": "Download", "mitre": "T1105"},
    "expand.exe": {"category": "Download", "mitre": "T1105"},
    "findstr.exe": {"category": "Download", "mitre": "T1105"},
    "hh.exe": {"category": "Download", "mitre": "T1105"},
    "ieexec.exe": {"category": "Download", "mitre": "T1105"},
    "replace.exe": {"category": "Download", "mitre": "T1105"},

    # AWL Bypass (Application Whitelisting)
    "bginfo.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "cdb.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "dnscmd.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "ftp.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "gpscript.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "infdefaultinstall.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "makecab.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "mavinject.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "microsoft.workflow.compiler.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "mmc.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "msdeploy.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "msconfig.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "odbcconf.exe": {"category": "AWL Bypass", "mitre": "T1218.008"},
    "pcwrun.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "presentationhost.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "rcsi.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "register-cimprovider.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "runscripthelper.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "sfc.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "te.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "tracker.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "tttracer.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "verclsid.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "wab.exe": {"category": "AWL Bypass", "mitre": "T1218"},
    "winrm.cmd": {"category": "AWL Bypass", "mitre": "T1218"},
    "wmic.exe": {"category": "AWL Bypass", "mitre": "T1047"},
    "xwizard.exe": {"category": "AWL Bypass", "mitre": "T1218"},

    # UAC Bypass
    "computerdefaults.exe": {"category": "UAC Bypass", "mitre": "T1548.002"},
    "eventvwr.exe": {"category": "UAC Bypass", "mitre": "T1548.002"},
    "fodhelper.exe": {"category": "UAC Bypass", "mitre": "T1548.002"},
    "sdclt.exe": {"category": "UAC Bypass", "mitre": "T1548.002"},
    "slui.exe": {"category": "UAC Bypass", "mitre": "T1548.002"},
    "wsreset.exe": {"category": "UAC Bypass", "mitre": "T1548.002"},

    # Credential Access
    "comsvcs.dll": {"category": "Credential Access", "mitre": "T1003"},
    "vaultcmd.exe": {"category": "Credential Access", "mitre": "T1555"},
    "vssadmin.exe": {"category": "Credential Access", "mitre": "T1003.003"},
    "diskshadow.exe": {"category": "Credential Access", "mitre": "T1003.003"},
    "ntdsutil.exe": {"category": "Credential Access", "mitre": "T1003.003"},

    # Reconnaissance
    "arp.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "dsquery.exe": {"category": "Reconnaissance", "mitre": "T1018"},
    "finger.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "hostname.exe": {"category": "Reconnaissance", "mitre": "T1082"},
    "ipconfig.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "nbtstat.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "net.exe": {"category": "Reconnaissance", "mitre": "T1087"},
    "net1.exe": {"category": "Reconnaissance", "mitre": "T1087"},
    "netsh.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "netstat.exe": {"category": "Reconnaissance", "mitre": "T1049"},
    "nltest.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "nslookup.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "pathping.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "ping.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "qprocess.exe": {"category": "Reconnaissance", "mitre": "T1057"},
    "query.exe": {"category": "Reconnaissance", "mitre": "T1057"},
    "quser.exe": {"category": "Reconnaissance", "mitre": "T1033"},
    "qwinsta.exe": {"category": "Reconnaissance", "mitre": "T1033"},
    "route.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "systeminfo.exe": {"category": "Reconnaissance", "mitre": "T1082"},
    "tasklist.exe": {"category": "Reconnaissance", "mitre": "T1057"},
    "tracert.exe": {"category": "Reconnaissance", "mitre": "T1016"},
    "whoami.exe": {"category": "Reconnaissance", "mitre": "T1033"},

    # Lateral Movement
    "psexec.exe": {"category": "Lateral Movement", "mitre": "T1570"},
    "psexesvc.exe": {"category": "Lateral Movement", "mitre": "T1570"},

    # Persistence
    "at.exe": {"category": "Persistence", "mitre": "T1053.002"},
    "reg.exe": {"category": "Persistence", "mitre": "T1112"},
    "sc.exe": {"category": "Persistence", "mitre": "T1543.003"},
    "schtasks.exe": {"category": "Persistence", "mitre": "T1053.005"},

    # Defense Evasion
    "attrib.exe": {"category": "Defense Evasion", "mitre": "T1564.001"},
    "icacls.exe": {"category": "Defense Evasion", "mitre": "T1222"},
    "takeown.exe": {"category": "Defense Evasion", "mitre": "T1222"},
    "wevtutil.exe": {"category": "Defense Evasion", "mitre": "T1070.001"},

    # Data Exfiltration
    "extrac32.exe": {"category": "Exfiltration", "mitre": "T1560"},
    "print.exe": {"category": "Exfiltration", "mitre": "T1105"},
    "tar.exe": {"category": "Exfiltration", "mitre": "T1560"},
    "xcopy.exe": {"category": "Exfiltration", "mitre": "T1560"},

    # Other
    "dxcap.exe": {"category": "Other", "mitre": "T1218"},
    "fltmc.exe": {"category": "Other", "mitre": "T1562"},
    "pktmon.exe": {"category": "Other", "mitre": "T1040"},
    "psr.exe": {"category": "Other", "mitre": "T1113"},
    "rpcping.exe": {"category": "Other", "mitre": "T1018"},
}


@dataclass
class LOLBinDetection:
    """A detection related to a LOLBin."""
    threat_name: str
    lolbin: str
    category: str
    mitre: str
    source: Optional[str]
    sig_type: str


@dataclass
class LOLBinWriterStats:
    """Statistics from LOLBin extraction."""
    signatures_analyzed: int = 0
    lolbin_detections: int = 0
    lolbins_found: Dict[str, int] = field(default_factory=dict)
    categories_found: Dict[str, int] = field(default_factory=dict)


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable strings."""
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings


def find_lolbins_in_data(data: bytes) -> Set[str]:
    """Find LOLBin references in signature data."""
    found = set()
    strings = extract_strings(data, 3)
    text = ' '.join(strings).lower()

    for lolbin in LOLBINS.keys():
        # Check for the binary name
        lolbin_lower = lolbin.lower()
        if lolbin_lower in text:
            found.add(lolbin)
        # Also check without extension
        base = lolbin_lower.rsplit('.', 1)[0]
        if len(base) > 3 and base in text:
            found.add(lolbin)

    return found


def decompile_lua_safe(bytecode: bytes) -> Optional[str]:
    """Safely decompile Lua."""
    try:
        if not is_lua_bytecode(bytecode):
            return None
        return backend_decompile(bytecode)
    except:
        return None


class LOLBinWriter:
    """Extracts and organizes LOLBin detections."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.stats = LOLBinWriterStats()
        self._lolbin_detections: Dict[str, List[LOLBinDetection]] = defaultdict(list)
        self._category_detections: Dict[str, List[LOLBinDetection]] = defaultdict(list)

    def process_threat(self, threat: ThreatDefinition) -> int:
        """Process threat for LOLBin detections."""
        found_count = 0

        for entry in threat.signatures:
            self.stats.signatures_analyzed += 1

            # Check for LOLBins in the signature
            lolbins_found = find_lolbins_in_data(entry.data)

            # For Lua scripts, also check decompiled source
            source = None
            if entry.sig_type in (LUA_STANDALONE, LUA_SCRIPT):
                bytecode = extract_lua_from_signature(entry.data)
                if not bytecode:
                    if is_lua_bytecode(entry.data) or is_mplua(entry.data):
                        bytecode = entry.data
                if bytecode:
                    source = decompile_lua_safe(bytecode)
                    if source:
                        # Find LOLBins in source
                        source_lower = source.lower()
                        for lolbin in LOLBINS.keys():
                            if lolbin.lower() in source_lower:
                                lolbins_found.add(lolbin)

            # Record detections
            for lolbin in lolbins_found:
                info = LOLBINS[lolbin]
                detection = LOLBinDetection(
                    threat_name=threat.threat_name,
                    lolbin=lolbin,
                    category=info["category"],
                    mitre=info["mitre"],
                    source=source,
                    sig_type="Lua" if entry.sig_type in (LUA_STANDALONE, LUA_SCRIPT) else "PEHSTR"
                )

                self._lolbin_detections[lolbin].append(detection)
                self._category_detections[info["category"]].append(detection)

                self.stats.lolbin_detections += 1
                self.stats.lolbins_found[lolbin] = self.stats.lolbins_found.get(lolbin, 0) + 1
                self.stats.categories_found[info["category"]] = self.stats.categories_found.get(info["category"], 0) + 1
                found_count += 1

        return found_count

    def write_all(self) -> None:
        """Write LOLBin-organized output."""
        lolbin_dir = self.output_dir / 'lolbin'
        lolbin_dir.mkdir(parents=True, exist_ok=True)

        # Write by LOLBin
        for lolbin, detections in self._lolbin_detections.items():
            info = LOLBINS[lolbin]
            bin_dir = lolbin_dir / lolbin.replace('.', '_')
            bin_dir.mkdir(parents=True, exist_ok=True)

            # README
            readme_path = bin_dir / 'README.md'
            with open(readme_path, 'w') as f:
                f.write(f"# {lolbin}\n\n")
                f.write(f"**Category:** {info['category']}\n\n")
                f.write(f"**MITRE ATT&CK:** {info['mitre']}\n\n")
                f.write(f"**Detections:** {len(detections)}\n\n")
                f.write("## Threats\n\n")
                seen = set()
                for d in detections:
                    if d.threat_name not in seen:
                        f.write(f"- {d.threat_name}\n")
                        seen.add(d.threat_name)

            # Write Lua scripts
            lua_idx = 0
            for detection in detections:
                if detection.source:
                    lua_idx += 1
                    script_path = bin_dir / f'{lua_idx}.lua'
                    with open(script_path, 'w') as f:
                        f.write(f"-- Threat: {detection.threat_name}\n")
                        f.write(f"-- LOLBin: {detection.lolbin}\n")
                        f.write(f"-- MITRE: {detection.mitre}\n\n")
                        f.write(detection.source)
                    if lua_idx >= 50:  # Limit
                        break

        # Write category summaries
        for category, detections in self._category_detections.items():
            cat_file = lolbin_dir / f'{category.replace(" ", "_").lower()}.md'
            with open(cat_file, 'w') as f:
                f.write(f"# {category} LOLBins\n\n")
                f.write(f"Detections: {len(detections)}\n\n")

                # Group by LOLBin
                by_bin = defaultdict(list)
                for d in detections:
                    by_bin[d.lolbin].append(d.threat_name)

                for lolbin, threats in sorted(by_bin.items()):
                    info = LOLBINS[lolbin]
                    f.write(f"## {lolbin}\n\n")
                    f.write(f"MITRE: {info['mitre']}\n\n")
                    f.write("Threats:\n")
                    for t in sorted(set(threats))[:10]:
                        f.write(f"- {t}\n")
                    if len(set(threats)) > 10:
                        f.write(f"- ... and {len(set(threats)) - 10} more\n")
                    f.write("\n")

    def write_index(self) -> str:
        """Write LOLBin index."""
        lolbin_dir = self.output_dir / 'lolbin'
        lolbin_dir.mkdir(parents=True, exist_ok=True)

        readme_path = lolbin_dir / 'README.md'
        lines = []
        lines.append("# LOLBin Detections")
        lines.append("")
        lines.append("Living Off The Land Binaries detected by Defender.")
        lines.append("")
        lines.append("Reference: https://lolbas-project.github.io/")
        lines.append("")
        lines.append("## Statistics")
        lines.append("")
        lines.append(f"- Signatures analyzed: {self.stats.signatures_analyzed}")
        lines.append(f"- LOLBin detections: {self.stats.lolbin_detections}")
        lines.append(f"- Unique LOLBins: {len(self.stats.lolbins_found)}")
        lines.append("")
        lines.append("## LOLBins by Detection Count")
        lines.append("")
        lines.append("| Binary | Category | MITRE | Count |")
        lines.append("|--------|----------|-------|-------|")

        for lolbin, count in sorted(self.stats.lolbins_found.items(), key=lambda x: -x[1])[:40]:
            info = LOLBINS[lolbin]
            lines.append(f"| {lolbin} | {info['category']} | {info['mitre']} | {count} |")

        lines.append("")
        lines.append("## Categories")
        lines.append("")
        for cat, count in sorted(self.stats.categories_found.items(), key=lambda x: -x[1]):
            lines.append(f"- **{cat}**: {count}")

        with open(readme_path, 'w') as f:
            f.write('\n'.join(lines))

        return str(readme_path)


def write_lolbin_detections(vdm_data: bytes, output_dir: str, progress_callback=None) -> LOLBinWriterStats:
    """Extract and write LOLBin detections."""
    writer = LOLBinWriter(output_dir)
    threats = list(extract_threats(vdm_data))

    for i, threat in enumerate(threats):
        writer.process_threat(threat)
        if progress_callback and i % 1000 == 0:
            progress_callback(i, len(threats))

    writer.write_all()
    writer.write_index()

    return writer.stats
