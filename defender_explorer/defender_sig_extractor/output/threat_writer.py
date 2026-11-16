"""
Threat-organized signature output writer.

Creates a folder structure organized by threat type/family with
signatures formatted in readable C-like structures.

OPTIMIZED: Uses batching, multiprocessing, and combined family files.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Iterator, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import multiprocessing as mp

from ..signature_extractor import (
    TLVEntry, ThreatDefinition, parse_tlv_stream,
    parse_threat_begin, parse_pehstr_signature,
    THREAT_BEGIN, THREAT_END, PEHSTR, PEHSTR_EXT, PEHSTR_EXT2,
    LUA_STANDALONE, LUA_SCRIPT
)


@dataclass
class ParsedSignature:
    """A parsed signature with formatted output."""
    sig_type: int
    type_name: str
    raw_data: bytes
    formatted: str
    strings: List[str] = field(default_factory=list)


def format_hex_dump(data: bytes, indent: str = "    ") -> str:
    """Format data as hex dump with ASCII."""
    lines = []
    for offset in range(0, min(len(data), 256), 16):  # Limit to 256 bytes
        chunk = data[offset:offset + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(48)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{indent}{offset:04x}  {hex_part}  {ascii_part}")
    if len(data) > 256:
        lines.append(f"{indent}... ({len(data) - 256} more bytes)")
    return '\n'.join(lines)


def extract_strings(data: bytes, min_len: int = 4, max_strings: int = 10) -> List[str]:
    """Extract printable ASCII strings from data."""
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
                if len(strings) >= max_strings:
                    return strings
            current = []
    if len(current) >= min_len and len(strings) < max_strings:
        strings.append(''.join(current))
    return strings


def format_pehstr_fast(sig_type: int, data: bytes) -> Tuple[str, List[str]]:
    """Fast PEHSTR formatting without full parsing."""
    try:
        if len(data) < 7:
            return f"// Invalid PEHSTR (size={len(data)})", []

        threshold = data[2] | (data[3] << 8)
        num_rules = data[4] | (data[5] << 8)

        lines = [f"// Threshold: 0x{threshold:X}, Subrules: {num_rules}"]
        strings = extract_strings(data[7:], max_strings=5)

        for i, s in enumerate(strings):
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'char* str_{i} = "{escaped}";')

        return '\n'.join(lines), strings
    except Exception:
        return f"// Parse error\n{format_hex_dump(data[:64])}", []


def format_signature_fast(entry: TLVEntry) -> Tuple[str, List[str]]:
    """Fast signature formatting."""
    sig_type = entry.sig_type
    data = entry.data

    if sig_type in (PEHSTR, PEHSTR_EXT, PEHSTR_EXT2):
        return format_pehstr_fast(sig_type, data)
    elif sig_type in (LUA_STANDALONE, LUA_SCRIPT):
        return f"// Lua script ({len(data)} bytes)", []
    elif sig_type in (0x44, 0x45, 0x46, 0x47):
        if len(data) == 32:
            return f'char* sha256 = "{data.hex()}";', []
        elif len(data) == 64:
            return f'char* sha512 = "{data.hex()}";', []
        return f"// Hash ({len(data)} bytes): {data[:32].hex()}...", []
    else:
        strings = extract_strings(data, max_strings=5)
        lines = [f"// {entry.type_name} ({len(data)} bytes)"]
        for s in strings[:3]:
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')[:80]
            lines.append(f'char* s = "{escaped}";')
        return '\n'.join(lines), strings


def categorize_threat(threat_name: str) -> Tuple[str, str]:
    """Categorize threat into folder structure."""
    name = threat_name.strip('!')

    categories = {
        'Trojan': 'Trojan', 'Backdoor': 'Backdoor', 'Worm': 'Worm',
        'Virus': 'Virus', 'Ransom': 'Ransomware', 'PUA': 'PUA',
        'HackTool': 'HackTool', 'Exploit': 'Exploit', 'PWS': 'PasswordStealer',
        'Downloader': 'Downloader', 'Dropper': 'Dropper', 'Spyware': 'Spyware',
        'Adware': 'Adware', 'Riskware': 'Riskware', 'VirTool': 'VirTool',
        'DoS': 'DoS', 'Behavior': 'Behavior', 'HSTR': 'HSTR', 'ALF': 'ALF',
        'SoftwareBundler': 'Bundler', 'BrowserModifier': 'BrowserModifier',
    }

    for prefix, category in categories.items():
        if prefix.lower() in name.lower():
            parts = name.split(':')
            family = parts[-1].split('/')[0].split('.')[0] if len(parts) > 1 else name.split('.')[0]
            return category, family

    if ':Win32/' in name or ':Win64/' in name:
        parts = name.split('/')
        return 'Windows', parts[-1].split('.')[0] if len(parts) > 1 else 'Unknown'

    if ':Linux/' in name:
        return 'Linux', name.split('/')[-1].split('.')[0]

    if ':MacOS/' in name:
        return 'MacOS', name.split('/')[-1].split('.')[0]

    if name.startswith('#'):
        return 'Internal', name.lstrip('#').split('.')[0]

    return 'Other', name.split('.')[0].split(':')[-1].split('/')[-1]


def sanitize_filename(name: str) -> str:
    """Sanitize string for use as filename."""
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    name = re.sub(r'\s+', '_', name)
    return name.strip('._')[:80]


def format_threat_entry(threat: ThreatDefinition) -> str:
    """Format a single threat entry for combined output."""
    lines = []
    lines.append(f"/* === {threat.threat_name} === */")
    lines.append(f"// Signature ID: 0x{threat.signature_id:08X}")
    lines.append(f"// Signatures: {len(threat.signatures)}")

    # Group by type and format
    by_type = defaultdict(list)
    for entry in threat.signatures:
        by_type[entry.type_name].append(entry)

    for type_name, entries in sorted(by_type.items()):
        lines.append(f"// {type_name}: {len(entries)}")
        for entry in entries[:3]:  # Limit entries per type
            fmt, _ = format_signature_fast(entry)
            lines.append(fmt)

    lines.append("")
    return '\n'.join(lines)


def write_family_batch(args: Tuple[str, str, List[ThreatDefinition]]) -> Tuple[str, int]:
    """Write a batch of threats for a family (for multiprocessing)."""
    output_dir, family_key, threats = args
    category, family = family_key.split('/', 1) if '/' in family_key else ('Other', family_key)

    family_dir = Path(output_dir) / sanitize_filename(category) / sanitize_filename(family)
    family_dir.mkdir(parents=True, exist_ok=True)

    # Write combined file for family
    combined_path = family_dir / '_combined.sig'
    with open(combined_path, 'w', encoding='utf-8') as f:
        f.write(f"/*\n * Family: {family}\n * Category: {category}\n")
        f.write(f" * Threats: {len(threats)}\n */\n\n")

        for threat in threats:
            f.write(format_threat_entry(threat))

    return family_key, len(threats)


class ThreatWriter:
    """Optimized threat writer using batching and parallel processing."""

    def __init__(self, output_dir: str, workers: int = None):
        self.output_dir = Path(output_dir)
        self.workers = workers or max(1, mp.cpu_count() - 1)
        self.stats = {
            'threats': 0,
            'signatures': 0,
            'categories': set(),
            'families': set(),
        }
        self._batches: Dict[str, List[ThreatDefinition]] = defaultdict(list)

    def add_threat(self, threat: ThreatDefinition) -> None:
        """Add threat to batch."""
        if not threat.threat_name:
            return

        category, family = categorize_threat(threat.threat_name)
        family_key = f"{category}/{family}"

        self._batches[family_key].append(threat)
        self.stats['threats'] += 1
        self.stats['signatures'] += len(threat.signatures)
        self.stats['categories'].add(category)
        self.stats['families'].add(family)

    def write_all(self, progress_callback=None) -> None:
        """Write all batched threats in parallel."""
        # Prepare batch args
        batch_args = [
            (str(self.output_dir), family_key, threats)
            for family_key, threats in self._batches.items()
        ]

        total = len(batch_args)
        completed = 0

        # Use ThreadPoolExecutor for I/O-bound work
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(write_family_batch, args) for args in batch_args]

            for future in futures:
                try:
                    family_key, count = future.result()
                    completed += 1
                    if progress_callback and completed % 100 == 0:
                        progress_callback(completed, total)
                except Exception as e:
                    completed += 1

    def write_index(self) -> str:
        """Write index file."""
        index_path = self.output_dir / 'INDEX.md'

        lines = [
            "# Extracted Defender Signatures",
            "",
            f"- **Total Threats**: {self.stats['threats']}",
            f"- **Total Signatures**: {self.stats['signatures']}",
            f"- **Categories**: {len(self.stats['categories'])}",
            f"- **Families**: {len(self.stats['families'])}",
            "",
            "## Categories",
            "",
        ]

        for cat in sorted(self.stats['categories']):
            cat_path = self.output_dir / sanitize_filename(cat)
            if cat_path.exists():
                families = list(cat_path.iterdir())
                lines.append(f"- **{cat}/** ({len(families)} families)")

        with open(index_path, 'w') as f:
            f.write('\n'.join(lines))

        return str(index_path)


def write_threats_organized(vdm_data: bytes, output_dir: str,
                            progress_callback=None) -> Dict:
    """
    Extract and write all threats in organized structure.

    OPTIMIZED: Streams threats, batches by family, writes in parallel.
    """
    from ..signature_extractor import extract_threats

    writer = ThreatWriter(output_dir)

    # Stream threats without materializing full list
    threat_count = 0
    for threat in extract_threats(vdm_data):
        writer.add_threat(threat)
        threat_count += 1
        if progress_callback and threat_count % 10000 == 0:
            progress_callback(threat_count, 0)  # Total unknown during streaming

    if progress_callback:
        progress_callback(threat_count, threat_count)

    # Write batches in parallel
    print(f"    Writing {len(writer._batches)} family files...")
    writer.write_all()
    writer.write_index()

    return {
        'threats': writer.stats['threats'],
        'signatures': writer.stats['signatures'],
        'categories': len(writer.stats['categories']),
        'families': len(writer.stats['families']),
    }
