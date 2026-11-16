"""
YARA Rule Generator for Microsoft Defender Signatures

Converts Defender PEHSTR/PEHSTR_EXT signatures to YARA rules.
Based on concepts from defender2yara.
"""

import re
from pathlib import Path
from typing import List, Dict, Iterator, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict

from ..signature_extractor import (
    ThreatDefinition, extract_threats,
    PEHSTR, PEHSTR_EXT, PEHSTR_EXT2
)
from ..signature_handlers.pehstr_handler import (
    parse_pehstr_signature, PEHSTRSignature, PEHSTRSubRule,
    parse_wildcards, WILDCARD_PREFIX
)


def sanitize_rule_name(name: str) -> str:
    """Convert threat name to valid YARA rule name."""
    # Remove invalid characters
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Ensure doesn't start with digit
    if name and name[0].isdigit():
        name = '_' + name
    # Truncate
    return name[:128] if name else 'unknown_threat'


def bytes_to_yara_hex(data: bytes) -> str:
    """Convert bytes to YARA hex string, handling wildcards."""
    if WILDCARD_PREFIX not in data:
        # Simple case: no wildcards
        return data.hex()

    # Parse wildcards and build YARA pattern
    parts = []
    offset = 0

    wildcards = list(parse_wildcards(data))
    wc_positions = []

    # Find wildcard positions
    pos = 0
    while True:
        idx = data.find(bytes([WILDCARD_PREFIX]), pos)
        if idx == -1:
            break
        wc_positions.append(idx)
        pos = idx + 1

    # Build pattern
    last_end = 0
    for wc in wildcards:
        # Find this wildcard in data
        for wc_pos in wc_positions:
            if wc_pos >= last_end:
                # Add literal bytes before wildcard
                if wc_pos > last_end:
                    parts.append(data[last_end:wc_pos].hex())

                # Add wildcard pattern
                if wc.pattern_type == "SINGLE_BYTE":
                    # Match exactly N bytes
                    parts.append(' '.join(['??' for _ in range(wc.param1)]))
                    last_end = wc_pos + 3
                elif wc.pattern_type == "RANGE":
                    # Match 0 to N bytes
                    parts.append(f'[0-{wc.param1}]')
                    last_end = wc_pos + 3
                elif wc.pattern_type == "OR":
                    # OR pattern
                    seq_a = data[wc_pos + 4:wc_pos + 4 + wc.param1].hex()
                    seq_b = data[wc_pos + 4 + wc.param1:wc_pos + 4 + wc.param1 + wc.param2].hex()
                    parts.append(f'({seq_a} | {seq_b})')
                    last_end = wc_pos + 4 + wc.param1 + wc.param2
                elif wc.pattern_type in ("REGEX", "REGEX_ICASE"):
                    # Regex patterns - approximate with wildcards
                    parts.append(f'[0-{wc.param1}]')
                    last_end = wc_pos + 4 + wc.param2
                else:
                    # Unknown, skip
                    last_end = wc_pos + 2
                break

    # Add remaining bytes
    if last_end < len(data):
        parts.append(data[last_end:].hex())

    return ' '.join(parts)


def subrule_to_yara_string(sr: PEHSTRSubRule, index: int) -> Tuple[str, str]:
    """
    Convert a PEHSTR subrule to YARA string definition.

    Returns: (string_name, string_definition)
    """
    name = f"$s{index}"

    # Check if it's mostly printable ASCII
    printable = sum(1 for b in sr.bytes_to_match if 32 <= b < 127)
    is_text = printable > len(sr.bytes_to_match) * 0.8 and WILDCARD_PREFIX not in sr.bytes_to_match

    if is_text:
        # Text string
        try:
            text = sr.bytes_to_match.decode('ascii')
            escaped = text.replace('\\', '\\\\').replace('"', '\\"')
            return name, f'"{escaped}"'
        except:
            pass

    # Hex string
    hex_pattern = bytes_to_yara_hex(sr.bytes_to_match)
    return name, f'{{ {hex_pattern} }}'


def pehstr_to_yara_rule(threat_name: str, sig: PEHSTRSignature,
                        rule_index: int = 0) -> str:
    """
    Convert a PEHSTR signature to a YARA rule.
    """
    rule_name = sanitize_rule_name(threat_name)
    if rule_index > 0:
        rule_name += f'_{rule_index}'

    lines = []
    lines.append(f'rule {rule_name}')
    lines.append('{')

    # Meta
    lines.append('    meta:')
    lines.append(f'        description = "Defender: {threat_name}"')
    lines.append(f'        threshold = {sig.threshold}')
    lines.append(f'        sig_type = "{sig.type_name}"')
    lines.append('')

    # Strings
    lines.append('    strings:')
    string_defs = []
    for i, sr in enumerate(sig.subrules):
        name, definition = subrule_to_yara_string(sr, i)
        string_defs.append((name, definition, sr.weight))
        lines.append(f'        {name} = {definition}  // weight={sr.weight}')
    lines.append('')

    # Condition
    lines.append('    condition:')

    if sig.threshold == sig.total_weight():
        # All strings required
        all_strings = ' and '.join(name for name, _, _ in string_defs)
        lines.append(f'        {all_strings}')
    else:
        # Weighted condition
        weight_terms = [f'({w} * #{n})' for n, _, w in string_defs]
        lines.append(f'        ({" + ".join(weight_terms)}) >= {sig.threshold}')

    lines.append('}')
    return '\n'.join(lines)


def threat_to_yara_rules(threat: ThreatDefinition) -> List[str]:
    """
    Convert all PEHSTR signatures in a threat to YARA rules.
    """
    rules = []
    pehstr_idx = 0

    for entry in threat.signatures:
        if entry.sig_type in (PEHSTR, PEHSTR_EXT, PEHSTR_EXT2):
            try:
                sig = parse_pehstr_signature(entry.sig_type, entry.data)
                if sig.subrules:  # Only if has actual patterns
                    rule = pehstr_to_yara_rule(threat.threat_name, sig, pehstr_idx)
                    rules.append(rule)
                    pehstr_idx += 1
            except Exception:
                pass

    return rules


@dataclass
class YaraWriterStats:
    """Statistics from YARA rule generation."""
    threats_processed: int = 0
    rules_generated: int = 0
    files_written: int = 0
    categories: Dict[str, int] = None

    def __post_init__(self):
        if self.categories is None:
            self.categories = {}


class YaraWriter:
    """
    Writes YARA rules organized by threat category/family.
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.stats = YaraWriterStats()
        self._category_rules: Dict[str, List[str]] = defaultdict(list)

    def _categorize(self, threat_name: str) -> Tuple[str, str]:
        """Categorize threat into (category, family)."""
        # Extract category from threat name
        name = threat_name.strip('!')

        # Common patterns
        if ':' in name:
            parts = name.split(':')
            if len(parts) >= 2:
                category = parts[0]
                remainder = ':'.join(parts[1:])
                if '/' in remainder:
                    family = remainder.split('/')[1].split('.')[0]
                else:
                    family = remainder.split('.')[0]
                return category, family

        # Simple pattern
        family = name.split('.')[0]
        return 'Unknown', family

    def process_threat(self, threat: ThreatDefinition) -> int:
        """
        Process a threat and generate YARA rules.

        Returns number of rules generated.
        """
        if not threat.threat_name:
            return 0

        rules = threat_to_yara_rules(threat)
        if not rules:
            return 0

        category, family = self._categorize(threat.threat_name)
        self._category_rules[category].extend(rules)

        self.stats.threats_processed += 1
        self.stats.rules_generated += len(rules)
        self.stats.categories[category] = self.stats.categories.get(category, 0) + len(rules)

        return len(rules)

    def write_all(self) -> None:
        """Write all collected rules to files."""
        for category, rules in self._category_rules.items():
            if not rules:
                continue

            cat_dir = self.output_dir / sanitize_rule_name(category)
            cat_dir.mkdir(parents=True, exist_ok=True)

            # Write combined file for category
            output_file = cat_dir / f'{sanitize_rule_name(category)}.yar'
            with open(output_file, 'w') as f:
                f.write(f'// YARA rules for {category}\n')
                f.write(f'// Generated from Microsoft Defender signatures\n')
                f.write(f'// Total rules: {len(rules)}\n\n')
                f.write('\n\n'.join(rules))

            self.stats.files_written += 1

    def write_index(self) -> str:
        """Write index file."""
        index_path = self.output_dir / 'INDEX.md'

        lines = []
        lines.append('# Generated YARA Rules')
        lines.append('')
        lines.append(f'- **Threats processed**: {self.stats.threats_processed}')
        lines.append(f'- **Rules generated**: {self.stats.rules_generated}')
        lines.append(f'- **Files written**: {self.stats.files_written}')
        lines.append('')
        lines.append('## Categories')
        lines.append('')
        for cat, count in sorted(self.stats.categories.items(), key=lambda x: -x[1]):
            lines.append(f'- **{cat}**: {count} rules')

        with open(index_path, 'w') as f:
            f.write('\n'.join(lines))

        return str(index_path)


def write_yara_rules(vdm_data: bytes, output_dir: str,
                     progress_callback=None) -> YaraWriterStats:
    """
    Extract threats from VDM data and generate YARA rules.

    Args:
        vdm_data: Decompressed VDM signature data
        output_dir: Output directory for YARA files
        progress_callback: Optional callback(current, total)

    Returns:
        Statistics about generated rules
    """
    writer = YaraWriter(output_dir)
    threats = list(extract_threats(vdm_data))

    for i, threat in enumerate(threats):
        writer.process_threat(threat)
        if progress_callback and i % 1000 == 0:
            progress_callback(i, len(threats))

    writer.write_all()
    writer.write_index()

    return writer.stats
