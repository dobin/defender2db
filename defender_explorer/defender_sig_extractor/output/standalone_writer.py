"""
Standalone Signature Output Writer

Writes semantically grouped standalone signatures to organized output files.
"""

import json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from collections import defaultdict

from ..signature_handlers.standalone_handler import (
    StandaloneSignatureGrouper,
    SemanticGroup,
    StandaloneSignature,
    extract_standalone_signatures,
)


@dataclass
class StandaloneWriterStats:
    """Statistics from standalone signature writing."""
    total_signatures: int = 0
    total_groups: int = 0
    categories: int = 0
    files_written: int = 0
    by_category: Dict[str, int] = None
    by_type: Dict[str, int] = None

    def __post_init__(self):
        if self.by_category is None:
            self.by_category = {}
        if self.by_type is None:
            self.by_type = {}


def format_signature_detail(sig: StandaloneSignature, include_hex: bool = True) -> str:
    """Format a single signature for output."""
    lines = []

    lines.append(f"// Type: {sig.type_name} (0x{sig.sig_type:02X})")
    lines.append(f"// Size: {len(sig.data)} bytes")
    lines.append(f"// Category: {sig.full_category}")

    if sig.matched_pattern:
        lines.append(f"// Matched: {sig.matched_pattern}")

    if sig.strings:
        lines.append("// Strings:")
        for s in sig.strings[:5]:
            safe_s = s.replace('"', '\\"').replace('\n', '\\n')
            lines.append(f'//   "{safe_s}"')

    if include_hex and len(sig.data) <= 256:
        lines.append("// Hex:")
        hex_str = sig.data.hex()
        for i in range(0, len(hex_str), 64):
            lines.append(f"//   {hex_str[i:i+64]}")

    return '\n'.join(lines)


def write_group_file(group: SemanticGroup, output_path: Path, max_samples: int = 100) -> None:
    """Write a single group to a file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write(f"/*\n")
        f.write(f" * Standalone Signature Group: {group.category}/{group.subcategory}\n")
        f.write(f" * Signature Type: {group.type_name} (0x{group.sig_type:02X})\n")
        f.write(f" * Total Signatures: {group.count}\n")
        f.write(f" */\n\n")

        # Write pattern statistics
        if group.matched_patterns:
            f.write("/* Pattern Statistics:\n")
            sorted_patterns = sorted(group.matched_patterns.items(), key=lambda x: -x[1])
            for pattern, count in sorted_patterns[:20]:
                safe_pattern = pattern.replace('*/', '* /')
                f.write(f" *   {safe_pattern}: {count}\n")
            if len(sorted_patterns) > 20:
                f.write(f" *   ... and {len(sorted_patterns) - 20} more patterns\n")
            f.write(" */\n\n")

        # Write sample signatures
        f.write(f"/* Sample Signatures ({min(max_samples, group.count)} of {group.count}) */\n\n")

        for i, sig in enumerate(group.signatures[:max_samples]):
            f.write(f"/* --- Signature {i+1} --- */\n")
            f.write(format_signature_detail(sig))
            f.write("\n\n")

        if group.count > max_samples:
            f.write(f"\n/* ... {group.count - max_samples} more signatures not shown */\n")


def write_category_index(
    category: str,
    groups: List[SemanticGroup],
    output_path: Path
) -> None:
    """Write an index file for a category."""
    with open(output_path, 'w') as f:
        f.write(f"# {category} - Standalone Signatures\n\n")

        total = sum(g.count for g in groups)
        f.write(f"**Total Signatures:** {total:,}\n")
        f.write(f"**Groups:** {len(groups)}\n\n")

        f.write("## Groups by Subcategory\n\n")
        f.write("| Subcategory | Type | Count | Top Pattern |\n")
        f.write("|-------------|------|-------|-------------|\n")

        for group in groups:
            top_pattern = ""
            if group.matched_patterns:
                top_pattern = max(group.matched_patterns.items(), key=lambda x: x[1])[0]
                if len(top_pattern) > 30:
                    top_pattern = top_pattern[:27] + "..."

            f.write(f"| {group.subcategory or 'General'} | {group.type_name} | {group.count:,} | {top_pattern} |\n")


def write_master_index(
    grouper: StandaloneSignatureGrouper,
    output_path: Path
) -> None:
    """Write the master index file."""
    summary = grouper.summary()
    by_category = grouper.get_groups_by_category()

    with open(output_path, 'w') as f:
        f.write("# Standalone Signatures - Semantic Grouping\n\n")

        f.write("Signatures extracted from VDM that exist **outside** of named threat blocks.\n")
        f.write("These are generic detection patterns not tied to specific malware names.\n\n")

        f.write("## Summary\n\n")
        f.write(f"- **Total Signatures:** {summary['total_signatures']:,}\n")
        f.write(f"- **Semantic Groups:** {summary['total_groups']}\n")
        f.write(f"- **Categories:** {summary['categories']}\n\n")

        f.write("## Categories\n\n")
        f.write("| Category | Signatures | Groups | Description |\n")
        f.write("|----------|------------|--------|-------------|\n")

        category_descriptions = {
            'Packer': 'Packer/protector detection patterns (UPX, VMProtect, etc.)',
            'PE': 'Generic PE structure patterns',
            'Persistence': 'Registry/file persistence mechanisms',
            'Registry': 'Registry key detection patterns',
            'FilePath': 'Suspicious file path patterns',
            'Behavior': 'Behavioral detection patterns',
            'Bundleware': 'Bundled software/adware patterns',
            'Installer': 'Installer script patterns',
            'COM': 'COM object registration patterns',
            'Security': 'Security settings modification',
            'Network': 'Network configuration patterns',
            'Browser': 'Browser modification patterns',
            'System': 'System configuration patterns',
            'URL': 'Malicious URL patterns',
            'Mutex': 'Named mutex patterns',
            'Pipe': 'Named pipe patterns',
            'Generic': 'Uncategorized patterns',
        }

        for category in sorted(by_category.keys()):
            groups = by_category[category]
            total = sum(g.count for g in groups)
            desc = category_descriptions.get(category, '')
            f.write(f"| [{category}](./{category}/INDEX.md) | {total:,} | {len(groups)} | {desc} |\n")

        f.write("\n## Signature Types\n\n")
        f.write("| Type | Count |\n")
        f.write("|------|-------|\n")

        for sig_type, count in sorted(summary['by_type'].items(), key=lambda x: -x[1]):
            try:
                from ..signature_types import SigType
                type_name = SigType(sig_type).name
            except:
                type_name = f"UNKNOWN_0x{sig_type:02X}"
            f.write(f"| {type_name} | {count:,} |\n")


def write_json_summary(
    grouper: StandaloneSignatureGrouper,
    output_path: Path
) -> None:
    """Write a JSON summary of all groups."""
    by_category = grouper.get_groups_by_category()

    data = {
        "summary": grouper.summary(),
        "categories": {}
    }

    for category, groups in by_category.items():
        data["categories"][category] = {
            "total": sum(g.count for g in groups),
            "groups": [
                {
                    "subcategory": g.subcategory,
                    "type": g.type_name,
                    "count": g.count,
                    "top_patterns": dict(sorted(
                        g.matched_patterns.items(),
                        key=lambda x: -x[1]
                    )[:10])
                }
                for g in groups
            ]
        }

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)


def write_standalone_signatures(
    vdm_data: bytes,
    output_dir: str,
    progress_callback=None,
    max_samples_per_group: int = 100
) -> StandaloneWriterStats:
    """
    Extract, group, and write standalone signatures.

    Args:
        vdm_data: Raw decompressed VDM data
        output_dir: Output directory path
        progress_callback: Optional callback(current, total)
        max_samples_per_group: Max signatures to write per group file

    Returns:
        Statistics about the extraction
    """
    output_path = Path(output_dir) / 'standalone'
    output_path.mkdir(parents=True, exist_ok=True)

    # Extract and group
    if progress_callback:
        progress_callback(0, 100)

    grouper = extract_standalone_signatures(vdm_data, progress_callback)

    # Get organized groups
    by_category = grouper.get_groups_by_category()
    summary = grouper.summary()

    files_written = 0

    # Write category directories and files
    for category, groups in by_category.items():
        category_path = output_path / category
        category_path.mkdir(parents=True, exist_ok=True)

        # Write each group file
        for group in groups:
            safe_subcategory = (group.subcategory or 'General').replace('/', '_').replace('\\', '_')
            filename = f"{safe_subcategory}_{group.type_name}.sig"
            write_group_file(group, category_path / filename, max_samples_per_group)
            files_written += 1

        # Write category index
        write_category_index(category, groups, category_path / 'INDEX.md')
        files_written += 1

    # Write master index
    write_master_index(grouper, output_path / 'INDEX.md')
    files_written += 1

    # Write JSON summary
    write_json_summary(grouper, output_path / 'summary.json')
    files_written += 1

    # Build stats
    stats = StandaloneWriterStats(
        total_signatures=summary['total_signatures'],
        total_groups=summary['total_groups'],
        categories=summary['categories'],
        files_written=files_written,
        by_category=summary['by_category'],
        by_type={
            str(k): v for k, v in summary['by_type'].items()
        }
    )

    return stats
