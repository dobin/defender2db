#!/usr/bin/env python3
"""
Extract ALL signatures from Microsoft Defender VDM files.

This script:
1. Downloads mpam-fe.exe from Microsoft (if needed)
2. Extracts VDM files from the CAB archive
3. Decompresses VDM files
4. Parses ALL signature types (not just Lua)
5. Outputs organized results

Usage:
    python -m defender_sig_extractor.extract_all --download --output ./signatures/
    python -m defender_sig_extractor.extract_all --vdm-dir ./vdm/ --output ./signatures/
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

from .vdm_parser import VDMParser
from .signature_extractor import (
    SignatureExtractor,
    ThreatDefinition,
    TLVEntry,
    parse_tlv_stream,
    THREAT_BEGIN, THREAT_END, PEHSTR, PEHSTR_EXT, PEHSTR_EXT2, LUA_STANDALONE
)


def extract_vdm_signatures(vdm_path: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Extract all signatures from a VDM file.

    Returns a dict with:
    - signature_counts: count of each signature type
    - threats: list of threat definitions
    - total_signatures: total number of signatures
    """
    if verbose:
        print(f"  Parsing {os.path.basename(vdm_path)}...")

    try:
        parser = VDMParser(vdm_path)
        decompressed = parser.decompress()
    except Exception as e:
        if verbose:
            print(f"    Error decompressing: {e}")
        return {"error": str(e), "signature_counts": {}, "threats": [], "total_signatures": 0}

    if verbose:
        print(f"    Decompressed size: {len(decompressed):,} bytes")

    extractor = SignatureExtractor(decompressed)
    summary = extractor.summary()

    if verbose:
        print(f"    Total signatures: {summary['total_signatures']:,}")
        print(f"    Signature types: {summary['signature_types']}")
        if summary['threat_count'] > 0:
            print(f"    Threats: {summary['threat_count']:,}")
        if summary['lua_count'] > 0:
            print(f"    Lua scripts: {summary['lua_count']:,}")
        if summary['pehstr_count'] > 0:
            print(f"    PEHSTR signatures: {summary['pehstr_count']:,}")

    # Extract threats if present
    threats = []
    if summary['has_threats']:
        for threat in extractor.extract_threats():
            threats.append(threat.to_dict())

    return {
        "file": os.path.basename(vdm_path),
        "decompressed_size": len(decompressed),
        "signature_counts": summary['type_counts'],
        "total_signatures": summary['total_signatures'],
        "threat_count": len(threats),
        "threats": threats[:100] if len(threats) > 100 else threats,  # Limit for JSON
    }


def extract_lua_from_vdm(vdm_path: str, output_dir: str, verbose: bool = False) -> int:
    """Extract all Lua scripts from a VDM file."""
    try:
        parser = VDMParser(vdm_path)
        decompressed = parser.decompress()
    except Exception as e:
        if verbose:
            print(f"    Error: {e}")
        return 0

    extractor = SignatureExtractor(decompressed)
    lua_scripts = extractor.extract_lua_scripts()

    if not lua_scripts:
        return 0

    # Create output directory
    vdm_name = Path(vdm_path).stem
    lua_dir = Path(output_dir) / "lua" / vdm_name
    lua_dir.mkdir(parents=True, exist_ok=True)

    # Import Lua decompiler backend
    try:
        from .lua_decompiler.backend import decompile as backend_decompile
        has_decompiler = True
    except ImportError:
        has_decompiler = False

    extracted = 0
    for i, lua_data in enumerate(lua_scripts):
        try:
            # Save raw bytecode
            bytecode_path = lua_dir / f"{i}.luac"
            bytecode_path.write_bytes(lua_data)

            if has_decompiler:
                # Try to decompile (backend handles MpLua conversion)
                try:
                    if lua_data.startswith(b'\x1bLua'):
                        source = backend_decompile(lua_data)
                        source_path = lua_dir / f"{i}.lua"
                        source_path.write_text(source)
                except Exception:
                    pass

            extracted += 1

        except Exception as e:
            if verbose:
                print(f"    Error extracting Lua {i}: {e}")

    return extracted


def extract_pehstr_from_vdm(vdm_path: str, output_dir: str, verbose: bool = False) -> int:
    """Extract all PEHSTR signatures from a VDM file."""
    try:
        parser = VDMParser(vdm_path)
        decompressed = parser.decompress()
    except Exception as e:
        if verbose:
            print(f"    Error: {e}")
        return 0

    extractor = SignatureExtractor(decompressed)
    pehstr_sigs = extractor.extract_pehstr_signatures()

    if not pehstr_sigs:
        return 0

    # Create output directory
    vdm_name = Path(vdm_path).stem
    pehstr_dir = Path(output_dir) / "pehstr" / vdm_name
    pehstr_dir.mkdir(parents=True, exist_ok=True)

    # Export signatures
    sigs_data = []
    for i, sig in enumerate(pehstr_sigs):
        sig_dict = sig.to_dict()
        sig_dict["index"] = i
        sigs_data.append(sig_dict)

    # Save as JSON
    json_path = pehstr_dir / "signatures.json"
    with open(json_path, 'w') as f:
        json.dump(sigs_data, f, indent=2)

    return len(pehstr_sigs)


def extract_threats_from_vdm(vdm_path: str, output_dir: str, verbose: bool = False) -> int:
    """Extract all threat definitions from a VDM file."""
    try:
        parser = VDMParser(vdm_path)
        decompressed = parser.decompress()
    except Exception as e:
        if verbose:
            print(f"    Error: {e}")
        return 0

    extractor = SignatureExtractor(decompressed)
    threats = extractor.extract_threats()

    if not threats:
        return 0

    # Create output directory
    vdm_name = Path(vdm_path).stem
    threats_dir = Path(output_dir) / "threats" / vdm_name
    threats_dir.mkdir(parents=True, exist_ok=True)

    # Export threats
    threats_data = [t.to_dict() for t in threats]

    # Save summary
    summary_path = threats_dir / "threats_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(threats_data, f, indent=2)

    # Save individual threat files (top 1000)
    for i, threat in enumerate(threats[:1000]):
        threat_name = threat.threat_name.replace('/', '_').replace('\\', '_').replace(':', '_')
        if not threat_name:
            threat_name = f"unknown_{i}"

        threat_path = threats_dir / f"{i:05d}_{threat_name}.json"
        with open(threat_path, 'w') as f:
            json.dump(threat.to_dict(), f, indent=2)

    return len(threats)


def main():
    parser = argparse.ArgumentParser(
        description="Extract ALL signatures from Microsoft Defender VDM files"
    )
    parser.add_argument(
        "--download", action="store_true",
        help="Download mpam-fe.exe from Microsoft"
    )
    parser.add_argument(
        "--mpam", type=str,
        help="Path to existing mpam-fe.exe"
    )
    parser.add_argument(
        "--vdm-dir", type=str,
        help="Path to directory containing VDM files"
    )
    parser.add_argument(
        "--output", "-o", type=str, default="./signatures_output",
        help="Output directory"
    )
    parser.add_argument(
        "--lua-only", action="store_true",
        help="Only extract Lua scripts"
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Only generate summary, don't extract files"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    vdm_files = []

    # Find VDM files
    if args.vdm_dir:
        vdm_dir = Path(args.vdm_dir)
        vdm_files = list(vdm_dir.glob("*.vdm"))
    elif args.mpam or args.download:
        # Need to extract from mpam-fe.exe
        if args.download:
            print("Downloading mpam-fe.exe from Microsoft...")
            from .downloader import download_mpam
            mpam_path = download_mpam(str(output_dir / "mpam-fe.exe"))
        else:
            mpam_path = args.mpam

        print(f"Extracting VDM files from {mpam_path}...")
        from .pe_extractor import extract_vdm_files
        vdm_dir = output_dir / "vdm"
        vdm_dir.mkdir(exist_ok=True)
        extracted = extract_vdm_files(mpam_path, str(vdm_dir))
        vdm_files = [Path(f.path) for f in extracted]
        print(f"Extracted {len(vdm_files)} VDM files")
    else:
        # Look for VDM files in current directory
        vdm_files = list(Path(".").glob("*.vdm"))

    if not vdm_files:
        print("No VDM files found. Use --download, --mpam, or --vdm-dir")
        sys.exit(1)

    print(f"\nProcessing {len(vdm_files)} VDM files...")

    # Process each VDM file
    all_results = {}
    total_lua = 0
    total_pehstr = 0
    total_threats = 0
    total_sigs = 0

    for vdm_path in vdm_files:
        vdm_name = vdm_path.name
        print(f"\n{vdm_name}:")

        # Get summary
        result = extract_vdm_signatures(str(vdm_path), verbose=args.verbose)
        all_results[vdm_name] = result
        total_sigs += result.get("total_signatures", 0)

        if args.summary_only:
            continue

        # Extract signatures
        if args.lua_only:
            lua_count = extract_lua_from_vdm(str(vdm_path), str(output_dir), args.verbose)
            total_lua += lua_count
            if lua_count > 0:
                print(f"  Extracted {lua_count} Lua scripts")
        else:
            # Extract all types
            lua_count = extract_lua_from_vdm(str(vdm_path), str(output_dir), args.verbose)
            total_lua += lua_count
            if lua_count > 0:
                print(f"  Extracted {lua_count} Lua scripts")

            pehstr_count = extract_pehstr_from_vdm(str(vdm_path), str(output_dir), args.verbose)
            total_pehstr += pehstr_count
            if pehstr_count > 0:
                print(f"  Extracted {pehstr_count} PEHSTR signatures")

            threat_count = extract_threats_from_vdm(str(vdm_path), str(output_dir), args.verbose)
            total_threats += threat_count
            if threat_count > 0:
                print(f"  Extracted {threat_count} threat definitions")

    # Save overall summary
    summary = {
        "vdm_files": len(vdm_files),
        "total_signatures": total_sigs,
        "total_lua_scripts": total_lua,
        "total_pehstr_signatures": total_pehstr,
        "total_threats": total_threats,
        "per_file_results": {k: {
            "total_signatures": v.get("total_signatures", 0),
            "threat_count": v.get("threat_count", 0),
            "signature_types": len(v.get("signature_counts", {})),
        } for k, v in all_results.items()},
    }

    summary_path = output_dir / "extraction_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*50}")
    print("EXTRACTION COMPLETE")
    print(f"{'='*50}")
    print(f"VDM files processed: {len(vdm_files)}")
    print(f"Total signatures: {total_sigs:,}")
    if not args.summary_only:
        print(f"Lua scripts extracted: {total_lua:,}")
        print(f"PEHSTR signatures: {total_pehstr:,}")
        print(f"Threat definitions: {total_threats:,}")
    print(f"\nOutput directory: {output_dir}")
    print(f"Summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
