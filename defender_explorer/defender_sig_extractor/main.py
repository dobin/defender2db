"""
Microsoft Defender Signature Extractor & Lua Decompiler

CLI entry point for the pure Python signature extraction and decompilation pipeline.

Usage:
    # Full pipeline (download + extract + decompile):
    python -m defender_sig_extractor --download --output ./signatures/

    # From existing VDM files:
    python -m defender_sig_extractor --vdm ./vdm_files/ --output ./signatures/

    # From existing mpam-fe.exe:
    python -m defender_sig_extractor --mpam ./mpam-fe.exe --output ./signatures/

    # Options:
    #   --lua-only      Only extract Lua signatures
    #   --no-decompile  Skip decompilation, output raw bytecode
    #   --format csv|json|files
"""

import argparse
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional
import shutil

from . import __version__
from .downloader import download_mpam, print_progress, verify_download
from .pe_extractor import extract_vdm_files, get_vdm_files, ExtractionError
from .vdm_parser import VDMParser, Signature
from .output.csv_writer import write_signatures_to_csv, write_lua_signatures_to_csv
from .output.lua_writer import write_lua_signatures, create_index
from .output.threat_writer import write_threats_organized
from .output.yara_writer import write_yara_rules
from .output.asr_writer import write_asr_rules
from .output.ioc_writer import write_iocs
from .output.lolbin_writer import write_lolbin_detections
from .output.standalone_writer import write_standalone_signatures
from .lua_decompiler.backend import set_backend, check_backend_available


def print_banner():
    """Print program banner."""
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║  Microsoft Defender Signature Extractor & Lua Decompiler  ║
║                     Version {__version__}                        ║
╚═══════════════════════════════════════════════════════════╝
""")


def download_signatures(output_dir: str, arch: str = 'x64') -> str:
    """Download Microsoft Defender signature package."""
    print(f"[*] Downloading signature package (arch: {arch})...")

    output_path = Path(output_dir) / 'mpam-fe.exe'
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        path = download_mpam(str(output_path), arch=arch, progress_callback=print_progress)
        print()  # New line after progress

        # Verify download
        result = verify_download(path)
        if result['valid']:
            print(f"[+] Downloaded: {path}")
            print(f"    Size: {result['size']:,} bytes")
            print(f"    SHA256: {result['sha256']}")
            return path
        else:
            print(f"[-] Download verification failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)

    except Exception as e:
        print(f"[-] Download failed: {e}")
        sys.exit(1)


def extract_vdm(mpam_path: str, output_dir: str) -> dict:
    """Extract VDM files from mpam-fe.exe."""
    print(f"[*] Extracting VDM files from {mpam_path}...")

    try:
        extracted = extract_vdm_files(mpam_path, output_dir)
        print(f"[+] Extracted {len(extracted)} files:")
        for f in extracted:
            print(f"    - {f.name} ({f.size:,} bytes)")

        return get_vdm_files(output_dir)

    except ExtractionError as e:
        print(f"[-] Extraction failed: {e}")
        sys.exit(1)


def parse_vdm_file(vdm_path: str, lua_only: bool = False) -> List[Signature]:
    """Parse a single VDM file and return signatures."""
    parser = VDMParser(vdm_path)

    if lua_only:
        return list(parser.extract_lua_signatures())
    else:
        return list(parser.parse_tlv_stream())


def process_vdm_files(vdm_files: dict, lua_only: bool = False) -> tuple:
    """Process VDM files and extract signatures.

    Returns:
        Tuple of (signatures list, combined raw VDM data)
    """
    all_signatures = []
    all_vdm_data = bytearray()

    # Process base + delta pairs
    for base_key, delta_key in [('av_base', 'av_delta'), ('as_base', 'as_delta')]:
        if base_key in vdm_files:
            base_path = vdm_files[base_key]
            print(f"[*] Processing {Path(base_path).name}...")

            parser = VDMParser(base_path)
            sigs = list(parser.parse_tlv_stream()) if not lua_only else list(parser.extract_lua_signatures())
            print(f"    Found {len(sigs)} signatures")
            all_signatures.extend(sigs)

            # Get decompressed data for threat extraction
            try:
                all_vdm_data.extend(parser.get_decompressed_data())
            except:
                pass

            # Apply delta if available
            if delta_key in vdm_files:
                delta_path = vdm_files[delta_key]
                print(f"[*] Processing {Path(delta_path).name}...")

                parser = VDMParser(delta_path)
                sigs = list(parser.parse_tlv_stream()) if not lua_only else list(parser.extract_lua_signatures())
                print(f"    Found {len(sigs)} signatures")
                all_signatures.extend(sigs)

                try:
                    all_vdm_data.extend(parser.get_decompressed_data())
                except:
                    pass

    return all_signatures, bytes(all_vdm_data)


def output_signatures(signatures: List[Signature], output_dir: str,
                      format_type: str = 'threats', lua_only: bool = False,
                      decompile: bool = True, vdm_data: bytes = None) -> None:
    """Output signatures in specified format."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if format_type == 'csv':
        csv_path = output_path / 'signatures.csv'
        print(f"[*] Writing CSV to {csv_path}...")

        if lua_only:
            count = write_lua_signatures_to_csv(iter(signatures), str(csv_path))
        else:
            count = write_signatures_to_csv(iter(signatures), str(csv_path))

        print(f"[+] Wrote {count} signatures to CSV")

    elif format_type == 'files':
        lua_dir = output_path / 'lua'
        print(f"[*] Writing Lua files to {lua_dir}...")

        results = write_lua_signatures(
            iter(signatures),
            str(lua_dir),
            write_bytecode=True,
            write_source=decompile
        )

        decompiled = sum(1 for r in results if r.decompiled)
        failed = sum(1 for r in results if r.error)
        print(f"[+] Wrote {len(results)} Lua signatures")
        print(f"    Decompiled: {decompiled}")
        print(f"    Failed: {failed}")

        # Create index
        index_path = lua_dir / 'INDEX.md'
        create_index(results, str(index_path))
        print(f"[+] Created index at {index_path}")

    elif format_type == 'threats':
        print(f"[*] Writing organized threats to {output_path}...")

        if not vdm_data:
            print("[-] Threat extraction requires VDM data")
            sys.exit(1)

        def progress_cb(current, total):
            print(f"\r    Processing threats: {current}/{total}", end='', flush=True)

        stats = write_threats_organized(vdm_data, str(output_path), progress_cb)
        print()  # New line after progress
        print(f"[+] Wrote {stats['threats']} threats")
        print(f"    Signatures: {stats['signatures']}")
        print(f"    Categories: {stats['categories']}")
        print(f"    Families: {stats['families']}")

    elif format_type == 'yara':
        yara_dir = output_path / 'yara'
        print(f"[*] Generating YARA rules to {yara_dir}...")

        if vdm_data:
            def progress_cb(current, total):
                print(f"\r    Processing: {current}/{total}", end='', flush=True)

            stats = write_yara_rules(vdm_data, str(yara_dir), progress_cb)
            print()
            print(f"[+] Generated {stats.rules_generated} YARA rules")
            print(f"    Threats processed: {stats.threats_processed}")
            print(f"    Files written: {stats.files_written}")
        else:
            print("[-] YARA generation requires VDM data")
            sys.exit(1)

    elif format_type == 'asr':
        print(f"[*] Extracting ASR rules to {output_path}...")

        if vdm_data:
            def progress_cb(current, total):
                print(f"\r    Processing: {current}/{total}", end='', flush=True)

            stats = write_asr_rules(vdm_data, str(output_path), progress_cb)
            print()
            print(f"[+] Extracted ASR-related scripts")
            print(f"    Total Lua scripts: {stats.total_lua_scripts}")
            print(f"    Scripts with ASR: {stats.scripts_with_asr}")
            print(f"    ASR rules found: {len(stats.asr_rules_found)}")
            print(f"    Decompiled: {stats.decompiled}")
            if stats.unknown_guids:
                print(f"    Unknown GUIDs: {len(stats.unknown_guids)}")
        else:
            print("[-] ASR extraction requires VDM data")
            sys.exit(1)

    elif format_type == 'standalone':
        # Extract only standalone signatures
        print(f"[*] Extracting standalone signatures to {output_path}...")

        if not vdm_data:
            print("[-] Standalone extraction requires VDM data")
            sys.exit(1)

        def progress_cb(current, total):
            print(f"\r    Processing: {current}/{total}", end='', flush=True)

        standalone_stats = write_standalone_signatures(vdm_data, str(output_path), progress_cb)
        print()
        print(f"[+] Extracted {standalone_stats.total_signatures:,} standalone signatures")
        print(f"    Categories: {standalone_stats.categories}")
        print(f"    Groups: {standalone_stats.total_groups}")
        print(f"    Files written: {standalone_stats.files_written}")

        if standalone_stats.by_category:
            print("\n    By category:")
            for cat, count in sorted(standalone_stats.by_category.items(), key=lambda x: -x[1]):
                print(f"      {cat}: {count:,}")

    elif format_type == 'all':
        # Generate all output formats
        print(f"[*] Generating all formats to {output_path}...")

        if not vdm_data:
            print("[-] Full extraction requires VDM data")
            sys.exit(1)

        def progress_cb(current, total):
            print(f"\r    Processing: {current}/{total}", end='', flush=True)

        # 1. Threats (C-like organized)
        print("\n[*] Writing organized threats...")
        stats = write_threats_organized(vdm_data, str(output_path / 'threats'), progress_cb)
        print()
        print(f"    Threats: {stats['threats']}, Categories: {stats['categories']}")

        # 2. YARA rules
        print("\n[*] Generating YARA rules...")
        yara_stats = write_yara_rules(vdm_data, str(output_path / 'yara'), progress_cb)
        print()
        print(f"    Rules: {yara_stats.rules_generated}")

        # 3. ASR rules
        print("\n[*] Extracting ASR rules...")
        asr_stats = write_asr_rules(vdm_data, str(output_path), progress_cb)
        print()
        print(f"    ASR scripts: {asr_stats.scripts_with_asr}, Rules: {len(asr_stats.asr_rules_found)}")

        # 4. IOCs (hashes, URLs, etc.)
        print("\n[*] Extracting IOCs...")
        ioc_counts = write_iocs(vdm_data, str(output_path), progress_cb)
        print()
        total_iocs = sum(ioc_counts.values())
        print(f"    IOCs: {total_iocs} ({len(ioc_counts)} types)")

        # 5. LOLBin detections
        print("\n[*] Extracting LOLBin detections...")
        lolbin_stats = write_lolbin_detections(vdm_data, str(output_path), progress_cb)
        print()
        print(f"    LOLBins: {len(lolbin_stats.lolbins_found)}, Detections: {lolbin_stats.lolbin_detections}")

        # 6. Lua files
        print("\n[*] Writing Lua files...")
        lua_dir = output_path / 'lua'
        results = write_lua_signatures(
            iter(signatures),
            str(lua_dir),
            write_bytecode=True,
            write_source=decompile
        )
        decompiled_count = sum(1 for r in results if r.decompiled)
        print(f"    Lua scripts: {len(results)}, Decompiled: {decompiled_count}")

        # 7. Standalone signatures (not in threat blocks)
        print("\n[*] Extracting standalone signatures...")
        standalone_stats = write_standalone_signatures(vdm_data, str(output_path), progress_cb)
        print()
        print(f"    Standalone: {standalone_stats.total_signatures:,}, Categories: {standalone_stats.categories}")

        # Create master index
        index_path = output_path / 'INDEX.md'
        with open(index_path, 'w') as f:
            f.write("# Microsoft Defender Signature Extraction\n\n")
            f.write("## Output Directories\n\n")
            f.write("- **threats/** - Signatures organized by threat category/family (C-like format)\n")
            f.write("- **yara/** - YARA rules generated from PEHSTR signatures\n")
            f.write("- **asr/** - Lua scripts organized by ASR rule GUID\n")
            f.write("- **iocs/** - Extracted IOCs (hashes, URLs, domains, etc.)\n")
            f.write("- **mitre/** - Scripts mapped to MITRE ATT&CK techniques\n")
            f.write("- **lolbin/** - LOLBin detection rules\n")
            f.write("- **lua/** - All decompiled Lua scripts\n")
            f.write("- **standalone/** - Standalone signatures (not mapped to threats)\n")
            f.write("\n## Statistics\n\n")
            f.write(f"- Threats: {stats['threats']}\n")
            f.write(f"- YARA rules: {yara_stats.rules_generated}\n")
            f.write(f"- ASR scripts: {asr_stats.scripts_with_asr}\n")
            f.write(f"- IOCs: {total_iocs}\n")
            f.write(f"- MITRE techniques: {len(asr_stats.asr_rules_found)}\n")
            f.write(f"- LOLBin detections: {lolbin_stats.lolbin_detections}\n")
            f.write(f"- Lua scripts: {len(results)}\n")
            f.write(f"- Standalone signatures: {standalone_stats.total_signatures}\n")

        print(f"\n[+] Created master index at {index_path}")

    else:
        print(f"[-] Unknown format: {format_type}")
        sys.exit(1)


def print_statistics(signatures: List[Signature]) -> None:
    """Print statistics about extracted signatures."""
    print("\n[*] Signature Statistics:")
    print(f"    Total signatures: {len(signatures)}")

    # Count by type
    type_counts = {}
    lua_count = 0
    total_size = 0

    for sig in signatures:
        type_name = sig.type_name
        type_counts[type_name] = type_counts.get(type_name, 0) + 1
        total_size += sig.size
        if sig.is_lua:
            lua_count += 1

    print(f"    Lua signatures: {lua_count}")
    print(f"    Total payload size: {total_size:,} bytes")

    # Top 10 types
    print("\n    Top signature types:")
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    for type_name, count in sorted_types[:10]:
        print(f"      {type_name}: {count}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Microsoft Defender Signature Extractor & Lua Decompiler',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download, extract, and decompile:
  python -m defender_sig_extractor --download --output ./signatures/

  # Process existing mpam-fe.exe:
  python -m defender_sig_extractor --mpam ./mpam-fe.exe --output ./signatures/

  # Process VDM files directly:
  python -m defender_sig_extractor --vdm ./vdm/ --output ./signatures/

  # Extract only Lua signatures to CSV:
  python -m defender_sig_extractor --download --lua-only --format csv --output ./lua.csv
        """
    )

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--download', action='store_true',
                             help='Download signature package from Microsoft')
    input_group.add_argument('--mpam', metavar='PATH',
                             help='Path to existing mpam-fe.exe')
    input_group.add_argument('--vdm', metavar='DIR',
                             help='Path to directory containing VDM files')

    # Output options
    parser.add_argument('--output', '-o', required=True,
                        help='Output directory or file path')
    parser.add_argument('--format', '-f', choices=['csv', 'files', 'threats', 'yara', 'asr', 'standalone', 'all'],
                        default='all',
                        help='Output format: all (everything), threats (C-like), yara, asr, standalone (unmapped sigs), files (lua), csv')

    # Filter options
    parser.add_argument('--lua-only', action='store_true',
                        help='Only extract Lua signatures')
    parser.add_argument('--no-decompile', action='store_true',
                        help='Skip Lua decompilation')
    parser.add_argument('--luadec', choices=['auto', 'luadec', 'python', 'docker'],
                        default='auto',
                        help='Lua decompiler backend: auto (detect luadec on PATH, fallback to python), luadec (native binary), python (pure Python), docker (viruscamp/luadec image)')

    # Download options
    parser.add_argument('--arch', choices=['x64', 'x86', 'arm64'],
                        default='x64',
                        help='Architecture for signature download (default: x64)')

    # Other options
    parser.add_argument('--keep-temp', action='store_true',
                        help='Keep temporary files')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress progress output')
    parser.add_argument('--version', '-v', action='version',
                        version=f'defender_sig_extractor {__version__}')

    args = parser.parse_args()

    start_time = time.time()

    if not args.quiet:
        print_banner()

    # Set decompiler backend
    if not args.no_decompile:
        if args.luadec == 'auto':
            # Auto-detect: prefer native luadec, fall back to python
            check = check_backend_available('luadec')
            if check['available']:
                set_backend('luadec')
                if not args.quiet:
                    print(f"[*] Using native luadec binary")
            else:
                set_backend('python')
                if not args.quiet:
                    print(f"[*] Native luadec not found, using Python decompiler")
                    print(f"    Install luadec for better results: https://github.com/viruscamp/luadec")
        else:
            check = check_backend_available(args.luadec)
            if not check['available']:
                print(f"[-] Backend '{args.luadec}' not available: {check['error']}")
                sys.exit(1)
            set_backend(args.luadec)
            if not args.quiet:
                labels = {
                    'luadec': 'native luadec binary',
                    'python': 'Python decompiler',
                    'docker': 'Docker luadec (viruscamp/luadec)',
                }
                print(f"[*] Using {labels.get(args.luadec, args.luadec)}")

    # Create temp directory for intermediate files
    temp_dir = tempfile.mkdtemp(prefix='defender_sig_')
    cleanup_temp = not args.keep_temp

    try:
        # Step 1: Get mpam-fe.exe
        if args.download:
            mpam_path = download_signatures(temp_dir, args.arch)
        elif args.mpam:
            mpam_path = args.mpam
            if not Path(mpam_path).exists():
                print(f"[-] File not found: {mpam_path}")
                sys.exit(1)
        else:
            mpam_path = None

        # Step 2: Extract VDM files
        if mpam_path:
            vdm_dir = Path(temp_dir) / 'vdm'
            vdm_files = extract_vdm(mpam_path, str(vdm_dir))
        elif args.vdm:
            vdm_files = get_vdm_files(args.vdm)
            if not vdm_files:
                print(f"[-] No VDM files found in: {args.vdm}")
                sys.exit(1)
        else:
            print("[-] No input specified")
            sys.exit(1)

        # Step 3: Parse VDM files
        print("\n[*] Parsing VDM files...")
        signatures, vdm_data = process_vdm_files(vdm_files, lua_only=args.lua_only)

        if not signatures:
            print("[-] No signatures found")
            sys.exit(1)

        # Step 4: Print statistics
        if not args.quiet:
            print_statistics(signatures)

        # Step 5: Output
        print(f"\n[*] Writing output to {args.output}...")
        output_signatures(
            signatures,
            args.output,
            format_type=args.format,
            lua_only=args.lua_only,
            decompile=not args.no_decompile,
            vdm_data=vdm_data
        )

        elapsed = time.time() - start_time
        print(f"\n[+] Done! (Total time: {elapsed:.1f}s)")

    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\n[-] Error: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    finally:
        # Cleanup temp directory
        if cleanup_temp and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
