"""
Lua Writer for Decompiled Script Export

Writes decompiled Lua scripts to organized directory structure.
"""

import hashlib
import re
from pathlib import Path
from typing import Iterator, Optional, Dict, List
from dataclasses import dataclass

from ..vdm_parser import Signature
from ..signature_types import get_type_name
from ..signature_handlers.lua_handler import (
    parse_lua_signature, decompile_lua_signature, LuaSignature
)


@dataclass
class LuaOutputFile:
    """Information about an output Lua file."""
    path: str
    threat_name: str
    category: str
    sig_type: str
    size: int
    decompiled: bool
    error: Optional[str] = None


class LuaWriter:
    """
    Writes decompiled Lua scripts to disk.

    Output structure:
    {output_dir}/
    ├── {threat_name}/
    │   ├── {category}/
    │   │   ├── {index}.lua      (decompiled source)
    │   │   └── {index}.luac     (original bytecode)
    │   └── ...
    └── ...
    """

    def __init__(self, output_dir: str, write_bytecode: bool = True,
                 write_source: bool = True):
        """
        Initialize Lua writer.

        Args:
            output_dir: Base directory for output
            write_bytecode: Write .luac bytecode files
            write_source: Write .lua decompiled source files
        """
        self.output_dir = Path(output_dir)
        self.write_bytecode = write_bytecode
        self.write_source = write_source
        self._counters: Dict[str, int] = {}

    def _sanitize_filename(self, name: str) -> str:
        """Sanitize string for use in filename."""
        if not name:
            return "unknown"
        # Remove/replace invalid characters
        name = re.sub(r'[<>:"/\\|?*]', '_', name)
        name = re.sub(r'\s+', '_', name)
        name = name.strip('._')
        return name[:100] or "unknown"  # Limit length

    def _get_output_path(self, sig: LuaSignature) -> Path:
        """Get output path for a Lua signature."""
        threat = self._sanitize_filename(sig.threat_name or "unknown_threat")
        category = self._sanitize_filename(sig.category or "general")
        sig_type = self._sanitize_filename(sig.sig_type.name)

        # Generate unique index
        key = f"{threat}/{category}/{sig_type}"
        index = self._counters.get(key, 0)
        self._counters[key] = index + 1

        return self.output_dir / threat / category / f"{sig_type}_{index:04d}"

    def _get_output_path_by_hash(self, sig: LuaSignature) -> Path:
        """Get output path using hash-based naming."""
        # Use hash of bytecode for unique naming
        hash_str = hashlib.sha256(sig.lua_bytecode).hexdigest()[:16]

        threat = self._sanitize_filename(sig.threat_name or "unknown")
        category = self._sanitize_filename(sig.category or "general")

        return self.output_dir / threat / category / hash_str

    def write_lua_signature(self, sig: Signature) -> Optional[LuaOutputFile]:
        """
        Write a single Lua signature to disk.

        Args:
            sig: Raw signature from VDM parser

        Returns:
            Output file info or None if not a Lua signature
        """
        if not sig.is_lua:
            return None

        try:
            # Parse the Lua signature
            lua_sig = parse_lua_signature(sig.sig_type, sig.data)

            if not lua_sig.has_bytecode:
                return LuaOutputFile(
                    path="",
                    threat_name=lua_sig.threat_name,
                    category=lua_sig.category,
                    sig_type=lua_sig.sig_type.name,
                    size=sig.size,
                    decompiled=False,
                    error="No valid bytecode found"
                )

            # Get output path
            base_path = self._get_output_path(lua_sig)
            base_path.parent.mkdir(parents=True, exist_ok=True)

            output_file = LuaOutputFile(
                path=str(base_path),
                threat_name=lua_sig.threat_name,
                category=lua_sig.category,
                sig_type=lua_sig.sig_type.name,
                size=sig.size,
                decompiled=False
            )

            # Write bytecode
            if self.write_bytecode:
                bytecode_path = base_path.with_suffix('.luac')
                with open(bytecode_path, 'wb') as f:
                    f.write(lua_sig.lua_bytecode)

            # Decompile and write source
            if self.write_source:
                try:
                    source = decompile_lua_signature(lua_sig)
                    source_path = base_path.with_suffix('.lua')
                    with open(source_path, 'w', encoding='utf-8') as f:
                        f.write(source)
                    output_file.decompiled = True
                except Exception as e:
                    output_file.error = f"Decompilation failed: {e}"

            return output_file

        except Exception as e:
            return LuaOutputFile(
                path="",
                threat_name="",
                category="",
                sig_type=get_type_name(sig.sig_type),
                size=sig.size,
                decompiled=False,
                error=str(e)
            )

    def write_all(self, signatures: Iterator[Signature]) -> List[LuaOutputFile]:
        """
        Write all Lua signatures to disk.

        Args:
            signatures: Iterator of signatures

        Returns:
            List of output file info
        """
        results = []
        for sig in signatures:
            if sig.is_lua:
                result = self.write_lua_signature(sig)
                if result:
                    results.append(result)
        return results


class LuaIndexWriter:
    """
    Writes an index file for decompiled Lua scripts.
    """

    def __init__(self, output_path: str):
        self.output_path = Path(output_path)

    def write_index(self, files: List[LuaOutputFile]) -> None:
        """Write index file."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write("# Decompiled Lua Signatures Index\n\n")
            f.write(f"Total files: {len(files)}\n")

            decompiled = sum(1 for file in files if file.decompiled)
            failed = sum(1 for file in files if file.error)
            f.write(f"Successfully decompiled: {decompiled}\n")
            f.write(f"Failed: {failed}\n\n")

            # Group by threat
            by_threat: Dict[str, List[LuaOutputFile]] = {}
            for file in files:
                threat = file.threat_name or "unknown"
                if threat not in by_threat:
                    by_threat[threat] = []
                by_threat[threat].append(file)

            f.write("## By Threat\n\n")
            for threat in sorted(by_threat.keys()):
                threat_files = by_threat[threat]
                f.write(f"### {threat} ({len(threat_files)} files)\n")
                for file in threat_files:
                    status = "OK" if file.decompiled else f"FAILED: {file.error}"
                    f.write(f"- {file.path} [{status}]\n")
                f.write("\n")


def write_lua_signatures(signatures: Iterator[Signature], output_dir: str,
                         write_bytecode: bool = True,
                         write_source: bool = True) -> List[LuaOutputFile]:
    """
    Write all Lua signatures to disk.

    Args:
        signatures: Iterator of signatures
        output_dir: Output directory
        write_bytecode: Write .luac files
        write_source: Write .lua decompiled files

    Returns:
        List of output file info
    """
    writer = LuaWriter(output_dir, write_bytecode, write_source)
    return writer.write_all(signatures)


def create_index(files: List[LuaOutputFile], output_path: str) -> None:
    """Create index file for decompiled Lua scripts."""
    index_writer = LuaIndexWriter(output_path)
    index_writer.write_index(files)
