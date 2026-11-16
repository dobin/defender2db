"""
Delta Patcher - Apply delta patches to base VDM files

Microsoft Defender uses delta updates to minimize download sizes.
Delta files contain commands to copy from base or insert new data.
"""

import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional
from pathlib import Path


@dataclass
class DeltaHeader:
    """Delta file header information."""
    version: int
    checksum: int
    base_size: int
    output_size: int


@dataclass
class DeltaCommand:
    """Single delta patch command."""
    is_copy: bool  # True = copy from base, False = literal bytes
    offset: int    # Source offset (for copy) or data offset (for literal)
    length: int    # Number of bytes


class DeltaPatcher:
    """
    Apply delta patches to base signature files.

    Delta format:
    - Header: 16 bytes
      - version: uint32
      - checksum: uint32
      - base_size: uint32
      - output_size: uint32

    - Commands: Variable length
      - 2-byte command pairs
      - High bit of first byte indicates command type:
        - 1: Copy from base[offset:offset+length]
        - 0: Literal bytes from delta stream
    """

    def __init__(self, base_data: bytes, delta_data: bytes):
        self.base = base_data
        self.delta = delta_data
        self.header: Optional[DeltaHeader] = None
        self.commands: List[DeltaCommand] = []

    def _parse_header(self) -> DeltaHeader:
        """Parse delta file header."""
        if len(self.delta) < 16:
            raise ValueError("Delta file too short for header")

        version, checksum, base_size, output_size = struct.unpack_from(
            '<IIII', self.delta, 0
        )

        return DeltaHeader(
            version=version,
            checksum=checksum,
            base_size=base_size,
            output_size=output_size
        )

    def _parse_commands(self) -> List[Tuple[bool, int, int, bytes]]:
        """
        Parse delta commands.

        Returns list of (is_copy, offset, length, literal_data) tuples.
        For copy commands, literal_data is empty.
        For literal commands, offset refers to delta stream position.
        """
        commands = []
        offset = 16  # Skip header

        while offset < len(self.delta):
            if offset + 1 >= len(self.delta):
                break

            # Read command byte
            cmd = self.delta[offset]

            if cmd & 0x80:  # Copy command
                # Parse copy command (variable length encoding)
                copy_offset = 0
                copy_length = 0
                offset += 1

                # Offset bytes (up to 4)
                if cmd & 0x01:
                    copy_offset |= self.delta[offset]
                    offset += 1
                if cmd & 0x02:
                    copy_offset |= self.delta[offset] << 8
                    offset += 1
                if cmd & 0x04:
                    copy_offset |= self.delta[offset] << 16
                    offset += 1
                if cmd & 0x08:
                    copy_offset |= self.delta[offset] << 24
                    offset += 1

                # Length bytes (up to 3)
                if cmd & 0x10:
                    copy_length |= self.delta[offset]
                    offset += 1
                if cmd & 0x20:
                    copy_length |= self.delta[offset] << 8
                    offset += 1
                if cmd & 0x40:
                    copy_length |= self.delta[offset] << 16
                    offset += 1

                # Length of 0 means 0x10000
                if copy_length == 0:
                    copy_length = 0x10000

                commands.append((True, copy_offset, copy_length, b''))

            elif cmd:  # Literal command (cmd = length)
                literal_length = cmd
                offset += 1
                literal_data = self.delta[offset:offset + literal_length]
                offset += literal_length

                commands.append((False, 0, literal_length, literal_data))

            else:  # Reserved (cmd = 0)
                break

        return commands

    def apply(self) -> bytes:
        """Apply delta patch and return patched data."""
        self.header = self._parse_header()
        commands = self._parse_commands()

        output = bytearray()

        for is_copy, src_offset, length, literal_data in commands:
            if is_copy:
                # Copy from base
                if src_offset + length > len(self.base):
                    # Truncate if exceeds base size
                    length = max(0, len(self.base) - src_offset)
                if length > 0:
                    output.extend(self.base[src_offset:src_offset + length])
            else:
                # Insert literal data
                output.extend(literal_data)

        return bytes(output)

    @classmethod
    def patch_files(cls, base_path: str, delta_path: str) -> bytes:
        """Convenience method to patch files by path."""
        with open(base_path, 'rb') as f:
            base_data = f.read()
        with open(delta_path, 'rb') as f:
            delta_data = f.read()

        patcher = cls(base_data, delta_data)
        return patcher.apply()


class VDMDeltaPatcher:
    """
    VDM-specific delta patcher.

    Handles decompression before patching and re-compression after.
    """

    def __init__(self, base_vdm_path: str, delta_vdm_path: str):
        self.base_path = Path(base_vdm_path)
        self.delta_path = Path(delta_vdm_path)

    def apply(self) -> bytes:
        """Apply VDM delta patch."""
        from .vdm_parser import VDMParser

        # Decompress both base and delta
        base_parser = VDMParser(str(self.base_path))
        delta_parser = VDMParser(str(self.delta_path))

        try:
            base_data = base_parser.decompress()
        except Exception as e:
            raise ValueError(f"Failed to decompress base VDM: {e}")

        try:
            delta_data = delta_parser.decompress()
        except Exception as e:
            raise ValueError(f"Failed to decompress delta VDM: {e}")

        # Apply delta patch
        patcher = DeltaPatcher(base_data, delta_data)
        return patcher.apply()


def apply_delta(base_data: bytes, delta_data: bytes) -> bytes:
    """Convenience function to apply delta patch."""
    patcher = DeltaPatcher(base_data, delta_data)
    return patcher.apply()


def combine_vdm_files(base_path: str, delta_path: str) -> bytes:
    """Combine base and delta VDM files."""
    patcher = VDMDeltaPatcher(base_path, delta_path)
    return patcher.apply()
