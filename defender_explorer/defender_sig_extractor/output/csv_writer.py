"""
CSV Writer for Signature Export

Exports parsed signatures to CSV format for analysis.
"""

import csv
from pathlib import Path
from typing import List, Iterator, Optional, TextIO
from dataclasses import dataclass

from ..vdm_parser import Signature


@dataclass
class CSVRow:
    """Represents a row in the signature CSV."""
    sig_type: int
    type_name: str
    size: int
    offset: int
    hex_data: str
    threat_name: str = ""
    category: str = ""
    is_lua: bool = False


class CSVWriter:
    """
    Writes signatures to CSV format.

    CSV columns:
    - sig_type: Numeric signature type code
    - type_name: Human-readable type name
    - size: Payload size in bytes
    - offset: Offset in original stream
    - threat_name: Extracted threat name (if available)
    - category: Signature category
    - is_lua: Whether this is a Lua signature
    - hex_data: Hex-encoded payload data
    """

    COLUMNS = [
        'sig_type',
        'type_name',
        'size',
        'offset',
        'threat_name',
        'category',
        'is_lua',
        'hex_data',
    ]

    def __init__(self, output_path: str, include_hex: bool = True,
                 max_hex_length: int = 10000):
        """
        Initialize CSV writer.

        Args:
            output_path: Path to output CSV file
            include_hex: Whether to include hex data column
            max_hex_length: Maximum length of hex data to include
        """
        self.output_path = Path(output_path)
        self.include_hex = include_hex
        self.max_hex_length = max_hex_length
        self._file: Optional[TextIO] = None
        self._writer: Optional[csv.DictWriter] = None

    def _signature_to_row(self, sig: Signature) -> CSVRow:
        """Convert signature to CSV row."""
        hex_data = ""
        if self.include_hex:
            hex_data = sig.data.hex()
            if len(hex_data) > self.max_hex_length:
                hex_data = hex_data[:self.max_hex_length] + "..."

        return CSVRow(
            sig_type=sig.sig_type,
            type_name=sig.type_name,
            size=sig.size,
            offset=sig.offset,
            hex_data=hex_data,
            is_lua=sig.is_lua
        )

    def open(self) -> None:
        """Open the CSV file for writing."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.output_path, 'w', newline='', encoding='utf-8')

        columns = [c for c in self.COLUMNS if c != 'hex_data' or self.include_hex]
        self._writer = csv.DictWriter(self._file, fieldnames=columns)
        self._writer.writeheader()

    def write_signature(self, sig: Signature) -> None:
        """Write a single signature to CSV."""
        if self._writer is None:
            raise RuntimeError("CSV file not opened. Call open() first.")

        row = self._signature_to_row(sig)
        row_dict = {
            'sig_type': row.sig_type,
            'type_name': row.type_name,
            'size': row.size,
            'offset': row.offset,
            'threat_name': row.threat_name,
            'category': row.category,
            'is_lua': row.is_lua,
        }
        if self.include_hex:
            row_dict['hex_data'] = row.hex_data

        self._writer.writerow(row_dict)

    def write_signatures(self, signatures: Iterator[Signature]) -> int:
        """Write multiple signatures to CSV."""
        count = 0
        for sig in signatures:
            self.write_signature(sig)
            count += 1
        return count

    def close(self) -> None:
        """Close the CSV file."""
        if self._file:
            self._file.close()
            self._file = None
            self._writer = None

    def __enter__(self) -> 'CSVWriter':
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()


def write_signatures_to_csv(signatures: Iterator[Signature], output_path: str,
                            include_hex: bool = True) -> int:
    """
    Write signatures to CSV file.

    Args:
        signatures: Iterator of signatures to write
        output_path: Path to output CSV file
        include_hex: Whether to include hex data

    Returns:
        Number of signatures written
    """
    with CSVWriter(output_path, include_hex=include_hex) as writer:
        return writer.write_signatures(signatures)


def write_lua_signatures_to_csv(signatures: Iterator[Signature],
                                 output_path: str) -> int:
    """
    Write only Lua signatures to CSV file.

    Args:
        signatures: Iterator of signatures
        output_path: Path to output CSV file

    Returns:
        Number of signatures written
    """
    lua_sigs = (s for s in signatures if s.is_lua)
    return write_signatures_to_csv(lua_sigs, output_path)


class CSVReader:
    """
    Reads signatures from CSV format.

    Used for re-processing previously exported signatures.
    """

    def __init__(self, csv_path: str):
        self.path = Path(csv_path)

    def read_all(self) -> Iterator[dict]:
        """Read all rows from CSV."""
        with open(self.path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert types
                row['sig_type'] = int(row['sig_type'])
                row['size'] = int(row['size'])
                row['offset'] = int(row['offset'])
                row['is_lua'] = row['is_lua'].lower() == 'true'
                yield row

    def read_lua_only(self) -> Iterator[dict]:
        """Read only Lua signature rows."""
        for row in self.read_all():
            if row['is_lua']:
                yield row

    def get_statistics(self) -> dict:
        """Get statistics about the CSV file."""
        stats = {
            'total': 0,
            'lua_count': 0,
            'type_counts': {},
            'total_size': 0,
        }

        for row in self.read_all():
            stats['total'] += 1
            stats['total_size'] += row['size']

            if row['is_lua']:
                stats['lua_count'] += 1

            type_name = row['type_name']
            stats['type_counts'][type_name] = stats['type_counts'].get(type_name, 0) + 1

        return stats


def read_csv(csv_path: str) -> Iterator[dict]:
    """Read signatures from CSV file."""
    reader = CSVReader(csv_path)
    return reader.read_all()
