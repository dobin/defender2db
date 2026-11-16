"""
Hash Signature Handler

Parses file hash signatures (SHA256, SHA512, etc.) from Microsoft Defender.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional
from io import BytesIO
from enum import IntEnum

from ..signature_types import SigType


class HashType(IntEnum):
    """Hash algorithm types."""
    MD5 = 1
    SHA1 = 2
    SHA256 = 3
    SHA512 = 4
    CTPH = 5  # Context Triggered Piecewise Hash (fuzzy hash)
    IMPHASH = 6
    AUTHENTIHASH = 7


@dataclass
class HashEntry:
    """A single hash entry."""
    hash_type: HashType
    hash_value: bytes
    metadata: dict

    @property
    def hex_hash(self) -> str:
        return self.hash_value.hex()

    def __str__(self) -> str:
        return f"{self.hash_type.name}:{self.hex_hash}"


@dataclass
class HashSignature:
    """Parsed hash signature containing one or more hashes."""
    sig_type: SigType
    hashes: List[HashEntry]
    threat_name: Optional[str] = None
    is_friendly: bool = False  # True for whitelist, False for blacklist

    @property
    def is_threat(self) -> bool:
        return not self.is_friendly


class HashSignatureParser:
    """
    Parser for hash signature entries.

    Hash signatures can contain:
    - Single hash
    - Multiple hashes for the same file
    - Hash with metadata (file size, type, etc.)
    """

    # Hash sizes in bytes
    HASH_SIZES = {
        HashType.MD5: 16,
        HashType.SHA1: 20,
        HashType.SHA256: 32,
        HashType.SHA512: 64,
    }

    def __init__(self, sig_type: SigType, data: bytes):
        self.sig_type = sig_type
        self.data = data
        self.stream = BytesIO(data)

    def _read_uint8(self) -> int:
        b = self.stream.read(1)
        return b[0] if b else 0

    def _read_uint16(self) -> int:
        data = self.stream.read(2)
        if len(data) < 2:
            return 0
        return struct.unpack('<H', data)[0]

    def _read_uint32(self) -> int:
        data = self.stream.read(4)
        if len(data) < 4:
            return 0
        return struct.unpack('<I', data)[0]

    def _read_uint64(self) -> int:
        data = self.stream.read(8)
        if len(data) < 8:
            return 0
        return struct.unpack('<Q', data)[0]

    def _read_null_string(self) -> str:
        chars = []
        while True:
            b = self.stream.read(1)
            if not b or b == b'\x00':
                break
            chars.append(b)
        return b''.join(chars).decode('utf-8', errors='replace')

    def _determine_hash_type(self) -> HashType:
        """Determine hash type from signature type."""
        if self.sig_type in (SigType.FRIENDLYHASH_SHA256, SigType.THREATHASH_SHA256):
            return HashType.SHA256
        elif self.sig_type in (SigType.FRIENDLYHASH_SHA512, SigType.THREATHASH_SHA512):
            return HashType.SHA512
        elif self.sig_type in (SigType.FRIENDLYHASH_CTPH, SigType.THREATHASH_CTPH):
            return HashType.CTPH
        else:
            # Default to SHA256
            return HashType.SHA256

    def parse(self) -> HashSignature:
        """Parse the hash signature."""
        hashes = []
        threat_name = None
        is_friendly = self.sig_type in (
            SigType.FRIENDLY_FILE_HASH,
            SigType.FRIENDLYHASH_SHA256,
            SigType.FRIENDLYHASH_SHA512,
            SigType.FRIENDLYHASH_CTPH,
        )

        hash_type = self._determine_hash_type()
        hash_size = self.HASH_SIZES.get(hash_type, 32)

        # Try to parse based on signature type
        try:
            if self.sig_type == SigType.FRIENDLY_FILE_HASH:
                # Friendly hash format: multiple SHA256 hashes packed together
                while self.stream.tell() + hash_size <= len(self.data):
                    hash_data = self.stream.read(hash_size)
                    if len(hash_data) == hash_size:
                        hashes.append(HashEntry(
                            hash_type=hash_type,
                            hash_value=hash_data,
                            metadata={}
                        ))

            elif self.sig_type == SigType.THREAT_FILE_HASH:
                # Threat hash format: may include threat name
                # Try to detect format
                first_bytes = self.data[:4]

                if all(b in range(0x20, 0x7f) or b == 0 for b in first_bytes):
                    # Starts with printable ASCII - likely threat name
                    self.stream.seek(0)
                    threat_name = self._read_null_string()

                # Read hash
                remaining = len(self.data) - self.stream.tell()
                if remaining >= hash_size:
                    hash_data = self.stream.read(hash_size)
                    hashes.append(HashEntry(
                        hash_type=hash_type,
                        hash_value=hash_data,
                        metadata={"threat_name": threat_name} if threat_name else {}
                    ))

            else:
                # Generic hash parsing
                # Try to read as many hashes as possible
                while self.stream.tell() + hash_size <= len(self.data):
                    hash_data = self.stream.read(hash_size)
                    if len(hash_data) == hash_size and any(b != 0 for b in hash_data):
                        hashes.append(HashEntry(
                            hash_type=hash_type,
                            hash_value=hash_data,
                            metadata={}
                        ))
                    else:
                        break

        except Exception:
            # If parsing fails, try raw extraction
            if len(self.data) >= hash_size:
                hashes.append(HashEntry(
                    hash_type=hash_type,
                    hash_value=self.data[:hash_size],
                    metadata={"raw": True}
                ))

        return HashSignature(
            sig_type=self.sig_type,
            hashes=hashes,
            threat_name=threat_name,
            is_friendly=is_friendly
        )


def parse_hash_signature(sig_type: int, data: bytes) -> HashSignature:
    """Parse a hash signature from raw data."""
    try:
        st = SigType(sig_type)
    except ValueError:
        st = SigType.FRIENDLY_FILE_HASH

    parser = HashSignatureParser(st, data)
    return parser.parse()


def format_hash_signature(sig: HashSignature) -> str:
    """Format hash signature for display."""
    lines = []

    sig_label = "Friendly" if sig.is_friendly else "Threat"
    lines.append(f"{sig_label} Hash Signature ({sig.sig_type.name})")

    if sig.threat_name:
        lines.append(f"  Threat: {sig.threat_name}")

    for i, entry in enumerate(sig.hashes):
        lines.append(f"  [{i}] {entry.hash_type.name}: {entry.hex_hash}")
        for key, value in entry.metadata.items():
            lines.append(f"       {key}: {value}")

    return "\n".join(lines)


def extract_hashes(data: bytes, hash_size: int = 32) -> List[str]:
    """Extract all possible hashes of given size from data."""
    hashes = []
    offset = 0
    while offset + hash_size <= len(data):
        hash_bytes = data[offset:offset + hash_size]
        if any(b != 0 for b in hash_bytes):  # Skip null hashes
            hashes.append(hash_bytes.hex())
        offset += hash_size
    return hashes
