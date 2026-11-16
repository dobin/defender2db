"""
Generic Signature Handler

Fallback handler for signature types that don't have specialized parsers.
Provides hex dump and basic structure analysis.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from io import BytesIO

from ..signature_types import SigType, get_type_name, get_signature_info


@dataclass
class GenericSignature:
    """Generic parsed signature."""
    sig_type: SigType
    data: bytes
    fields: Dict[str, Any]
    strings: List[str]
    hex_preview: str

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def type_name(self) -> str:
        return get_type_name(self.sig_type)


class GenericSignatureParser:
    """
    Generic parser that extracts basic structure from signatures.

    Attempts to:
    - Find null-terminated strings
    - Identify common binary structures
    - Provide hex dump preview
    """

    def __init__(self, sig_type: SigType, data: bytes):
        self.sig_type = sig_type
        self.data = data
        self.stream = BytesIO(data)

    def _find_strings(self, min_length: int = 4) -> List[str]:
        """Find printable strings in data."""
        strings = []
        current = []

        for b in self.data:
            if 0x20 <= b <= 0x7e:  # Printable ASCII
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    def _extract_fields(self) -> Dict[str, Any]:
        """Try to extract common fields."""
        fields = {}

        if len(self.data) < 4:
            return fields

        # Try to read first few bytes as potential length/type fields
        try:
            fields['first_byte'] = self.data[0]
            fields['first_word'] = struct.unpack('<H', self.data[:2])[0]
            fields['first_dword'] = struct.unpack('<I', self.data[:4])[0]
        except struct.error:
            pass

        # Check for common patterns
        if self.data[:4] == b'\x1bLua':
            fields['type'] = 'lua_bytecode'
        elif self.data[:2] == b'MZ':
            fields['type'] = 'pe_executable'
        elif self.data[:4] == b'\x7fELF':
            fields['type'] = 'elf_executable'
        elif self.data[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
            fields['type'] = 'zip_archive'
        elif self.data[:2] == b'\x1f\x8b':
            fields['type'] = 'gzip'
        elif self.data[:6] == b'Rar!\x1a\x07':
            fields['type'] = 'rar_archive'

        return fields

    def _hex_preview(self, max_bytes: int = 64) -> str:
        """Generate hex preview of data."""
        preview_data = self.data[:max_bytes]
        hex_str = preview_data.hex()

        # Format as space-separated bytes
        formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

        if len(self.data) > max_bytes:
            formatted += f" ... ({len(self.data) - max_bytes} more bytes)"

        return formatted

    def parse(self) -> GenericSignature:
        """Parse the signature."""
        return GenericSignature(
            sig_type=self.sig_type,
            data=self.data,
            fields=self._extract_fields(),
            strings=self._find_strings(),
            hex_preview=self._hex_preview()
        )


def parse_generic_signature(sig_type: int, data: bytes) -> GenericSignature:
    """Parse a signature using the generic handler."""
    try:
        st = SigType(sig_type)
    except ValueError:
        st = SigType.UNKNOWN

    parser = GenericSignatureParser(st, data)
    return parser.parse()


def format_generic_signature(sig: GenericSignature) -> str:
    """Format generic signature for display."""
    lines = []

    lines.append(f"Signature Type: {sig.type_name} (0x{sig.sig_type:02x})")
    lines.append(f"Size: {sig.size} bytes")

    if sig.fields:
        lines.append("Fields:")
        for key, value in sig.fields.items():
            if isinstance(value, int):
                lines.append(f"  {key}: {value} (0x{value:x})")
            else:
                lines.append(f"  {key}: {value}")

    if sig.strings:
        lines.append(f"Strings ({len(sig.strings)}):")
        for s in sig.strings[:10]:  # Limit to first 10
            lines.append(f"  \"{s}\"")
        if len(sig.strings) > 10:
            lines.append(f"  ... and {len(sig.strings) - 10} more")

    lines.append("Hex Preview:")
    lines.append(f"  {sig.hex_preview}")

    return "\n".join(lines)


def hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Generate formatted hex dump."""
    lines = []

    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]

        # Hex part
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)

        # ASCII part
        ascii_part = ''.join(
            chr(b) if 0x20 <= b <= 0x7e else '.'
            for b in chunk
        )

        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")

    return "\n".join(lines)


def analyze_signature(sig_type: int, data: bytes) -> Dict[str, Any]:
    """Analyze a signature and return structured information."""
    try:
        st = SigType(sig_type)
    except ValueError:
        st = SigType.UNKNOWN

    info = get_signature_info(st)

    result = {
        'sig_type': st,
        'type_name': get_type_name(sig_type),
        'size': len(data),
        'info': info,
    }

    # Parse using generic handler
    parser = GenericSignatureParser(st, data)
    parsed = parser.parse()

    result['fields'] = parsed.fields
    result['strings'] = parsed.strings

    # Add type-specific analysis
    if info and info.is_lua:
        result['content_type'] = 'lua_bytecode'
    elif parsed.fields.get('type'):
        result['content_type'] = parsed.fields['type']
    else:
        result['content_type'] = 'binary'

    return result
