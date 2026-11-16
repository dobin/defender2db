"""
PE/CAB Extractor for Microsoft Defender Signatures

Extracts VDM files from mpam-fe.exe self-extracting archive.
mpam-fe.exe is a PE file with an embedded CAB archive.

Requires cabextract binary for CAB extraction.
"""

import struct
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


def _check_cabextract() -> None:
    """Check if cabextract is installed."""
    if shutil.which("cabextract") is None:
        raise RuntimeError(
            "cabextract not found. Please install it:\n"
            "  macOS: brew install cabextract\n"
            "  Ubuntu/Debian: sudo apt install cabextract\n"
            "  Fedora: sudo dnf install cabextract"
        )


# VDM file names to extract
VDM_FILES = [
    'mpasbase.vdm',   # Base antispyware signatures
    'mpasdlta.vdm',   # Delta antispyware signatures
    'mpavbase.vdm',   # Base antivirus signatures
    'mpavdlta.vdm',   # Delta antivirus signatures
]

# CAB file signature
CAB_SIGNATURE = b'MSCF'


@dataclass
class ExtractedFile:
    """Information about an extracted file."""
    name: str
    path: str
    size: int
    is_vdm: bool


class PEExtractor:
    """
    Extracts CAB archive from PE file overlay.
    """

    def __init__(self, pe_path: str):
        self.path = Path(pe_path)
        self._data: Optional[bytes] = None
        self._pe = None

    def _load(self) -> bytes:
        """Load PE file data."""
        if self._data is None:
            with open(self.path, 'rb') as f:
                self._data = f.read()
        return self._data

    def _find_cab_offset(self) -> Tuple[int, int]:
        """Find CAB archive in PE overlay."""
        data = self._load()

        # Search for CAB signature
        cab_offset = data.find(CAB_SIGNATURE)
        if cab_offset == -1:
            raise ExtractionError("CAB signature not found in PE file")

        # Parse CAB header to get size
        # CAB header format:
        # 0x00: 'MSCF' (signature)
        # 0x04: reserved1 (4 bytes)
        # 0x08: cabinet file size (4 bytes, little-endian)
        if cab_offset + 12 > len(data):
            raise ExtractionError("Incomplete CAB header")

        cab_size = struct.unpack_from('<I', data, cab_offset + 8)[0]

        # Validate size
        if cab_offset + cab_size > len(data):
            # Size might be corrupt, use remaining data
            cab_size = len(data) - cab_offset

        return cab_offset, cab_size

    def _find_cab_offset_pefile(self) -> Tuple[int, int]:
        """Use pefile to find overlay (data after PE sections)."""
        if not HAS_PEFILE:
            raise ImportError("pefile library required: pip install pefile")

        data = self._load()
        pe = pefile.PE(data=data)

        # Find end of PE sections
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is None:
            raise ExtractionError("No overlay data found in PE")

        # Check if overlay starts with CAB signature
        if data[overlay_offset:overlay_offset + 4] != CAB_SIGNATURE:
            # Search for CAB in overlay
            cab_offset = data.find(CAB_SIGNATURE, overlay_offset)
            if cab_offset == -1:
                raise ExtractionError("CAB signature not found in PE overlay")
        else:
            cab_offset = overlay_offset

        # Get CAB size from header
        cab_size = struct.unpack_from('<I', data, cab_offset + 8)[0]
        if cab_offset + cab_size > len(data):
            cab_size = len(data) - cab_offset

        return cab_offset, cab_size

    def extract_cab(self) -> bytes:
        """Extract CAB data from PE file."""
        data = self._load()

        # First, try simple search for CAB signature anywhere in file
        # This works for mpam-fe.exe where CAB is embedded in PE body
        try:
            cab_offset, cab_size = self._find_cab_offset()
            return data[cab_offset:cab_offset + cab_size]
        except ExtractionError:
            pass

        # Fallback: try pefile overlay method
        if HAS_PEFILE:
            try:
                cab_offset, cab_size = self._find_cab_offset_pefile()
                return data[cab_offset:cab_offset + cab_size]
            except ExtractionError:
                pass

        raise ExtractionError("CAB signature not found in PE file")

    def extract_vdm_files(self, output_dir: str) -> List[ExtractedFile]:
        """Extract VDM files from PE to output directory."""
        _check_cabextract()
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        return self._extract_with_cabextract(output_dir)

    def _extract_with_cabextract(self, output_dir: str) -> List[ExtractedFile]:
        """Extract using cabextract command."""
        result = subprocess.run(
            ['cabextract', '-d', output_dir, str(self.path)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise ExtractionError(f"cabextract failed: {result.stderr}")

        # List extracted files
        extracted = []
        output_path = Path(output_dir)
        for f in output_path.iterdir():
            if f.is_file():
                extracted.append(ExtractedFile(
                    name=f.name,
                    path=str(f),
                    size=f.stat().st_size,
                    is_vdm=f.name.lower().endswith('.vdm')
                ))

        return extracted


class ExtractionError(Exception):
    """Error during file extraction."""
    pass


def extract_vdm_files(mpam_path: str, output_dir: str) -> List[ExtractedFile]:
    """
    Extract VDM files from mpam-fe.exe.

    Args:
        mpam_path: Path to mpam-fe.exe
        output_dir: Directory to extract files to

    Returns:
        List of extracted files
    """
    pe_extractor = PEExtractor(mpam_path)
    return pe_extractor.extract_vdm_files(output_dir)


def extract_cab_from_pe(pe_path: str) -> bytes:
    """Extract CAB archive data from PE file."""
    pe_extractor = PEExtractor(pe_path)
    return pe_extractor.extract_cab()


def list_cab_contents(cab_data: bytes) -> List[str]:
    """List files in a CAB archive using cabextract."""
    import tempfile
    _check_cabextract()

    # Write CAB data to temp file
    with tempfile.NamedTemporaryFile(suffix='.cab', delete=False) as tmp:
        tmp.write(cab_data)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ['cabextract', '-l', tmp_path],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise ExtractionError(f"cabextract failed: {result.stderr}")

        # Parse output to get file names
        files = []
        for line in result.stdout.splitlines():
            # cabextract -l output format: "  size | date time | name"
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    filename = parts[2].strip()
                    if filename:
                        files.append(filename)
        return files
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def get_vdm_files(extracted_dir: str) -> Dict[str, str]:
    """
    Find VDM files in extracted directory.

    Returns:
        Dictionary mapping VDM type to file path
    """
    dir_path = Path(extracted_dir)
    vdm_files = {}

    for vdm_name in VDM_FILES:
        file_path = dir_path / vdm_name
        if file_path.exists():
            # Determine type from filename
            if 'base' in vdm_name:
                key = 'as_base' if 'mpas' in vdm_name else 'av_base'
            else:
                key = 'as_delta' if 'mpas' in vdm_name else 'av_delta'
            vdm_files[key] = str(file_path)

    return vdm_files


def verify_pe_file(pe_path: str) -> Dict:
    """
    Verify PE file and check for CAB overlay.

    Returns:
        Verification result dictionary
    """
    result = {
        'is_pe': False,
        'has_cab': False,
        'cab_offset': None,
        'cab_size': None,
    }

    try:
        with open(pe_path, 'rb') as f:
            magic = f.read(2)
            result['is_pe'] = magic == b'MZ'

            if result['is_pe']:
                f.seek(0)
                data = f.read()

                # Find CAB
                cab_offset = data.find(CAB_SIGNATURE)
                if cab_offset != -1:
                    result['has_cab'] = True
                    result['cab_offset'] = cab_offset
                    result['cab_size'] = struct.unpack_from('<I', data, cab_offset + 8)[0]

    except Exception as e:
        result['error'] = str(e)

    return result
