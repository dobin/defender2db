import hashlib
from datetime import datetime, timezone

try:
    import pefile
except ImportError:  # pragma: no cover - pefile is a declared dependency
    pefile = None

from .base import BaseSig


VDLL_SIGS = frozenset({
    "SIGNATURE_TYPE_VDLL_X86",
    "SIGNATURE_TYPE_VDLL_X64",
})

# Expected PE machine per signature type.  The record body is the DLL image
# itself, so the machine word is a sanity check rather than the primary key.
VDLL_EXPECTED_MACHINES = {
    0x79: 0x14C,   # VDLL_X86 -> IMAGE_FILE_MACHINE_I386
    0x7C: 0x8664,  # VDLL_X64 -> IMAGE_FILE_MACHINE_AMD64
}

VDLL_ARCHITECTURES = {
    0x79: "x86",
    0x7C: "x64",
}

MACHINE_LABELS = {
    0x14C: "x86 (i386)",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64",
    0x1C0: "ARM",
    0x1C4: "ARM Thumb-2",
}

PE_FORMAT_LABELS = {
    0x10B: "PE32",
    0x20B: "PE32+",
    0x107: "PE32 ROM",
}

SUBSYSTEM_LABELS = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows console",
    5: "OS/2 console",
    7: "POSIX console",
    9: "Windows CE",
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows boot application",
}


def _decode_name(raw: bytes | None) -> str | None:
    if not raw:
        return None
    return raw.rstrip(b"\x00").decode("utf-8", "replace")


def _timestamp_iso(timestamp: int) -> str | None:
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OverflowError, OSError, ValueError):
        return None


class VdllSig(BaseSig):
    """
    SIGNATURE_TYPE_VDLL_X86 (0x79) and SIGNATURE_TYPE_VDLL_X64 (0x7c).

    A VDLL record is a complete, tiny Windows PE DLL image: the TLV payload
    starts directly with the ``MZ`` header (there is no wrapper header).  The
    images are Defender's "virtual DLLs": the emulator loads them and resolves
    the exported API names when a sample calls into a system module, so that a
    behaviour signature can observe the call without running the real DLL.

    The DLL's export-directory name field is the Windows module being emulated
    (``MSHTML.DLL``, ``WAB32.DLL``, ``LZ32.DLL``, ``ntdll.dll``,
    ``api-ms-win-core-*.dll``, ...).  Export names are the emulated API
    entries; some are forwarded (mostly ``MSVCRT.*``).  Imports are usually
    empty but a few images import from ``KERNEL32.dll``/``MSVCRT.dll``.

    The payload is an ordinary file-layout PE (section ``PointerToRawData``
    values are not RVAs), so the image can be handed to any PE parser.  Most
    images are 1–2 KiB stubs with entry point zero; a few are trimmed copies
    of real Microsoft DLLs (for example ``MFC42.DLL``) with real entry points
    and original timestamps.

    This is infrastructure, not a detection: a VDLL record cannot be turned
    into a YARA pattern that identifies malware.  The useful output is the
    emulated module name and the API surface it provides.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type_id in VDLL_EXPECTED_MACHINES

        self.payload_sha256 = hashlib.sha256(self.sig_data).hexdigest()
        self.decode_warnings = []

        self.architecture = VDLL_ARCHITECTURES[self.sig_type_id]
        self.machine: int | None = None
        self.machine_label: str | None = None
        self.pe_format: str | None = None
        self.is_dll = False
        self.is_executable = False
        self.timestamp: int | None = None
        self.timestamp_iso: str | None = None
        self.image_base: int | None = None
        self.entry_point: int | None = None
        self.size_of_image: int | None = None
        self.size_of_headers: int | None = None
        self.checksum: int | None = None
        self.subsystem: int | None = None
        self.subsystem_label: str | None = None
        self.dll_characteristics: int | None = None
        self.sections: list[dict] = []
        self.module_name: str | None = None
        self.exports: list[str] = []
        self.forwarders: dict[str, str] = {}
        self.imported_modules: list[str] = []
        self.import_count = 0
        self.overlay_size: int | None = None

        if not self.sig_data.startswith(b"MZ"):
            self.decode_warnings.append(
                "VDLL payload does not start with an MZ header"
            )
            return

        if pefile is None:
            self.decode_warnings.append("pefile is not installed")
            return

        try:
            pe = pefile.PE(data=self.sig_data, fast_load=True)
        except Exception as error:
            self.decode_warnings.append(f"Could not parse the embedded PE: {error}")
            return

        try:
            self._read_pe(pe)
        finally:
            pe.close()

    def _read_pe(self, pe) -> None:
        file_header = pe.FILE_HEADER
        optional_header = pe.OPTIONAL_HEADER

        self.machine = file_header.Machine
        self.machine_label = MACHINE_LABELS.get(
            self.machine, f"unknown (0x{self.machine:04x})"
        )
        self.pe_format = PE_FORMAT_LABELS.get(
            optional_header.Magic, f"unknown (0x{optional_header.Magic:04x})"
        )
        self.is_dll = bool(file_header.Characteristics & 0x2000)
        self.is_executable = bool(file_header.Characteristics & 0x0002)

        self.timestamp = file_header.TimeDateStamp
        self.timestamp_iso = _timestamp_iso(self.timestamp)
        self.image_base = optional_header.ImageBase
        self.entry_point = optional_header.AddressOfEntryPoint
        self.size_of_image = optional_header.SizeOfImage
        self.size_of_headers = optional_header.SizeOfHeaders
        self.checksum = optional_header.CheckSum
        self.subsystem = optional_header.Subsystem
        self.subsystem_label = SUBSYSTEM_LABELS.get(
            self.subsystem, f"unknown ({self.subsystem})"
        )
        self.dll_characteristics = optional_header.DllCharacteristics

        self.sections = [
            {
                "name": _decode_name(section.Name),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_offset": section.PointerToRawData,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
            }
            for section in pe.sections
        ]

        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                ]
            )
        except Exception as error:
            self.decode_warnings.append(f"Could not parse PE directories: {error}")

        export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_directory is not None:
            self.module_name = _decode_name(export_directory.name)
            for symbol in export_directory.symbols:
                if symbol.name:
                    name = symbol.name.decode("utf-8", "replace")
                else:
                    name = f"#{symbol.ordinal}"
                self.exports.append(name)
                if symbol.forwarder:
                    self.forwarders[name] = symbol.forwarder.decode(
                        "utf-8", "replace"
                    )

        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            self.imported_modules.append(_decode_name(entry.dll) or "?")
            self.import_count += len(entry.imports)

        try:
            overlay = pe.get_overlay()
            self.overlay_size = len(overlay) if overlay else 0
        except Exception:
            self.overlay_size = None

        expected_machine = VDLL_EXPECTED_MACHINES[self.sig_type_id]
        if self.machine != expected_machine:
            self.decode_warnings.append(
                f"PE machine 0x{self.machine:04x} does not match "
                f"{self.sig_type} (expected 0x{expected_machine:04x})"
            )

    @property
    def is_valid_pe(self) -> bool:
        return self.machine is not None

    @property
    def section_count(self) -> int:
        return len(self.sections)

    @property
    def export_count(self) -> int:
        return len(self.exports)

    @property
    def has_forwarders(self) -> bool:
        return bool(self.forwarders)

    def describe(self) -> str:
        if not self.is_valid_pe:
            return f"VDLL {self.architecture} image ({len(self.sig_data)} bytes)"
        text = f"{self.pe_format} {self.architecture} DLL"
        if self.module_name:
            text += f" {self.module_name!r}"
        text += (
            f", {len(self.sig_data)} bytes, "
            f"{self.export_count} exports, {self.import_count} imports"
        )
        if self.forwarders:
            text += f", {len(self.forwarders)} forwarded"
        return text

    def to_details(self) -> dict:
        return {
            "decode_warnings": list(self.decode_warnings),
            "architecture": self.architecture,
            "module_name": self.module_name,
            "pe_format": self.pe_format,
            "machine": self.machine,
            "machine_label": self.machine_label,
            "is_valid_pe": self.is_valid_pe,
            "is_dll": self.is_dll,
            "is_executable": self.is_executable,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "image_base": self.image_base,
            "entry_point": self.entry_point,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "checksum": self.checksum,
            "subsystem": self.subsystem,
            "subsystem_label": self.subsystem_label,
            "dll_characteristics": self.dll_characteristics,
            "section_count": self.section_count,
            "sections": self.sections,
            "export_count": self.export_count,
            "exports": self.exports,
            "forwarders": self.forwarders,
            "import_count": self.import_count,
            "imported_modules": self.imported_modules,
            "overlay_size": self.overlay_size,
            "payload_size": len(self.sig_data),
            "payload_sha256": self.payload_sha256,
            "summary": self.describe(),
        }
