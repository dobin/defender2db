# Decoding VDLL_X86 and VDLL_X64

`SIGNATURE_TYPE_VDLL_X86` (`0x79`) and `SIGNATURE_TYPE_VDLL_X64` (`0x7c`) are
Defender's **virtual DLL** images.  Unlike most signature records, these are not
metadata or a fingerprint: the TLV payload is a complete Windows PE file that
starts directly with the `MZ` header.

The decoder is `VdllSig` in
`defender2yara/defender/signature/vdll.py`, wired into `Vdm.decode_record`.
Tests: `tests/test_signature_vdll.py`.

## Layout

```
u8  type           0x79 (x86) or 0x7c (x64)
u8  size_low
u16 size_high      payload size (normal TLV framing)
u8  image[]        complete PE image, file layout (starts with 'MZ')
```

There is no extra wrapper, compression or encryption.  `pefile.PE(data=payload)`
parses every record in the shipped database.  The embedded image is an ordinary
file-layout PE: section `PointerToRawData` values are not RVAs.

## What the images are

The export directory name is the Windows module the image emulates.  The
exports are the API entry points the engine can intercept.  Examples:

| module | exports |
|---|---|
| `MSHTML.DLL` | `RunHTMLApplication`, `ShowHTMLDialog`, `PrintHTML`, … |
| `LZ32.DLL` | `LZCopy`, `LZOpenFileA`, `LZRead`, … (forwarded to `kernel32.*`) |
| `BASESRV.DLL` | `BaseSrvNlsLogon`, `BaseSetProcessCreateNotify`, … |
| `UNKNOWNSYS.DLL` | `UnimplementedAPI` (catch-all stub) |
| `api-ms-win-core-*.dll` | individual Win32 API-set entries |

The engine strings `isvdllimage`, `isvdllbase`, `vdll_data_t`,
`MpVdllTickCount`, `reads_vdll_code`, `dynmem_reads_vdll_code` and
`verbose_vdll_reads` show that these images are loaded by the emulator and that
the engine tracks reads of their code.  They let a behaviour signature observe a
call into a system module without executing the real DLL.

Some images are trimmed copies of real Microsoft DLLs (they carry the original
timestamp and PDB name), while most are purpose-built 1–2 KiB stubs with an
entry point of zero.

## Statistics

Database: signature `1.463.330.0`, engine `1.1.26100.4`.  All VDLL records live
in `!InfrastructureShared`.

| metric | x86 (`0x79`) | x64 (`0x7c`) | total |
|---|---:|---:|---:|
| records | 750 | 195 | **945** |
| record bytes | 49,931,479 | 4,303,628 | **54,235,107** |
| payload range | 1,024 – 1,392,671 | 1,024 – 649,728 | |
| median payload | 17,408 | 3,584 | |
| distinct emulated modules | 750 | 195 | 750 (union; x64 names are a subset of x86) |
| exports | 93,384 | 41,633 | **135,017** |
| forwarded exports | 24,208 | 9,049 | **33,257** |
| imports | 6,131 | 1,180 | **7,311** |
| PE machine | `0x14c` | `0x8664` | |
| PE format | PE32 | PE32+ | |

All 945 images are DLLs.  Most are 1–5 sections and use subsystem 3 (Windows
console); six x86 images are older GUI DLLs (subsystem 2) with 2004-era
timestamps, and one has a 31-byte overlay.  The largest export tables belong to
the trimmed `MFC42.DLL` / `MFC42u.DLL` images (6,394 exports each).

The 54 MB of VDLL images are 36% of the `!InfrastructureShared` bytes and were
previously the pool's main undecoded region.

## Decoded fields

`VdllSig` exposes:

- `architecture` (`x86`/`x64`), `machine`, `machine_label`, `pe_format`
- `module_name` — export-directory name; the emulated module
- `is_dll`, `is_executable`, `timestamp`/`timestamp_iso`
- `image_base`, `entry_point`, `size_of_image`, `size_of_headers`, `checksum`
- `subsystem`/`subsystem_label`, `dll_characteristics`
- `sections` (name, virtual/raw address and size, characteristics)
- `exports`, `export_count`, `forwarders`
- `imported_modules`, `import_count`, `overlay_size`
- `payload_sha256`, `payload_size`, `summary`

Malformed payloads do not abort the database import: a payload without `MZ`, an
unparseable PE, or an image whose machine does not match the record type becomes
`partial` with a `decode_warnings` entry.  Every shipped VDLL record decodes
without warnings.

## Related types

`SIGNATURE_TYPE_VDLL_MSIL` (`0xc4`, 10 records) is also a PE image
(PE32/`0x14c` with a CLR header) but is not enabled in `VDLL_SIGS`; adding it
would reuse the same decoder.  The ARM/ARM64 VDLL types have no records in the
shipped database.

## Relation to VDLL_META

`SIGNATURE_TYPE_VDLL_META` (`0xb5`) and `VDLL_META_X64` (`0xe1`) are separate
12-byte records (5,499 and 1,090 in the shipped pool).  They are not required to
parse a VDLL image and remain opaque; the PE itself carries the module name and
API surface.

## YARA

VDLL records are emulator infrastructure, not detections.  There is no useful
YARA representation: the images are benign helper DLLs, and matching them would
identify Defender's own support files rather than malware.  The decoder is for
the database/UI and ASR research only.
