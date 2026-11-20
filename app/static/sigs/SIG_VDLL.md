# VDLL signatures

`SIGNATURE_TYPE_VDLL_X86` (`0x79`) and `SIGNATURE_TYPE_VDLL_X64` (`0x7c`) are
Defender's **virtual DLLs**: complete, tiny PE images stored directly in the
signature database.  They are infrastructure for the emulator, not detections.

The engine loads these images when emulating a sample and resolves their
exported API names.  The DLL's export-directory name says which Windows module
is being emulated — for example `MSHTML.DLL`, `LZ32.DLL`, `BASESRV.DLL`, or
`api-ms-win-core-*.dll`.  The exports are the API entry points; many are
forwards to `kernel32.*` or `MSVCRT.*`.

This page shows:

- the emulated module name,
- the PE type, machine, timestamp and section layout,
- the exported API names and forwarded exports,
- imported modules and the SHA-256 of the embedded image.

These records do not identify malware and are not converted to YARA.  All VDLL
records in the shipped database live in `!InfrastructureShared`.
