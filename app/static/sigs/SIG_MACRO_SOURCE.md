# MACRO_SOURCE signatures: macro routine sequences

`SIGNATURE_TYPE_MACRO_SOURCE` (`0x43`) is Defender's **macro source** signature.
It is evaluated against the source of Word/Excel/VBA macros after the engine has
extracted and normalised them, not against the carrier file's bytes.

## The short version

A MACRO_SOURCE record is an **ordered list of normalised macro routines** plus
the kind of macro stream it applies to:

```
name_len   0..0x3f, 0 = anonymous
name       optional engine label, e.g. !#SSF:ScanAllStreams
header     bits 0..5 = routine count, bits 6+ = source kind
low[]      low 32 bits of each 64-bit routine key
high[]     optional high 32 bits, all after the low array
```

The engine hashes each routine in the macro source and then requires every key
of the record to occur, **in order**, in the scan stream. It is a structural
family signature, not a byte pattern.

## Source kind

The source kind is compared for equality, not OR-ed. It tells the loader which
macro stream produced the routine keys:

| header >> 6 | engine stream | records |
|------------:|---------------|--------:|
| 0 | Word 6 / Excel 5 macro source | 3,078 |
| 2 | Excel formula | 15 |
| 4 | VBA source + VBA p-code | 9,074 |
| 8 | Excel formula routines (`xfcrcs`) | 4,043 |

The engine names the streams `MpWord6Routines`, `MpExcel5Routines`,
`MpExcelFormulaRoutines`, `MpVBASourceRoutines` and `MpVBAPCodeRoutines`.

## Keys

Each routine key is 64 bits, stored as a low dword and an optional high dword:

* Legacy Word 6 / Excel 5 records normally omit the high array (the high half
  is zero).
* VBA and Excel-formula records normally include it.
* 27,655 keys exist in 16,210 records; the largest record has 50 routines.

The dwords are **internal hashes of normalised routines**, not file hashes.
Do not compare them with MD5/SHA/CRC values computed over a document. They are
shown as 16-hex strings so they can be correlated between records.

### What the hex digits mean

A printed key such as `000000009e69abe4` is the 64-bit key written as big-endian
hex: the first eight digits are the high dword and the last eight the low dword.
On the legacy Word 6 / Excel 5 stream the high dword is always zero, so the key
is effectively the last eight digits. A thirty-two-bit record shows the key
zero-extended like this as well.

The engine computes the hash over its own normalised form of one macro routine
(usually one procedure or statement block): whitespace, comments and some
identifier detail are reduced before hashing. The hash function and the
normalisation rules are internal to mpengine and are not documented.

**The keys cannot be reversed.** No amount of lookup turns a key back into the
original VBA text; a hash is one-way, and the pre-image was never shipped. So
there is no source code to show for a key.

### Correlating keys

What *is* resolvable is reuse. The same routine is often copied between
variants and families, and Defender ships a separate record for each detection
that needs it. `defender2db` records every `MACRO_SOURCE` key in the
`macro_routine_key` table, so the threat page can answer "which other
detections require this exact routine?":

* The same key may link variants of one family (`XM/Emperor.A` and
  `XM/Emperor.B` share `0000000014c371f9`) or unrelated names that reuse a
  helper routine.
* A key unique to one record still tells you that routine is specific to this
  detection and is a good fingerprint to look for in samples.

Records built before `macro_routine_key` existed show "Rebuild the database to
resolve routine keys" instead; rebuild with `--convert` to populate it.

Examples from the shipped database:

```
Trojan:WM/Nikita.A   word6_excel5_macro_source  2 routines
Virus:W97M/ColdApe   vba_source                 1 routine
Virus:XM/Delta.A     word6_excel5_macro_source  1 routine
Virus:XM/Delta.B     word6_excel5_macro_source  1 routine
```

## Names

Only 52 records carry an inline name (33 distinct), all in
`!InfrastructureShared`. They are engine feeds, not detections:

```
!#SSF:ScanAllStreams
!#ALF:SpikeAex.xfcrcs
!#SLF:Trojan:Win32/NeoHash.macrosrc
!#Mcrosrc:Qakbot.SS1!MTB
!#ASRWin32ApiMacroExclusion
```

## Related types

* `MACRO_PCODE` (`0x42`) and `MACRO_PCODE64` (`0xcf`) hold compiled macro
  p-code signatures.
* `MACROHSTR_EXT` (`0x8f`) is the text-pattern macro signature and is already
  decoded into YARA strings.
* `NSCRIPT_BRUTE` (`0x29`) is the equivalent readable rule for script content.

`MACRO_PCODE`/`MACRO_PCODE64` are not implemented yet.
