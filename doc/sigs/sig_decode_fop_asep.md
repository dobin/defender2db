# ASEP file paths and file-offset code patterns (FOP / FOPEX)

Reverse-engineering notes for the ASEP path records and the FOP code-pattern
family, including the x64 variants:

| type | id | payload | what it is |
|------|----|--------:|------------|
| `SIGNATURE_TYPE_ASEP_FILEPATH` | `0x71` | `u16 root + path` | `FILEPATH` condition evaluated at an auto-start extensibility point |
| `SIGNATURE_TYPE_FOP` | `0x7f` | 4 B + name + bytes | literal x86 file-offset code pattern |
| `SIGNATURE_TYPE_FOPEX` | `0x89` | 10 B + name + 3 blocks | extended x86 code pattern (wildcards + signed offset) |
| `SIGNATURE_TYPE_FOP64` | `0xc8` | same as FOP | literal x64 code pattern |
| `SIGNATURE_TYPE_FOPEX64` | `0xc9` | same as FOPEX | extended x64 code pattern |

Engine build: x64 `mpengine.dll` 1.1.26100.4 (base `0x180000000`).  Function
notes were added to `cache/functions_vdm.md` section 23.  The related
`ASEP_FOLDERNAME` (`0x75`) is decoded with the same path parser; it has no
records in this database.

Decoders:

* `AsepFilePathSig` / `AsepFolderNameSig` in
  `defender2yara/defender/signature/pathname.py` (subclasses of
  `PathNameSig`).
* `FopSig` / `Fop64Sig` / `FopExSig` / `FopEx64Sig` in
  `defender2yara/defender/signature/fop.py`.

Wired into `Vdm.decode_record`; tests in `tests/test_signature_fop_asep.py`.
All 1,191 ASEP_FILEPATH, 1,519 FOP, 2,806 FOPEX, 72 FOP64 and 65 FOPEX64
records in `cache/threats.db` decode with zero errors and zero warnings.

---

## 1. `SIGNATURE_TYPE_ASEP_FILEPATH` (`0x71`)

### What it is

ASEP is the same path condition as `SIGNATURE_TYPE_FILEPATH` (`0x5f`).  The
payload is identical::

    u16  root_id      CSIDL / known-folder / engine pseudo-folder id
    u8   path[]       case-insensitive relative path or glob, no NUL terminator

The `?`/`*` glob characters are the same as in `FILEPATH`, and the root id
table is documented in `pathname.py` (`0x25` System32, `0x26` Program Files,
`0x24` windir, `0xfffe` `%temp%`, `0xffff` literal absolute path, ...).

The difference is the **context**, not the encoding.  `ASEP_FILEPATH` is used
by the auto-start extensibility point (ASEP) checks; the engine config strings
`MpExtraAsepScanLocations` and `MP_EXTRA_ASEP_SCAN_LOCATIONS` confirm the
terminology.  A path such as `%SystemRoot%\System32\ftpudp.exe` can therefore be
either a normal file condition or an ASEP check, expressed as `0x5f` or `0x71`.

### Engine registration

The resmgr plugin init `FUN_180939aa0` allocates four path tables and registers
them with `FUN_18093820c(type, builder, commit, count, table)`:

| type | builder | commit | parser |
|------|---------|--------|--------|
| `0x5f` `FILEPATH` | `FUN_1802b3690` | `FUN_1803a53b0` | `FUN_1802b378c` |
| `0x71` `ASEP_FILEPATH` | `FUN_1802b3590` | `FUN_1803a5230` | `FUN_1802b378c` |
| `0x60` `FOLDERNAME` | `FUN_1802b39c0` | `FUN_1803a52f0` | `FUN_1802b378c` |
| `0x75` `ASEP_FOLDERNAME` | `FUN_18093a1a0` | (ASEP folder commit) | `FUN_1802b378c` |

Each builder emits `FUN_180217edc(out, type, payload, size)` and computes the
packed record id as::

    crc32(payload) | type << 32 | size << 40

`FUN_1802b378c` accepts payloads of at least 3 bytes, reads the first `u16` as
the root, resolves it with `FUN_1802b3c3c`, copies the remaining path with
`FUN_1802b3d60`, and interns it.  Unknown root ids are retained but marked as
`UNKNOWN(0x....)` by the decoder.

### Examples from `cache/threats.db`

```
Worm:Win32/Korgo.AY    ASEP_FILEPATH %SystemRoot%\System32\ftpudp.exe
Worm:Win32/Msblast.F   ASEP_FILEPATH %windir%\system\eschlp.exe
Worm:Win32/Sober.C     ASEP_FILEPATH %windir%\Config\system\zipped.wrm
Worm:Win32/Bagz.A      ASEP_FILEPATH %SystemRoot%\System32\ipdb.dll
```

Top owners are browser modifiers/adware (`Hotbar`, `CnsMin`, `C2Lop`) and ASP
webshells (`Backdoor:ASP/Chopper`).

---

## 2. `SIGNATURE_TYPE_FOP` (`0x7f`) and `FOPEX` (`0x89`)

### What they are

FOP is Defender's **file-offset code pattern**: a byte-level code fingerprint
used by the emulator/code scanner, not a file hash.  `FOPEX` is the extended
form that adds the engine wildcard language, a name and a signed match offset.

The C++ classes in the binary are `FopScanner::x86_fop_processor`,
`x64_fop_processor`, `vb_fop_processor` and `msil_fop_processor` (RTTI).  The
same payload family covers:

| type | name | target |
|------|------|--------|
| `0x7f` | `FOP` | x86 literal code |
| `0x89` | `FOPEX` | x86 wildcard code |
| `0xc8` | `FOP64` | x64 literal code |
| `0xc9` | `FOPEX64` | x64 wildcard code |
| `0xb4` | `VBFOP` | Visual Basic p-code |
| `0xc7` | `VBFOPEX` | Visual Basic p-code wildcard |
| `0xba` | `MSILFOP` | .NET MSIL code |
| `0xc6` | `MSILFOPEX` | .NET MSIL wildcard |

The full FOP family is registered, but this database is dominated by the x86
forms: `0x7f` (1,519 records), `0x89` (2,806), `0xc8` FOP64 (72), `0xc9`
FOPEX64 (65), `0xba` MSILFOP (143) and `0xb4` VBFOP (6).  The x64 variants use
the same payloads and are decoded by `Fop64Sig` / `FopEx64Sig`.
`VBFOPEX` (`0xc7`) has one record and `MSILFOPEX` (`0xc6`) has none; those are
still raw.

### On-disk layout

`FOP` (`0x7f`)::

    u8  flags                 bit 0 only (0/1; 1,476 zero / 43 one)
    u8  name_length
    u16 pattern_length
    u8  name[name_length]     feed label, not NUL terminated
    u8  pattern[pattern_length] literal code bytes

`FOPEX` (`0x89`)::

    u8  flags                 bit 0 only (2,767 zero / 39 one)
    u8  name_length
    u16 prefix_length         literal code block
    u16 body_length           wildcard pattern block (always ends 90 00)
    u16 suffix_length         optional extra block (0 in 2,801, 1 in 5)
    i16 offset                signed match offset (-480..1064 observed)
    u8  name[name_length]     feed label, not NUL terminated
    u8  prefix[prefix_length]
    u8  body[body_length]
    u8  suffix[suffix_length]

The parser enforces the exact total length: `4 + name + pattern` for FOP and
`10 + name + prefix + body + suffix` for FOPEX.  It also enforces
`flags & 0xfe == 0`; records with any other flag bit are ignored by the engine
and flagged `partial` by the decoder.

### Pattern encoding

* `FOP` bytes are literal.  A `0x90` is a literal NOP, **not** the wildcard
  marker used by HSTR/KPATEX.  FOP patterns have no terminator and usually do
  not end in `90 00`.
* `FOPEX` block 2 (and block 3 when present) is validated by
  `FUN_1802b1974`, the same wildcard validator used by KPATEX.  It uses the
  shared `0x90` opcode language: `90 00` terminator, `90 01 n` skip exactly
  `n`, `90 02 n` skip 0..n, `90 03` byte class, `90 04`/`90 05` repeats.  In
  this database block 2 always ends with `90 00`; block 3 is empty in 2,801
  records and a single byte in the remaining 5.
* Block 1 is not wildcard-validated.  It is the literal code prefix before the
  wildcard body (0x90 appears as a literal NOP in 140 records).

The `offset` field is added to the current scan position by the matcher.  The
matcher entry point `FUN_1801fa18c` reads it as `(short)entry[4]` and calls
`FUN_1801167ac(..., (short)entry[4] + current_offset)`, which is why negative
values are meaningful.

### Engine notes

| address | role |
|--------:|------|
| `0x180b60a70` | FOP module init: registers `0x7f`, `0x89`, `0xc8`, `0xc9`, `0xb4`, `0xc7`, `0xba`, `0xc6` via `FUN_18018152c` |
| `0x1802b10b4` | shared record parser (`param_7` selects EX layout) |
| `0x1802b0bb0` / `0x1802b0be0` | thin wrappers: `FOP` / `FOPEX` |
| `0x1802b0910` / `0x1802b08e0` | thin wrappers: `FOP64` / `FOPEX64` |
| `0x1802b08b0` / `0x180b608c0` | thin wrappers: `VBFOP` / `VBFOPEX` |
| `0x1802b0880` / `0x180b60890` | thin wrappers: `MSILFOP` / `MSILFOPEX` |
| `DAT_181114ab0` | four 0x138-byte record contexts (x86, x64, VB, MSIL) |
| `0x1801f9ec0` / `0x1801fa18c` | matcher: build/scan a `FopScanner` program |
| `0x1801fad70` / `0x1801fafb0` | x64 / x86 processor match methods |
| `0x180c84860` / `0x180c84870` | `x64_fop_processor` / `x86_fop_processor` vftables |
| `0x180b66e50` | generic record lookup, selects x86/x64 FopScanner |
| `0x1802b1974` | wildcard validator for FOPEX body/suffix |
| `0x180118728` | KVIR32 page scanner also calls the FOP matcher |
| `0x1804288a4` / `0x18058dda4` | MSIL / VB FOP drivers |

The matcher is not a file-byte pattern in the usual sense: it is driven from
the emulator/unpacker and the code scanners.  FOP is the raw code fragment;
FOPEX is the same idea with wildcards and a relative offset.

### Coverage and examples

| type | records | real (non-aggregate) | named | notes |
|------|--------:|---------------------:|------:|-------|
| `ASEP_FILEPATH` `0x71` | 1,191 | 1,191 | 0 | identical to FILEPATH payload |
| `FOP` `0x7f` | 1,519 | 790 | 729 (474 labels) | literal fragments; 132 contain literal 0x90 |
| `FOPEX` `0x89` | 2,806 | 1,189 | 1,617 (1,096 labels) | 5 with a 1-byte suffix |
| `FOP64` `0xc8` | 72 | 15 | 57 (35 labels) | x64 literal fragments, all flag 0 |
| `FOPEX64` `0xc9` | 65 | 55 | 10 (9 labels) | x64 wildcard patterns, no suffix |

The names identify packers/obfuscators and code-patch attributes:

```
FOP    !ASprotect                     bb 03 2b 83 89 0f 8d 50 ff ...
FOP    !eXPressor                     00 07 07 00 21 75 66 72 61 69 65 ...
FOP    !#FOP:Win32/Nuwar.unsafe       ...
FOPEX  !#Tracur_LoDCheck              prefix b9 48 e2, body fd 90 00, offset 7
FOPEX  !#FOPEX:sehjump                prefix 64 90 e9, body ff 30 90 00, offset 1
FOPEX  !#attrmatch_codepatch_EIP_00000007_eb ...
```

A larger FOPEX example (`TrojanDropper:Win32/Cutwail.gen!C`) has prefix length
12, body length 25 and offset 42::

    prefix  55 8b 64 8b 25 2d 66 75 a3 8d 51 50
    body    90 02 06 "HeapAlloc" 00 90 03 02 04 ff 15 "SetT" 90 00
    offset  42

Both x86 and x64 FOP forms can be rendered as YARA hex (`??` per literal
wildcard, `[n]` skips for FOPEX tokens), but no generator is wired up.  They
are fingerprints of code that the emulator/unpacker sees, not of the raw
scanned file, so a YARA rule would only be meaningful together with the same
code-extraction context.
