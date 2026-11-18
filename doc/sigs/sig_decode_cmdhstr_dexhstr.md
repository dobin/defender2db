# Decoding `SIGNATURE_TYPE_CMDHSTR_EXT` and `SIGNATURE_TYPE_DEXHSTR_EXT`

Both types are members of the engine's shared **HSTR** family.  They use the
same record container, the same weighted sub-rule model and the same HSTR
wildcard opcodes; only the *thing being searched* differs.  This note covers
the on-disk layout, the engine-side meaning, the sub-rule flag bits, and what
the shipped definitions contain.

Build analysed: x64 `mpengine.dll` 1.1.26100.4, image base `0x180000000`.
Engine anchors are also listed in `cache/functions_vdm.md` §18.

## 1. The HSTR family in mpengine

`FUN_180a1f948` (the HSTR plugin init) builds two families of contexts and
registers the same parser for every member:

* `DAT_181113a90` — kind 0, the PE/file HSTR context (`0x61`, `0x78`, `0x85`).
* `DAT_181114170 + kind * 0x58` — one context per HSTR target kind.

The kind → signature-type table is the 20-byte table at `0x180c8b800`:

| kind | type | member |
|-----:|------|--------|
| 1 | `0x8f` | `MACROHSTR_EXT` |
| 2 | `0x8d` | `MACHOHSTR_EXT` |
| 3 | `0x8c` | `ELFHSTR_EXT` |
| 4 | `0x8e` | `DOSHSTR_EXT` |
| 5 | `0xbe` | **`DEXHSTR_EXT`** |
| 6 | `0xbf` | `JAVAHSTR_EXT` |
| 7 | `0xc5` | `ARHSTR_EXT` |
| 8 | `0xd1` | `SWFHSTR_EXT` |
| 9 | `0xd3` | `AUTOITHSTR_EXT` |
| 10 | `0xd4` | `INNOHSTR_EXT` |
| **11** | **`0xd7`** | **`CMDHSTR_EXT`** |
| 12 | `0xe4` | `MDBHSTR_EXT` |
| 13 | `0xea` | `DMGHSTR_EXT` |
| 14 | `0x92` | `ASCRIPTHSTR_EXT` |
| 15 | `0xef` | `ARHSTR_POSIX_EXT` |
| **16** | **`0xdd`** | **`CMDHSTR_FAST_EXT`** |
| 17 | `0xb9` | `WASMHSTR_EXT` |
| 18 | `0x6d` | `BRUTEHSTR_EXT` |
| 19 | `0x6e` | `SCRIPTBRUTEHSTR_EXT` |

Each kind is registered twice (a normal and a "PE-attached" callback) with its
fixed type byte, and every wrapper calls the same parser:

```
handler(ctx, payload, size, ..., type_byte)   # small thunk, type in stack arg
  -> FUN_180182d14(ctx, payload, size, ..., type_byte)
       -> FUN_180183298(...) per sub-rule        # pattern compiler
       -> FUN_180186b84(...)                     # record/condition registration
```

The runtime matcher is `FUN_180249264(kind, ...)` → `FUN_180047590(...)`.  It
walks the record's pattern chain and compares each pattern against the scan
buffer; HSTR records are therefore **content signatures**, not hashes.

## 2. Common `*HSTR_EXT` record layout

All members use exactly one layout (confirmed by `FUN_180182d14` and by 100 %
walking of every `*HSTR_EXT` record in the shipped database):

```
u16  score_or_flags    usually the total positive weight (and == threshold)
u16  threshold         minimum score (sum of matching sub-rule weights)
u16  rule_numbers      number of sub-rules
u8   name[]            NUL-terminated label, empty in compiled threat records
sub-rule[rule_numbers]:
    i16  weight        positive => score, negative => penalty/exclusion
    u8   size          number of pattern bytes
    u8   flags         bit 0 case-sensitive, bit 1 wildcard pattern,
                       bit 7 extended header
    u8   extra         only when flags & 0x80; bit 0 = also add a
                       terminator-less variant (stored with internal 0x400)
    u8   bytes[size]
u16  tail_word1        optional; engine stores it at record+0x10
u16  tail_word2        optional; engine stores it at record+0x0c
```

`FUN_180184898` (called from the record builder `FUN_1801836c8`) starts at
byte 6, scans up to `0x40` bytes for a NUL and, when a name is present, moves
the sub-rule bytes back over it before hashing the record.  That is the proof
that byte 6 is the name start and not a reserved field.

There is **no explicit terminator word** between the last sub-rule and the
tail words: the engine stops after exactly `rule_numbers` sub-rules and then
optionally reads one or two `u16` values.  The old "`u16 0x0000` end marker"
description was an artefact of records that happen to carry a zero
`tail_word1`.

### Sub-rule flags

`FUN_180183298` and `FUN_180181a7c` give the semantics:

| bit | meaning |
|----:|---------|
| `0x01` | keep the pattern case-sensitive; when clear the engine lower-cases every byte |
| `0x02` | the pattern contains `0x90` HSTR wildcard opcodes and must end with `90 00`; case folding is wildcard-aware (operand bytes are not folded) |
| `0x80` | extended header: one `extra` byte sits between the flags and the pattern |
| extra `0x01` | the engine additionally registers a terminator-less variant of the pattern (internal flag `0x400`) |
| `0x80` on the stored word | set by the engine while compiling when the pattern contains no "loose" `90 1b` token |

The engine rejects a `0x02` pattern that does not end in `90 00`, and it
validates every wildcard token against the 50-entry table at
`0x180c94d50` (same table as `NSCRIPT_BRUTE`).

### Wildcard opcodes (subset)

`90 00` terminates the pattern, `90 90` is an escaped literal `0x90`,
`90 01 NN` skips exactly `NN` bytes and `90 02 NN` skips 0..`NN` bytes.  The
remaining 50 entries are target-specific checks; the ones seen in these two
types are:

| token | meaning (engine behaviour) |
|-------|----------------------------|
| `90 03 count mask_len mask...` | consume `count` input bytes from a byte class; the mask is a list of bytes/ranges (`a-b`) |
| `90 04 repeat len bytes...` | repeat one of the listed bytes `repeat` times (case-sensitive) |
| `90 05 repeat len bytes...` | same, case-insensitive/variable |
| `90 09 NN MM` | engine-specific multi-byte check/limit (operands preserved) |
| `90 17 NN` / `90 19` / `90 1a` | target checks with extra length byte |

The renderer (`decode_hstr_pattern` in `defender/signature/hstr.py`) prints
wildcards as `<skip N>`, `<skip 0..N>`, `<any-of {...} xN>`,
`<repeat N of ...>` and `<op XX ...>`; literal runs are decoded as UTF-16LE,
UTF-8 or latin-1.

## 3. `SIGNATURE_TYPE_CMDHSTR_EXT` (`0xd7`)

### What it is

A **command-line content signature**.  It is not a file hash and not a file
byte pattern: the engine matches it against the command line of a process.
The `cmdlinescan` module (`FUN_180afde40`, module table entry at
`0x180e54b90`) drives the scan:

```
FUN_180554374  MpCmdLineScan
  FUN_180afce70  per-command-line scan/report callback
    FUN_18024af38 -> FUN_180249264(0xb, ...)   kind 11 = CMDHSTR
    FUN_180553cac                              PowerShell base64 decode path
    FUN_180afe204                              extracted/alternate variant
    FUN_1802409b0(0xb, ...)                    final chance / no-cmdline path
```

The same matcher is reached from the task-scheduler and BITS command-line
paths.  The engine's caller ids are `HSTR_CALLER_CMDLINE`,
`HSTR_CALLER_TSKSCHED_CMDLINE` and `HSTR_CALLER_BITS_CMDLINE`
(`0x180c78130` / `0x180c78148` / `0x180c78168`).  `#ClnCmdLine` is the clean
verdict tag and `FUN_180afe8a8` implements the deprecated low-fi reporting
path.  `HSTR_CALLER_*` is also why the same records are reported through
AMSI/process-creation instead of a file scan.

### Payload characteristics

| metric | value |
|--------|------:|
| records in `cache/threats.db` | 5,415 |
| records in real threats | 2,941 (2,737 threats) |
| records in `!InfrastructureShared` | 2,474 |
| sub-rules | 30,142 (average 5.57, max 272) |
| UTF-16LE patterns | 27,848 (92.4 %) |
| ASCII patterns | 2,294 (7.6 %) |
| case-sensitive (flag bit 0) | 399 |
| wildcard patterns (flag bit 1) | 4,074 |
| extended-header sub-rules | 1,661 (all `extra == 1`) |
| negative-weight sub-rules | 2,859 |
| unique payloads | 5,415 |

Real-threat records are anonymous; the `!InfrastructureShared` copies carry a
feed label.  Prefixes: `!#SLF:` 2,060, `!#TEL:` 324, `!#ALF:` 43, `!#HSTR:`
11, `!#CMD:` 11, `!#SLFPER:` 11, `!#TELPER:` 8, and a few one-offs
(`!#AIDiscovery:`, `!#Exclusion:`, `!#Trojan:`, `!#PUA:`).

The `tail_word1` is zero for 5,394 of 5,415 records; 21 records use 1, 2, 5, 6
or 10.  No record has a second tail word.  `score_or_flags` equals `threshold`
in 5,289 of 5,415 records (97.7 %), so the first word is effectively a
duplicated/pre-set score value in this type.

### Examples

`Trojan:Win32/Kovter.G` (14 sub-rules, several negative exclusions):

```
mshta<skip 0..16>javascript:<skip 0..255>new activexobject(
mshta<skip 0..16>vbscript:<skip 0..255>execute(<skip 0..255>getobject(
Wscript.Shell"").Run ""robocopy.exe            (weight -50)
MSHTA.EXE javascript:new ActiveXObject('Scripting.FileSystemObject')...
```

`TrojanDownloader:PowerShell/Falsip.C`:

```
powershell.exe
=$env:temp+[char][byte]92+'15<skip 0..32>.js';(New-Object System.Net.WebClient).DownloadFile(
.jse',$d);Invoke-Item $d;
```

`Trojan:PowerShell/CoinMiner.A`:

```
powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc IEX (New-Object Net.WebClient).DownloadString(
IEX (New-Object Net.WebClient).DownloadString("http://85.204.74.105/<skip 0..255>.css
```

The family distribution confirms the purpose: ClickFix/SuspClickFix,
PowerShell downloaders, proxy/tamper tools and `mshta` launchers dominate.

### `SIGNATURE_TYPE_CMDHSTR_FAST_EXT` (`0xdd`)

Kind 16, same parser and same layout, registered for the fast/low-fi
command-line path.  Only two records exist in the shipped database, both
`Trojan:Linux/FchsE2ETest*` test patterns (`fchs-e2e-blk-<guid>` /
`fchs-e2e-aud-<guid>`).  They decode normally with this parser.

### YARA note

The patterns can be rendered as YARA strings (ASCII or wide hex with `??`
jumps), and the project keeps emitting them like other `*HSTR_EXT` types.
A CMDHSTR rule is meaningful when the YARA scanner is pointed at a command
line, a process-creation log or an in-memory wide string.  It is **not** a
file-content hash and will not match executable bytes in general.  The
`wide`/`ascii` distinction is decided by the pattern bytes; command-line
signatures are predominantly UTF-16LE.

## 4. `SIGNATURE_TYPE_DEXHSTR_EXT` (`0xbe`)

### What it is

The Android/Dalvik member (kind 5).  Patterns are matched against strings in
`classes.dex` / an APK's DEX string table, hence the type name.  The
`string_data_item` of every DEX string is prefixed with a uleb128 length
(usually two bytes), so signatures commonly interleave literals with
`90 01 02` skips:

```
03 "hi,xiaolu"  90 01 02  "hi,liqian"  90 01 02  "command ok"  90 01 02  "bye"  90 00
```

Unlike CMDHSTR the patterns are normally UTF-8/ASCII, and case-sensitive
matching dominates (DEX strings are identifiers).  `90 03` byte classes are
used for obfuscated `com/X`-style package paths.

### Payload characteristics

| metric | value |
|--------|------:|
| records in `cache/threats.db` | 3,053 |
| records in real threats | 2,766 (2,653 threats) |
| records in `!InfrastructureShared` | 287 |
| sub-rules | 16,409 (average 5.37, max 1,023) |
| case-sensitive (flag bit 0) | 10,402 |
| wildcard patterns (flag bit 1) | 526 |
| extended-header sub-rules | 117 (all `extra == 1`) |
| records with a second tail word | 424 |
| unique payloads | 3,053 |

The optional second tail word is the "DEX flags" value described in the
earlier notes.  Values observed: 1..8, 10, 11, 17, 20, 31, 41, 43, 46, with 3
(133), 4 (149) and 5 (63) most common.  It is a small option/scoring word, not
a byte pattern; its exact engine use is not decoded.

### Name-reference records

287 records live in `!InfrastructureShared` and use the name field, e.g.
`!#Tel:Trojan:AndroidOS/Fakecalls.YU`, `!#TEL:Trojan:AndroidOS/Piom.K`,
`!#ALF:Trojan:AndroidOS/...`.  Older parser versions treated these as
"reference only" and discarded the sub-rules.  That was wrong: the sub-rules
follow the NUL and are real DEX patterns, e.g.

```
!#Tel:Trojan:AndroidOS/Fakecalls.YU   -> |*callEntity*|
!#HSTR:AndroidOS/LimtPkg              -> com/limitemp/interstellar/app/
!#PUA:Block:Notifyer.B                -> /MyPushListener, /onejson, strimglink
```

The decoder now keeps them and exposes both `name_reference` and `patterns`.

### Examples

`TrojanSpy:AndroidOS/Geimini.A`:

```
hi,xiaolu<skip 2>hi,liqian<skip 2>command ok<skip 2>bye
AdActivity<op 09 0c00>com<any-of {2e} x1>/geinimi
processDOWNLOAD_FAILUE_Action
```

`TrojanSpy:AndroidOS/Adrd.A`:

```
adrd.xiaxiab.com/pic.aspx?im=<op 09 0700>http://
M032890500170758.mp3
go_g1_sms
```

`TrojanSpy:AndroidOS/DroidDream.A`:

```
DownloadProvidersManager.apk, sqlite.db, /root/AlarmReceiver,
go4root, rageagainstthecage
```

`Trojan:AndroidOS/Denofow.A` is a good demonstration of long string
constants: ten exact sentences such as `Its the Raptures,praise Jebus` and
`Prepare to meet thy maker...` are stored as plain case-sensitive sub-rules.

### YARA note

DEX patterns are normal ASCII/UTF-8 string fragments, so they convert to YARA
text or hex strings cleanly and remain useful against an extracted
`classes.dex` or an APK.  They are not hashes and do not identify the APK
container.  The existing YARA conversion renders `90 03` byte classes as
single-byte alternatives; the engine semantics (consume `count` bytes from a
byte class) are preserved in `decode_hstr_pattern` but are slightly broader in
the generated YARA hex.

## 5. Coverage / validation

Running the decoders over every record of both types in `cache/threats.db`:

| type | records | decoded | sub-rules | errors |
|------|--------:|--------:|----------:|-------:|
| `CMDHSTR_EXT` `0xd7` | 5,415 | 5,415 | 30,142 | 0 |
| `CMDHSTR_FAST_EXT` `0xdd` | 2 | 2 | 6 | 0 |
| `DEXHSTR_EXT` `0xbe` | 3,053 | 3,053 | 16,409 | 0 |

For every record `len(subrules) == rule_numbers`; every wildcard pattern
ends in `90 00`; every extended sub-rule has an `extra` byte.

## 6. Decoder API

`defender2yara/defender/signature/hstr.py`:

* `HStrExtSig` — shared container; exposes `unknown_u16_1`, `threshold`,
  `rule_numbers`, `name`, `tail_words`, `end_marker`, `flags`,
  `flags_present`, `patterns`, and `subrules`.
* `CmdHStrExtSig` — `0xd7` / `0xdd`; adds `scan_target`, `scan_callers`,
  `scan_targets`, `command_line_patterns` and `variant`.
* `DexHStrExtSig` — `0xbe`; adds `name_reference`, `is_name_reference`,
  `dex_patterns` and keeps the sub-rules for named records.
* `decode_hstr_pattern(pattern)` — text renderer; returns `(text, encoding)`.

`defender2yara/defender/subrule/hstr.py` — `HStrExtSubRule` exposes the real
flag bits (`case_sensitive`, `wildcard`, `extended`, `extra`, `variant`), the
correct extended-header offset, and `entry_size` for record walking.

Engine functions are summarised in `cache/functions_vdm.md` §18.
