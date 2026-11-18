# Decoding NSCRIPT_SP, NSCRIPT_BRUTE and MACRO_SOURCE

Follow-up to `cache/sig_type_usage.md`, `doc/sigs/sig_decode_more3.md`,
`doc/sigs/sig_decode_snid_nid64.md` and
`doc/sigs/sig_decode_pestatic_bm_sigtree_ext.md`.

Build analysed: `mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`
(x64, image base `0x180000000`; Ghidra project binary `/mpengine.dll`).

| type | id | records | what it is | decoder |
|------|----|--------:|------------|---------|
| `SIGNATURE_TYPE_NSCRIPT_SP` | `0x28` | 35,753 | compact script hash pair + window length | `defender/signature/nscript.py` (`NscriptSpSig`) |
| `SIGNATURE_TYPE_NSCRIPT_BRUTE` | `0x29` | 147,714 | literal script string with HSTR wildcards + script type / anchor | `nscript.py` (`NscriptBruteSig`) |
| `SIGNATURE_TYPE_MACRO_SOURCE` | `0x43` | 16,210 | ordered sequence of normalised macro / VBA routine hashes | `defender/signature/macro_source.py` (`MacroSourceSig`) |

All 199,677 records of these three types in `cache/threats.db` decode and
consume their payload exactly, with zero errors and zero warnings:

| type | total | decoded | in real threats | in `!InfrastructureShared` |
|------|------:|--------:|----------------:|---------------------------:|
| `NSCRIPT_SP` | 35,753 | 35,753 | 35,154 | 599 (named) |
| `NSCRIPT_BRUTE` | 147,714 | 147,714 | 32,738 | 114,976 (all named) |
| `MACRO_SOURCE` | 16,210 | 16,210 | 16,158 | 52 (named) |

None of the three types contains a threat name or a file hash. They are
**content signatures for scripts and macro source**, evaluated by the script
and macro engines after the input has been decoded/normalised.

---

## 1. The `nscript` module (0x27/0x28/0x29)

The module entry is `nscript` (`0x180e78388`) in the module table at
`0x180e56950`; its init is `FUN_180a65d00`.

| Address | Function / role |
|--------:|-----------------|
| `0x180a65d00` | `nscript` module init |
| `0x180180ef0` | handler for `0x27` (`NSCRIPT_NORMAL`), wrapper for `FUN_180180f0c` |
| `0x180181720` | handler for `0x28` (`NSCRIPT_SP`) |
| `0x1803f8320` | handler for `0x29` (`NSCRIPT_BRUTE`), wrapper for `FUN_1803f8348` |
| `0x1804a8fb0` | handler for `0x2c` (`NSCRIPT_CURE`) |
| `0x1801b8e40` | handler for `0x90` |
| `0x180a68540` | handler for `0xca` |
| `0x180180f0c` | shared `0x27`/`0x28` condition parser |
| `0x1803f8348` | `0x29` parser / condition builder |
| `0x1801836c8` | record id: `crc32(normalised payload) \| type << 32 \| size << 40` |
| `0x180184898` | payload normaliser; for `0x27`/`0x28`/`0x29`/`0x43` it strips the inline name |
| `0x180186df4` | xxHash32-based intern table (`data -> id`) |
| `0x180186a20` | id -> interned record (0x10-byte slot lookup) |
| `0x180186b84` | condition record builder (`id, name id, 20-byte digest`) |
| `0x18018054c` | condition matcher: resolve id, walk hit counters |
| `0x180180a84` | condition evaluator for one script hash |
| `0x18017f460` | script scanner: maintains the per-script 0x1000-byte ring buffer |
| `0x18017efc8` | reverse rolling-CRC32 window matcher over `DAT_181106a18` |
| `0x18017f9e0` | compiled script-condition program interpreter |
| `0x1801801d4` / `0x1801803f8` | sorted lookups in `DAT_181106a20` / `DAT_181106a18` |
| `0x180a685b0` / `0x180a68610` | commit/sort callbacks for the condition vectors |
| `0x180550330` | `NSCRIPT_BRUTE` table matcher |
| `0x180148f08` | wrapper that runs the matcher for both brute tables |
| `0x180149030` | script-scan driver (also handles filename-keyed brute records) |
| `0x1801b25b8` | pattern search (compiled with `0x1801b2778`) |
| `0x180c94d50` | 50-entry wildcard opcode length table |
| `0x180f130d0` | `Nscript:Type_*` script-type name table |

### Who consumes what

The engine converts each record into an in-memory vector:

* `NSCRIPT_NORMAL` (`0x27`) → `DAT_181106a20`, 0x10-byte entries
  `{hash1, hash2, condition_id, name_count_id}` (plus `DAT_181106a18`,
  0x14-byte entries `{value, window_length, crc32, condition_id, flags}` for
  the "length + hash" form).
* `NSCRIPT_SP` (`0x28`) → `DAT_181106a00`, 0x14-byte entries
  `{hash1, match_length, hash2, condition_id, flags}`.
* `NSCRIPT_BRUTE` (`0x29`) → `DAT_1811148b8` / `DAT_1811148e8`, 0x10-byte
  entries `{pattern_length, condition_id, any_length, pattern_length16,
  any_length16, flags}` with the pattern bytes stored in a side vector.

The script scanner (`FUN_18017f460`) normalises script text into 0x1000-byte
windows and computes a continued rolling CRC32 plus a fresh CRC32/CRC16 for
each fragment (`FUN_1806768a4`, `FUN_1806761e8`).  Conditions are compared
against those values; a hit becomes a signature/feature via `FUN_18015dde0`.
That is why the numbers in these records are hashes and not readable data.

---

## 2. `SIGNATURE_TYPE_NSCRIPT_BRUTE` (`0x29`)

This is the readable one: a normalised script fragment with wildcards.

### Layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 1 | `name_len` | 0..0x3f; 0 = no inline name |
| `0x01` | n | `name` | engine list/reference label (see below), not the threat name |
| `1+n` | 1 | `kind_and_flag` | bits 0..6 script type, bit 7 extra flag |
| `2+n` | 1 | `mode` | search direction / anchoring (0..2) |
| `3+n` | 4 | `any_length` | low 16 bits; `0xffffffff` = unset |
| `7+n` | 4 | `pattern_length` | bytes that follow (1..0xffff) |
| `11+n` | k | `pattern` | literal text plus `0x90` wildcard tokens, ends `90 00` |

The record is exactly `11 + name_len + pattern_length` bytes; all 147,714
records consume their payload exactly and all patterns end with `90 00`.

### Script type (`kind_and_flag`)

The low 7 bits are a one-based index into the `Nscript:Type_*` table at
`0x180f130d0` (`0x180f125e0` = `Nscript:Type_vbs`, then js, bat, irc, ps, py).
The engine maps it to an internal enum 0..6 and stores it in bits 7..9 of its
flag word; 6 means "any script type" (`(kind >> 7 & 7) == 6` is the wildcard
branch in `FUN_180550330`).

| byte & 0x7f | internal | type | records |
|------------:|---------:|------|--------:|
| 1 | 0 | `vbs` | 5,203 |
| 2 | 1 | `js` | 11,405 |
| 3 | 2 | `bat` | 1,542 |
| 4 | 3 | `irc` | 69 |
| 5 | 4 | `ps` | 5,335 |
| 6 | 5 | `py` | 1,200 |
| 0 or 7 | 6 | `any` | 122,960 |

83% of the database is script-type agnostic.  The high bit adds `0x0400` to
the engine flag word; 371 records set it.  Its meaning was not identified; it
is preserved as `kind_high_flag`.

### Mode

`mode` selects the search strategy: 1 scans forward from the start, 2 scans
backward from the end, 0 does not anchor the match.  In the database:
`0` = 128,164, `2` = 10,045, `1` = 9,505.  The engine also has two internal
bits here (`0x1000`/`0x2000` and a 5-bit distance in bits 0..4) that are never
set by compiled signatures; they are not present on disk.

### `any_length`

A limit passed to the pattern matcher, most likely the maximum amount consumed
by `90 02` variable skips.  147,320 records store `0xffffffff` (unbounded);
the rest are small (0, 1, 10, 20, 30, 60, 100, 200, 300, 512, ...).

### Pattern and wildcards

Pattern bytes are a normalised fragment of the script: lower case, whitespace
removed, punctuation kept.  The `0x90` escape table (`0x180c94d50`, 50 tokens)
gives the length of every token; the most important ones are the same HSTR
wildcards used by `PEHSTR_EXT`:

| token | meaning |
|-------|---------|
| `90 00` | NUL byte; in practice the string terminator |
| `90 01 XX` | skip exactly `XX` bytes |
| `90 02 XX` | skip 0..`XX` bytes |
| `90 1b ...` | loose/variable token; clears the engine "contiguous" bit `0x0800` |
| other `90 NN` | engine opcode; rendered as `<op NN ...>` with its table-defined operands |

`90 1b` occurs 14,174 times.  The engine stores `0x0800` in its flag word when
no loose token is present.  `decode_script_pattern()` renders all tokens and
escapes NUL/control bytes, so its output is safe to print.

Real examples from `cache/threats.db`:

```
Trojan:HTML/Webber.A
  <imgwidth=50height=100style="display:none"><skip 0..19>
  <objectdata="http://www.oil-bank.ru/cgi-bin/<skip 7>counter.cgi?action=click">

Worm:DOS/Crack.B  (irc)
  /msg#gigaviriii'mwideawakeinmykitchen,it'sdarkandi'mlonely,...

Worm:Win32/Bagle.O
  <html><body><fontface="system"><objectstyle="display:none"
  data="http://<skip 0..3>.<skip 0..3>.<skip 0..3>.<skip 0..3>:81/<skip 0..8>.php"

Worm:Win32/Netsky.V
  cmd.exe/cechooff&echoopen<skip 0..3>.<skip 0..3>.<skip 0..3>.<skip 0..3>5556
```

### Names

32,738 records belong to real threats (anonymous).  The other 114,976 live in
`!InfrastructureShared` and carry a reference label such as
`!#SCPT:Trojan:JS/NPMInstall.PR!AMTB` (942 uses), `!#JSON:Claw_BadSkill_VT`
(555), `!#SCPT:FakeLogin.B21.0618!atmn` (259); 94,272 distinct labels.  The
label names the shared list/definition, not the target threat.

### Why it is useful

Unlike the hash forms, `NSCRIPT_BRUTE` gives the actual matched script text,
so it can be emitted as a YARA string (with the wildcard opcodes mapped to
`??`/`[0-N]`).  It is also the type that reveals what "normalised script"
looks like to the engine (lower case, no whitespace).

---

## 3. `SIGNATURE_TYPE_NSCRIPT_SP` (`0x28`)

`SP` is the compact hash form of a script condition: two script hashes plus the
length of the window they cover.  It is parsed by `FUN_180181720`.

### Layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 1 | `name_len` | 0..0x3f; 0 = anonymous |
| `0x01` | n | `name` | engine list/reference label |
| `1+n` | 4 | `hash1` | first script hash |
| `5+n` | 1 | `flags` | bit 7 separate flag, low bits 0..4 observed |
| `6+n` | 4 | `hash2` | second script hash |
| `10+n` | 4 | `match_length` | script window length, 1..0x1000 |

The record is exactly `14 + name_len` bytes.  The engine stores the vector
entry as `{hash1, match_length, hash2, condition_id, flags}`
(`FUN_180181720`), i.e. `match_length` is the secondary sort key between the
two hashes.

`match_length` is never zero in the database, ranges from 23 to 0x1000 and is
clamped at 0x1000 (the engine's per-script ring-buffer size); 1,184 records use
exactly `0x1000`, which is the signature of a clamped length.  3,965 records
have a length below 0x100.

`flags` low values: `3` (23,566), `4` (9,583), `2` (932), `0` (896), `1`
(755), `0x83` (4), `0x84` (17).  Values 1 and 2 trigger a legacy special case
in `FUN_180181720`: when the referenced name contains `:IRC/`, the engine
synthesises an `NSCRIPT_NORMAL` record from `{name, hash2, flags, hash1,
match_length}`.  Bit `0x80` is preserved as an extra bit in the in-memory flag
word.  No further meaning could be assigned to the low bits with confidence;
they are exposed verbatim.

### Why it cannot be rendered

Both dwords are hashes computed by the script normaliser, not text.  The record
also does not store the wildcard/anchoring information of `NSCRIPT_BRUTE`; it
is the compiler's compact form for the common "two adjacent script fragments"
condition.  It can be decoded and counted, but not converted into YARA text.

599 records are named, with 484 distinct labels, mostly `!#TEL:`, `!#SCPT:` and
`!#SCRIPT:` feeds, e.g. `!#TEL:HTML/CoinHive.C!lib`,
`!#SCPT:O97M/CVE-2012-0158.RA!MTB`, `!#SCRIPT:Backdoor:Win32/AluminumApt!lowfi`.

### Related `NSCRIPT_NORMAL` (`0x27`) and `NSCRIPT_CURE` (`0x2c`)

`0x27` uses the same building blocks and is now fully decoded in
`doc/sigs/sig_decode_ck_nscript_normal.md` §4.  It is the general container for
one or more script conditions:

```
u8  name_len; u8 name[name_len]
u8  count
u32 hash_a[count]
u8  flags                  0 = hash-pair form, != 0 = window + hash-pair form

flags == 0:  u32 hash_b[count]              each hash is paired
flags != 0:  u32 hash1, u32 match_length    first condition: rolling window
             u32 hash_b[count]              optional, hash_b[0] reserved
optional:    u32 weight                     only the low byte is used
```

`hash1`/`match_length`/`hash_a[0]` in the window form are exactly
`NSCRIPT_SP`'s `hash1`/`match_length`/`hash2`, and `flags` low values 1/2 carry
the same legacy `:IRC/` case.  Real threats contribute 9,775 records; the 11
compact records omit `hash_b` entirely.  The decoder is `NscriptNormalSig` in
`defender/signature/nscript.py`.

`0x2c` (`NSCRIPT_CURE`) records use a different, bytecode-like payload
(e.g. `05 e4 ff a7 88 00 00 00 00 02 00 00 00 0d 0a`) and are not handled.

---

## 4. `SIGNATURE_TYPE_MACRO_SOURCE` (`0x43`)

`MACRO_SOURCE` is the macro/VBA counterpart of `NSCRIPT_BRUTE`, but the actual
source text is already reduced to per-routine hashes.  The `macro` module
(`0x180e78380`, init `FUN_180a50370`) registers the handler
`FUN_1801d35d0` for `0x43` (and `0x42`/`0xcf` for macro p-code).

### Layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 1 | `name_len` | 0..0x3f |
| `0x01` | n | `name` | engine list/reference label |
| `1+n` | 4 | `header` | bits 0..5 routine count, bits 6+ source kind |
| `5+n` | 4·count | `hash_low[]` | low dword of each 64-bit routine key |
| `5+n+4·count` | 4·count | `hash_high[]` | optional high dwords, all after the low array |

The high array is all-or-nothing; 7,000 records omit it (then every high dword
is zero) and 9,210 include it.  The record is exactly
`5 + name_len + 4·count` or `5 + name_len + 8·count` bytes.

`count` is 1..0x3f; the largest record in the shipped database has 50
routines.  The database contains 27,655 routine keys in 16,210 records.

### Source kind (`header >> 6`)

The loader compares this value for equality against the stream that produced
the keys (`FUN_18024dc90`), so it is an enum, not a bitmask:

| value | engine stream | label | records |
|------:|---------------|-------|--------:|
| 0 | Word 6 (`+0x6048`) / Excel 5 (`+0x5040`) | `word6_excel5_macro_source` | 3,078 |
| 2 | Excel formula (`+0x8048`) | `excel_formula` | 15 |
| 4 | VBA source (`+0xa048`) + VBA p-code (`+0xb050`) | `vba_source` | 9,074 |
| 8 | Excel formula routines (`+0x2da70`, `xfcrcs`) | `excel_formula_routines` | 4,043 |

The diagnostic strings in `FUN_1802f7e98` name the streams:
`MpWord6Routines`, `MpExcel5Routines`, `MpExcelFormulaRoutines`,
`MpVBASourceRoutines`, `MpVBAPCodeRoutines`; the Excel-formula routine list is
dumped as `MpInternal_researchdata=xfcrcs=0x...`.

### Matching

`FUN_1802f7e98` walks the five/six macro streams and calls
`FUN_1802f81bc(ctx, kind, stream, count)` with an array of 8-byte routine keys.
`FUN_1802f81bc` looks each key up in a global map (`DAT_1811069c8`); a hit
points at the records that require it.  `FUN_18024dc90` then walks the
record's `routine_keys` **in order** and requires each key to occur later in
the stream (`FUN_18024dc64` compares one key).  So a `MACRO_SOURCE` record is
an ordered sequence of normalised macro routines — a structural family
signature, not a byte pattern.

### Keys

Each key is two dwords (low array, then optional high array).  For legacy
Word 6 / Excel 5 records the high half is almost always zero (2 of 10,447
keys are non-zero); for VBA 7,932 keys carry a high dword and for Excel
formulas all keys do.  The exact per-routine normalisation is internal to the
macro parser; the keys are exposed as 16-hex strings, e.g.
`2aaad95be14561fd`.  Do not interpret them as a file hash.

Examples:

```
Trojan:WM/Nikita.A   word6_excel5_macro_source  2 routines
Virus:W97M/ColdApe   vba_source                 1 routine
Virus:XM/Delta.A     word6_excel5_macro_source  1 routine
```

### Names

52 records are named (33 labels), all `!InfrastructureShared` feeds:
`!#SSF:ScanAllStreams`, `!#ALF:SpikeAex.xfcrcs`,
`!#SLF:Trojan:Win32/NeoHash.macrosrc`, `!#Mcrosrc:Qakbot.SS1!MTB`,
`!#ASRWin32ApiMacroExclusion`, etc.  These are exclusions, telemetry and
feature gates, not detections.

---

## 5. Coverage

| type | records | decoded | named | notes |
|------|--------:|--------:|------:|-------|
| `NSCRIPT_SP` `0x28` | 35,753 | 35,753 | 599 | anonymous in real threats |
| `NSCRIPT_BRUTE` `0x29` | 147,714 | 147,714 | 114,976 | all names in `!InfrastructureShared` |
| `MACRO_SOURCE` `0x43` | 16,210 | 16,210 | 52 | all names in `!InfrastructureShared` |

The decoders are wired into `Vdm.decode_record`.  `NSCRIPT_BRUTE` exposes the
readable pattern (`pattern_text`), script type, mode, limits and opcode counts.
`NSCRIPT_SP` exposes both hashes, the window length and flags.
`MACRO_SOURCE` exposes the source kind and the 64-bit routine key list.

Only `NSCRIPT_BRUTE` is directly usable for YARA output; the other two are
hash/structure forms and are decoded for analysis, statistics and UI display.

## 6. Quick re-discovery hints

- **Module entry**: `nscript` / `macro` name pointers in the module table at
  `0x180e56950`; `FUN_18018152c(entry, 0x30, 0xc)` registers each record
  handler and its type byte.
- **On-disk form**: `FUN_180217edc` builds every TLV; the nscript/macro
  handlers do not call it directly (they build ids with `FUN_180186b84`), but
  `FUN_1801836c8` shows the packed record-id formula and
  `FUN_180184898` shows how the name prefix is stripped first.
- **Pattern semantics**: start at `0x180c94d50` (token lengths) and
  `FUN_1801b2778` (pattern compiler).
- **Script type enum**: the `Nscript:Type_*` string table at `0x180f130d0`.
- **Macro routine streams**: `FUN_1802f7e98` and the `Mp*Routines` strings.
