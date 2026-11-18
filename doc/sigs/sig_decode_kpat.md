# KPAT (`0xbb`) and KPATEX (`0xbc`): 8-byte-anchored byte patterns

`SIGNATURE_TYPE_KPAT` (`0xbb`) and `SIGNATURE_TYPE_KPATEX` (`0xbc`) are
Defender's **generic key patterns**.  A record is a real byte pattern, not a
hash, a reference, an expression or a path.  The engine matches it with a fast
multi-pattern scanner over arbitrary buffers: boot sectors / MBR / VBR, memory
and emulation buffers, decompressed data and the VBA macro reader all call the
same verifier.

Both types share one layout.  They differ only in how the part of the pattern
after the first eight bytes is encoded:

* `KPAT` (`0xbb`) - plain bytes with a single-byte wildcard.
* `KPATEX` (`0xbc`) - the engine's `0x90` wildcard opcode language, i.e. the
  same pattern language as the `*HSTR_EXT` family.

The 8-byte prefix is a **literal anchor**: the engine indexes the pattern by
those eight bytes in an Aho-Corasick matcher and only then verifies the tail.
This is why the payload stores the prefix separately from the tail instead of
keeping one flat pattern.

## Payload layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 1 | `pattern_length` | total pattern length (`8 + len(tail)`); 9..197 observed |
| `0x01` | 8 | `anchor` | literal first 8 bytes, also the Aho-Corasick index key |
| `0x09` | `pattern_length - 8` | `tail` | remainder of the pattern |
| `...` | 1 | `name_length` | optional; absent means anonymous |
| `...` | `name_length` | `name` | optional label, **not** NUL terminated |

All shipped records consume their payload exactly (331 of 331).  The optional
name is a length-prefixed byte string without a terminator; if a record instead
ends with a NUL byte it is stripped from the display name.

The loader is not a dedicated parser.  `FUN_180a1f948` (the HSTR module init)
registers both types through the generic "template record" machinery
(`FUN_1804eae94`).  The KPAT/KPATEX field template at VA `0x180f07500` is:

| template op | destination | effect |
|-------------|-------------|--------|
| `0x1007` | `entry+0x10` | read `u8`, store `value - 8` as the tail length |
| `0x2008` | `entry+0x00` | copy 8 bytes (the anchor) |
| `0x1008` | `entry+0x0c` | intern `value - 8` bytes (the tail) |
| `0x1016` | `entry+0x08` | build the condition id and consume the optional name |

The generic template interpreter is `FUN_180181cc4`, dispatched from
`FUN_1801835fc` / `FUN_180183894`.  `0x1016` reads `u8 name_length` followed by
that many bytes; opcode `0x1017` is the NUL-terminated variant used by other
types.

## `KPAT` (`0xbb`) - literal pattern with a 0x90 wildcard

The verifier `FUN_1800fa880` finds the 8-byte anchor with the Aho-Corasick
matcher (`FUN_180047200`) and then compares the tail byte by byte:

```c
pattern_byte = tail[i];
if (buffer[pos + 1 + i] != pattern_byte && pattern_byte != 0x90)
    no_match;
```

So in a `KPAT` record:

* the anchor is literal, even if it contains `0x90`;
* a `0x90` byte in the tail matches **any single byte**;
* `0x00` in the tail is a literal NUL, not a terminator.

`KPAT` tails are mostly 16-bit boot code / DOS virus code, plus a few text or
key-material patterns.  Examples:

```
Virus:DOS/Rex.1637
  b8 01 03 bb 00 06 b9 01 00 ba 80 00 cd 13 be be 07 80 3c 80 74 05 83 c6

Virus:DOS/AOS
  b8 21 35 cd 21 3e 89 9e ?? ?? 3e 8c 86 ?? ?? 0e 58 48 8e c0 ...
  (10 single-byte wildcards)

!#KPAT:PDF_Subtype
  %PDF-1.4\x0a%\xe2\xe3\xcf\xd3\x0a1 0 obj<</Subtype/Text/Contents(
```

Because `0x90` is the wildcard marker, a `KPAT` tail cannot force a literal
`0x90` byte; that is exactly why the extended form exists.

## `KPATEX` (`0xbc`) - extended pattern

The tail is a string in the engine's `0x90` wildcard language.  The loader
validates it with `FUN_1802b1974`: the pattern must be at least two bytes long,
must end with `90 00`, every token must be valid, and the validator also
records whether a "loose" token (`90 1b`) is present.

| token | meaning |
|-------|---------|
| `90 00` | end of pattern (required terminator) |
| `90 01 n` | skip exactly `n` bytes |
| `90 02 n` | skip `0..n` bytes |
| `90 03 <consume> <mask_len> <mask...>` | byte class; `consume` bytes each match one mask entry, ranges are written `lo 2d hi` |
| `90 04 n <len> <bytes>` | repeat the sub-pattern `n` times |
| `90 05 n <len> <bytes>` | repeat the sub-pattern `0..n` times |
| `90 90` | literal `0x90` |
| `90 1b` | "loose" token (clears the contiguous/`0x0800` flag) |
| other `90 xx` | other entries of the 50-entry table at `0x180c94d50` |

The verifier calls the wildcard matcher `FUN_180049320` for that tail instead
of doing the byte compare.  `KPATEX` is heavily used for SWF/ActionScript
bytecode, `autorun.inf` text and shellcode, where variable-length fields and
byte classes are needed:

```
Worm:Win32/Autorun!inf
  0d 0a 5b 41 75 54 6f 72 75 6e 5d [0-255] 0d 0a 61 63 74 69 4f 4e 3d
  "\r\n[Autorun]"  skip 0..255  "\r\n" "actiON="

!#KPAT:SWF/Obfuscator.SafeStr.A
  5f 53 61 66 65 53 74 72 5f   ->  "_SafeStr_"

!#SLFPER:KPAT:CobBeacon.A
  fc 48 83 e4 f0 eb 33 5d 8b [37] 74 02 eb e7
  ->  "\xfcH\x83\xe4\xf0\xeb3]\x8b"  skip 37  "\x74\x02\xeb\xe7"
```

## Matching and table registration

`FUN_180a1f948` creates one `kpat` matcher context (`DAT_181115ca8`, 0x80
bytes, ASCII tag `kpat` at `+8`) and two pattern tables:

| table | record type | element size | commit callback |
|-------|-------------|-------------:|-----------------|
| `DAT_181115ca0` | `0xbb` (`0x4bb` registration id) | `0x14` | `FUN_1802b0940` |
| `DAT_181115c90` | `0xbc` (`0x4bc` registration id) | `0x14` | `FUN_1802b0940` |

Runtime entries are 20 bytes:

```
+0x00  u64  first 8 pattern bytes (the matcher copies/rotates them)
+0x08  u32  condition id
+0x0c  u32  interned tail-pattern id
+0x10  u16  tail length (pattern_length - 8)
+0x12  u8   wildcard variant: 2 normally, 0 when a 90 1b loose token is present
```

The commit callback resolves the interned tail, validates KPATEX patterns with
`FUN_1802b1974`, and adds each anchor/tail to the multi-pattern matcher
(`FUN_1801b6ce4`).  `KPAT` entries are registered with a positive table index;
`KPATEX` entries use `index | 0x80000000`.  In `FUN_1800fa880` the sign of the
matched index therefore selects the table and the verifier.

The same verifier is called from several scan paths:

| address | scan path |
|--------:|-----------|
| `FUN_1800fca80` | boot-sector scan callback (calls `FUN_1800fa68c`, `FUN_1800fb080`) |
| `FUN_1800f95a0` | MBR/VBR scan: walks `0x800`-aligned boot sectors up to 0x40000 bytes and checks `Standard` / `JeB DB` / `ACE DB` structures |
| `FUN_1800fb080` | boot memory-stealth check (`MpDTBoot_MemoryStealth`) |
| `FUN_1800f8a08` | memory / generated buffer (`ctx+0x530`) |
| `FUN_180a52af4`, `FUN_1802fa704` | VBA macro module data |
| `FUN_180a62250` | decompressed buffer |

## Names are aggregator reference labels

The optional name is only present in `!InfrastructureShared`.  It is the group
label an aggregator uses, written as `!#KPAT:<label>` in the shared record and
referenced as `KPAT:<label>` in the expression:

```
KPAT:Trojan:Win32/Meterpreter.HashFunc &
KPAT:Trojan:Win32/Meterpreter.LoadDLL &
KPAT:Trojan:Win32/Meterpreter.code3
```

`KPATEX:frame1_charCodeAt&KPAT:1x1_framerate_24_count_1` is another example.
Real-threat records are anonymous because an aggregator addresses those through
their owner, e.g. `KPATEX:Worm:INF/Autorun.A`.

Nine distinct `KPAT` labels and 31 distinct `KPATEX` / feed labels appear in the
shared bucket; 28 aggregator references name `KPAT` groups and 2 name `KPATEX`
groups.

## Coverage in `cache/threats.db`

| metric | `KPAT` `0xbb` | `KPATEX` `0xbc` |
|--------|--------------:|----------------:|
| records | 208 | 123 |
| real-threat records (threats) | 183 (178) | 82 (71) |
| `!InfrastructureShared` records | 25 (all named) | 41 (all named) |
| distinct names | 9 | 31 |
| pattern length min / median / max | 9 / 36 / 197 | 11 / 43 / 201 |
| tails containing a `0x90` wildcard byte | 45 | 123 (all, terminator included) |
| patterns that are mostly printable text | 38 | 35 |

`KPATEX` opcode distribution over the shipped records: `90 00` terminator 124,
`90 01` skip 147, `90 02` skip-range 17, `90 03` byte class 33, `90 04` repeat 3,
`90 05` 0, `90 90` literal 7, and 9 tokens from the remaining opcode table.

## YARA expressibility

Both types are byte patterns, so they are expressible in YARA hex strings:
`??` for `KPAT` wildcards, `[n]` / `[0-n]` for skips, `( aa | bb )` groups for
byte classes.  The decoder renders `pattern_hex` in that shape but does not
emit rules; the engine's unusual anchor split (literal first 8 bytes plus a
validated tail) is an optimisation and does not need to be reproduced.

## Parser

`defender2yara/defender/signature/kpat.py`:

* `KpatSig` (`0xbb`) - exposes `pattern_length`, `anchor`, `tail`, `pattern`,
  `pattern_hex`, `pattern_text`, `text_like`, `wildcard_count` and the name.
* `KpatExSig` (`0xbc`) - the same plus `opcode_counts`.
* `decode_kpat_hex()` / `decode_kpatex_hex()` / `decode_kpat_text()`.
* `iter_key_pattern_opcodes()` walks the shared `0x90` opcode table.

Wired into `Vdm.decode_record`; tests in `tests/test_signature_kpat.py`.
All 331 records in `cache/threats.db` decode with zero warnings.
