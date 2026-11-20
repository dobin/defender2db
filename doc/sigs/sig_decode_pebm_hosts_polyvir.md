# PEB patterns, hosts-file entries and POLYVIR32

Reverse-engineering notes for the last three raw-only types in the shipped
database:

| type | id | payload | what it is |
|------|----|--------:|------------|
| `SIGNATURE_TYPE_PEBMPAT` | `0x95` | `u8 flags, u8 name_len, u16 len, name, pattern` | PEB/memory code pattern with `90` wildcards |
| `SIGNATURE_TYPE_HOSTSENTRY` | `0x64` | two `u8 len + NUL string` fields | one `hosts`-file line (address + host) |
| `SIGNATURE_TYPE_POLYVIR32` | `0x21` | 34 B template record | 16-byte code anchor + two CRC-32 windows |

Engine build: x64 `mpengine.dll` 1.1.26100.4 (base `0x180000000`).  Function
notes were added to `cache/functions_vdm.md` section 24.

Decoders:

* `PebmPatSig` in `defender2yara/defender/signature/pebmpat.py`
* `HostsEntrySig` in `defender2yara/defender/signature/hostsentry.py`
* `Polyvir32Sig` in `defender2yara/defender/signature/polyvir32.py`

Wired into `Vdm.decode_record`; tests in
`tests/test_signature_pebm_hosts_polyvir.py`.  All 2,711 `PEBMPAT`, 204
`HOSTSENTRY` and 151 `POLYVIR32` records in `cache/threats.db` decode with zero
errors and zero warnings.

---

## 1. `SIGNATURE_TYPE_PEBMPAT` (`0x95`)

### What it is

`PEBMPAT` is the emulator/memory counterpart of `FOP`/`FOPEX`: a literal code
fragment plus the shared `0x90` wildcard language, matched in the emulated
PEB and other PE/memory structures rather than at a file offset.  It is not a
file hash.

The name is slightly misleading.  The parser is effectively a specialised
`FOP` parser: the payload layout is the same as `FOP` (flags / name length /
pattern length / name / pattern), only the scan target and the registration
differ.  The pattern language is the `FOPEX`/`HSTR` language, not the literal
FOP byte string.

### On-disk layout

```
u8   flags                  bit 0 = hit/report class; engine rejects 0xfe
u8   name_length            0 = anonymous
u16  pattern_length
u8   name[name_length]      feed/aggregator label, not NUL terminated
u8   pattern[pattern_length] literal code + 90 wildcard tokens
                            always ends with 90 00
```

`FUN_1802b0c10` enforces:

* `payload_size >= 5` and `flags & 0xfe == 0`;
* the exact total length `4 + name_length + pattern_length`;
* at least four literal bytes before the first `0x90` token (and within the
  first eight pattern bytes — this is the multi-pattern anchor);
* the pattern is validated with `FUN_1802b1974`, the same wildcard validator
  used by `KPATEX`/`FOPEX`.

The record id is `crc32(payload) | 0x95 << 32 | size << 40` (built by
`FUN_1801836c8`).  The optional name is not part of the id.

### Registration and matching

The handler is a static 0x30-byte descriptor at `PTR_FUN_1810d4af0`:

```
+0x00  FUN_1802b0c10   parser
+0x10  0x95            signature type
+0x18  FUN_180b60d90   flush/validate callback
```

The `PEBMPat` module entry (`0x180e60e48`, name at `0x180f5a170`) installs it
from `FUN_1804f4e80`.  `FUN_180b60d90` calls `FUN_180141890` (flush the
Aho-Corasick matcher) and `FUN_180b60e40` destroys the context.  The name list
is walked by `FUN_180b60e90` (`FUN_180157248` → `FUN_18015a450`).

Matching is driven by `FUN_1801176e0`:

* the pattern is inserted into a multi-pattern matcher
  (`DAT_1811240d0`, built by `FUN_1801416bc` / `FUN_18016d360`);
* the driver feeds bytes from the scan object, walks the trie
  (`FUN_180047200`-style transition logic) and verifies each candidate with
  `FUN_1801167ac`;
* a verified hit is emitted with the flag bit stored at entry `+0x14`; the
  report class is `1` or `2` depending on bit 0 of the record flags;
* the engine strings `GetPEBAddress` / "GetPEBAddress should only be called
  from SMS scans" confirm that this path is used by the sandbox/memory scan.

### Pattern encoding and examples

The pattern is normalised code (x86/x64 or emulated API stubs) with the shared
`90` tokens:

| token | meaning |
|------:|---------|
| `90 00` | terminator (always present) |
| `90 01 n` | skip exactly `n` bytes |
| `90 02 n` | skip 0..`n` bytes |
| `90 03` | byte class |
| `90 04` / `90 05` | repeat |
| `90 90` | literal `0x90` |

The decoder renders the bytes with `decode_kpatex_hex` and the text with
`decode_hstr_pattern`.  Examples:

```
Trojan:Win32/Zlob.DI
  anchor  55 8b ec 83 c4 c0 81 e8
  len     102
  pattern 55 8b ec 83 c4 c0 81 e8 7e 22 40 00 72 06 81 e3
          8d 1f 40 00 81 e3 58 1d 40 00 2b d2 68 42 51 42
          00 5f be aa ff ff ff 66 01 37 66 83 07 2c 81 e8
          81 2e 40 00 72 06 81 e3 ee 11 40 00 ...
```

Named infrastructure records carry the aggregator/feed label, for example:

```
!#PEBMPAT:VirTool:Win32/Obfuscator.ACV!EP
!#PEBMPAT:lua_codepatch_ursnif_32
!#PEBMPAT:Deep_Analysis_Disable_APILimit
!#attrmatch_codepatch_EIP_00000008_0000
!#attrmatch_rescan_psif
!FakeXPA_Obfuscator
```

The dominant use is code-patch / emulator conditions (`codepatch_EIP_*`,
`rescan_psif`, `Deep_Analysis`, `sehjump`), i.e. the same kind of logic as
`FOPEX` but applied to the PEB and emulated memory structures.

### Coverage

| metric | value |
|--------|------:|
| records | 2,711 |
| real-threat records (352 threats) | 955 |
| named infrastructure records | 1,756 (1,109 labels) |
| flags 0 / 1 | 2,645 / 66 |
| pattern length | 6..177 (median 33) |
| patterns ending `90 00` | 2,711 (100%) |
| patterns with a wildcard token | 1,803 |
| top owners | `BrowserModifier:Win32/Soctuseer` (24), `!#PEBMPAT:Deep_Analysis` (49) |

Top real-threat owners are browser modifiers and obfuscated droppers
(`Soctuseer`, `Obfuscator.*`, `CeeInject`, `Upatre`, `Patched`, `Sality`,
`Tracur`, `Zlob`); the shared records are the code-patch/AI-analysis library.

Because the pattern is matched in emulated memory (PEB, unpacked buffers), it
is not directly convertible into a YARA file rule.  The decoder exposes the
anchor and wildcard rendering for tooling, not rule generation.

---

## 2. `SIGNATURE_TYPE_HOSTSENTRY` (`0x64`)

### What it is

A **single line of the Windows `hosts` file**: a mapped address plus a host
name.  The engine parses the `hosts` file during the `VFS:hosts` scan and
reports `SettingsModifier:Win32/HostsFileHijack` when a line matches a stored
condition.  It is a configuration/network condition, not a file-byte pattern.

### On-disk layout

```
u8  address_length          includes the trailing NUL, must be > 1
u8  address[address_length]
u8  host_length             includes the trailing NUL, must be > 1
u8  host[host_length]
```

Both strings are NUL-terminated and the NUL is counted in the length.  The
parser `FUN_180474f90` requires the exact payload size and a trailing NUL in
both fields.  The record id is

```
crc32(payload) | 0x64 << 32 | size << 40
```

built by `FUN_180186b84` from the Defender CRC-32 of the payload
(`FUN_180676c58`).

### Registration and matching

The type is registered by the **kcrce module init** `FUN_180927150`, not by a
dedicated `hosts` plugin:

```
local_40 = FUN_180474f90;  local_30 = 100 (0x64);  FUN_18018152c(&local_40, 0x30, 0xc)
```

The runtime tables are built by the same parser:

* exact host names: `DAT_1811231d8` (0xc-byte entries
  `{address_hash, payload_crc, condition_id}`);
* wildcard hosts (`*.suffix`): `DAT_1811231e0` (0x48-byte entries with an
  interned suffix and an optional prefix/offset check).

`FUN_180448360` is the matcher:

1. hash the host with `FUN_180676364` (case-insensitive/Defender hash) and
   look it up in the exact table;
2. require the stored address hash to equal the hash of the parsed line's
   address; the special address `NULL` is stored as `0xffffffff` and matches
   any `NULL` line;
3. if the host starts with `*.`, resolve the suffix with `FUN_180925328`,
   lower-case it, and scan `DAT_1811231e0` with `FUN_1809244e8`; the
   `FUN_180723aa0` suffix comparison enforces the tail match;
4. on success write the condition id into the caller structure and return the
   feature code `0x29`.

`FUN_1807a8bb0` registers the `SettingsModifier:Win32/HostsFileHijack` name
and `FUN_1801bb0c0` is the post-load commit that sorts/compacts both tables
(0xe-byte and 0xa-byte runtime side tables).

### Examples and coverage

```
SettingsModifier:Win32/PossibleHostsFileHijack   NULL      microsoft.com
SettingsModifier:Win32/PossibleHostsFileHijack   NULL      www.microsoft.com
SettingsModifier:Win32/PossibleHostsFileHijack   NULL      update.microsoft.com
SettingsModifier:Win32/HostsFileHijack           0.0.0.0   v4.windowsupdate.microsoft.com
SettingsModifier:Win32/HostsFileHijack           127.0.0.1 v4.windowsupdate.microsoft.com
```

| metric | value |
|--------|------:|
| records | 204 |
| owners | `HostsFileHijack` 149, `PossibleHostsFileHijack` 55 |
| address field | `NULL` 195, `0.0.0.0` 6, `127.0.0.1` 3 |
| distinct hosts | 71 |
| wildcard records (`*.`) | 0 (supported by the engine) |
| host length (incl. NUL) | 14..40 |

This is a hosts-file condition, not a file rule; the decoder keeps the address
and host so the condition can be displayed exactly as it would appear in the
file.

---

## 3. `SIGNATURE_TYPE_POLYVIR32` (`0x21`)

### What it is

`POLYVIR32` is a legacy **polymorphic-virus code fingerprint**.  A record
stores a 16-byte literal code fragment and the CRC-32 of two windows that
start at fixed offsets **relative to the fragment**.  The matcher finds the
fragment in the scanned buffer, then verifies the two windows, which lets one
record match differently encrypted variants of the same virus family.

It is not a file hash, not a FOP-style file-offset pattern, and not a plain
byte pattern; it is evaluated by the emulator/memory code scanner.

### Registration and template layout

The type is registered by the **HSTR module init** `FUN_180a1f948` as a
generic template table:

```c
FUN_1804eae94(&DAT_181113a98, 0x28, 0x12, &DAT_180f07470, ..., 0x421);
```

`FUN_1804eae94` stores the per-type context at
`DAT_18111e110 + (type + 0x1dd) * 0x58`; `0x421 & 0xff = 0x21`, so this is
the `POLYVIR32` context.  The template `0x180f07470` uses 16-byte
`{u64 opcode, u64 field_offset}` entries:

| opcode | field offset | meaning |
|-------:|-------------:|---------|
| `0x2010` | `0x00` | copy 16 bytes → literal anchor |
| `0x1001` | `0x10` | read u16 → window 1 offset |
| `0x1001` | `0x12` | read u16 → window 1 length |
| `0x1000` | `0x14` | read u32 → window 1 CRC-32 |
| `0x1001` | `0x18` | read u16 → window 2 offset |
| `0x1001` | `0x1a` | read u16 → window 2 length |
| `0x1000` | `0x1c` | read u32 → window 2 CRC-32 |
| `0x1009` | `0x24` | u16 length + optional blob (always 0 here) |
| `0x1016` | `0x20` | condition id + optional name (none here) |

The resulting entry is 0x28 bytes:

```
+0x00  u8  anchor[16]      literal code
+0x10  u16 window1_offset
+0x12  u16 window1_length
+0x14  u32 window1_crc
+0x18  u16 window2_offset
+0x1a  u16 window2_length
+0x1c  u32 window2_crc
+0x20  u32 condition_id
+0x24  u16 extra_length
```

All 151 shipped payloads are exactly 34 bytes, i.e. the anchor, six fields and
the zero `extra_length`; the optional blob and name are absent.

### Matching

`FUN_180047590` is the shared multi-pattern matcher (the same one used by the
HSTR family).  For the `POLYVIR32` table (`0x28`-byte stride) it does:

1. compare the 16-byte anchor ending at the current match position (it walks
   backwards from `match + 0xf`, stopping at the first mismatch);
2. `base = match_position - 15`; require
   `window1_offset + window1_length + base <= size` and
   `FUN_180676c58(buf + base + window1_offset, window1_length) == window1_crc`;
3. if the condition name is special (EUS-style; `FUN_18015fe38` returns
   non-zero), report it via `FUN_180154640`; otherwise require the same
   range/CRC check for window 2 and then report the condition id at entry
   `+0x20` via `FUN_18015dde0`;
4. a window-2 mismatch calls `FUN_18015c2b0(0xd, 0, window1_crc)`, which is the
   engine's repair/feature bookkeeping for a partially matching record.

The CRC is the engine CRC-32 (`FUN_180676c58`), i.e. reflected, init
`0xffffffff`, no final xor (`zlib.crc32(data) ^ 0xffffffff`).

### On-disk layout

```
u8  anchor[16]        literal code fragment
u16 window1_offset    relative to the anchor start
u16 window1_length
u32 window1_crc
u16 window2_offset
u16 window2_length
u32 window2_crc
u16 extra_length      0 in every shipped record
u8  extra[extra_length]
...                   optional name (none in this DB)
```

### Examples and coverage

```
Virus:Win32/Bugbear.B
  anchor  e8 03 ee 7e f7 bf 0b f7 f7 b8 d3 4d 62 10 bf 3c
  w1      [0,32)    0x4fc3fe78
  w2      [64,576)  0xd4ed7ee2

Virus:DOS/ASK.7972
  anchor  e8 07 00 "MS-DOS" 00 5e b8 8a 16 cd 2f
  w1      [64,128)  0x1541ef99
  w2      [128,256) 0xd42c4dc6

Virus:Win32/Bagle.O
  anchor  e8 00 00 00 00 5d eb 4f 17 40 70 3b 16 ce 3a 45
  w1      [64,96)   0x787abb18
  w2      [96,128)  0xb4049564
```

| metric | value |
|--------|------:|
| records | 151 |
| threats | 148 |
| named records | 0 |
| distinct anchors | 133 |
| payload size | 34 (all) |
| window 1 offset | 0, 0x10 (101), 0x20, 0x40, ... |
| window 1 length | 0x10 (99), 0x20 (42), 0x40 (4), 0x30 (2), 0xf0, 0x170 |
| window 2 offset | 0x20 (60), 0x10 (23), 0x30 (21), 0, 0x40, 0x100, ... |
| window 2 length | 0x20 (41), 0x30 (35), 0x10 (30), 0x40, 0x80, ... |

The dominant families are classic polymorphic/file infectors and droppers:
`Godog`, `Bofra`, `Bugbear`, `Bagle`, `ASK.*`, `CTX.*`, `Leviathan`, `Hybris`,
`Magistr`, `Aliz`, `Gain`, `Savior`, `Priest`, `Libertine`, `Pin`, `Moridi`,
`Idyll`, `Blakan`, `Zmorph`, `Begemot`.  The windows mostly cover code
immediately around the anchor, which is why offsets are small multiples of
0x10.

The anchor and windows are a memory/code fingerprint; there is no YARA
generator.  The decoder exposes the anchor as hex and text, both windows and
their CRCs, so the record can be compared and displayed.
