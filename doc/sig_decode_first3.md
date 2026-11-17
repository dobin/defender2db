# Decoding SNID / STATIC / KCRCE

Research notes for the three most common Defender signature types. Evidence comes from
`cache/threats.db` (all STATIC records plus samples from distinct threats) and from
`cache/mpengine.dll` via the PyGhidra MCP server.

All multi-byte values are little endian.

## TL;DR

| Type | ID | Payload | What it is |
|------|----|--------:|------------|
| `SIGNATURE_TYPE_SNID` | `0x7e` | 21 | Reference to a shared signature record: 20-byte SHA1 key + 1-byte record type |
| `SIGNATURE_TYPE_STATIC` | `0x67` | 22 / 34 / 38 / 50 (+name) | Known-file fingerprint: partial CRC1 / CRC3 / CRC2 windows + file size + optional strong hash (CRC32, MD5, SHA1, SHA1[:4] or SHA256) + optional inline tag |
| `SIGNATURE_TYPE_KCRCE` | `0x80` | 16 | Compact "known file" CRC signature: 3 CRC32s + region/size + flags |

mpengine's `getsigtype` equivalent is `FUN_180337818`; it confirms the IDs (0x7e/0x67/0x80)
in this engine build.

---

## 1. `SIGNATURE_TYPE_STATIC` (0x67)

### What it is

A **known-file fingerprint**. `SIGNATURE_TYPE_STATIC` is the file member of a small
family of hash-like record types (`0x67`..`0x6d`; `FUN_180859798` maps the scan-object
kind to the record type). mpengine loads these records into the "static match" table
built by `FUN_18092e220` / `FUN_18092be48` alongside the trusted-publisher (`0x70`) and
revoked-certificate (`0x6c`) tables. The matcher runs in the static (non-emulated)
signature phase and can:

* raise a detection for a known file,
* mark a file as clean/friendly (`#ClnFile`, `#Clean`, ...), optionally for a TTL,
* flag a file as expensive to scan (`#ExpensiveFile`),
* apply FP suppressions / exclusions (`#FP:...`, `#Exclusion...`),
* attach a classification or feedback name (`#PUA:Win32/...`, `#Trojan:JS/...`).

It is therefore not just a file-hash detection record: it is Defender's file reputation
and classification table.

### Layout

```
offset  size  field
0x00    4     hash1        partial CRC1: first min(size, 0x1000) bytes, zero padded
0x04    4     hash2        partial CRC3: last 0x1000 bytes of the first `size` bytes
0x08    4     hash3        partial CRC2: first min(size, 0x10000) bytes
0x0c    4     file_size    full u32 file/prefix size
0x10    2     flags        bit 0 = prefix match; bits 12..14 = strong hash algorithm
0x12    n     strong hash  n = 4 (CRC32), 16 (MD5), 20 (SHA1), 4 (SHA1[:4]), 32 (SHA256)
0x12+n  1     name_len     optional, only present in extended records
0x13+n  ...   name[ name_len ]   non-NUL-terminated tag, e.g. `#ClnFile`
```

The on-disk dword order is **CRC1, CRC3, CRC2** (not 1, 2, 3). The engine names come
from the `FileHashes` table (`PartialCRC1`, `PartialCRC2`, `PartialCRC3`); in the
record, `hash3` is `PartialCRC2`, which is why `hash3 == CRC32(file)` for files of at
most 64 KiB.

### The three partial CRCs

`FUN_1800ee5b8` (report/`FileHashes` path) computes them as:

* `partialcrc1` = CRC32 of the first `min(size, 0x1000)` bytes, then zeros appended to
  0x1000 bytes (the lookup/index key, built by `FUN_18028c670`),
* `partialcrc2` = CRC32 of the first `min(size, 0x10000)` bytes,
* `partialcrc3` = CRC32 of the last 0x1000 bytes of the first `size` bytes; for
  `size < 0x1000` the window is zero-padded **before** the data.

The matcher (`FUN_180214dec` → `FUN_180213c60`) uses them in this order:

1. binary-search the table by `hash1` (`FUN_1802153d0`),
2. compare `hash3` (first 64 KiB window) against the file,
3. compare `hash2` (last 4 KiB window) against the file,
4. check the `#CFG:` feature gate and verify the strong hash over the first `size`
   bytes (`FUN_1800f1728`, `GetHashes(Custom)`).

`FUN_180676c58` is the engine CRC helper: standard reflected CRC-32 (poly `0xEDB88320`),
initial value `0xffffffff`, **no final xor**. In Python: `zlib.crc32(data) ^ 0xffffffff`.

Empirical checks over 262,852 unique STATIC records in the merged compendium:

* all 75 records with `file_size == 0x1000` have `hash1 == hash2 == hash3` (all three
  windows cover the same bytes),
* the 22-byte CRC32 form satisfies `hash3 == trailing CRC32` for every record with
  `file_size <= 0x10000` (16,243 records); it never does for `file_size > 0x10000`
  (227,284 records),
* 4 records with an `!#Exclusion:` tag carry a zero trailing hash; they are the only
  small records where the relation fails.

### Flags

| value | meaning |
|-------|---------|
| `0x0000` | MD5 (16-byte strong hash) |
| `0x1000` | SHA1 (20 bytes) |
| `0x2000` | CRC32 (4 bytes) |
| `0x3000` | first 4 bytes of SHA1 (4 bytes) |
| `0x4000` | SHA256 (32 bytes) |
| `0x0001` | prefix/truncated match: `size <= file_size` instead of equality |

Only two bits are ever set: bit 0 is the size relaxation, bits 12..14 select the hash.
`0x3000` and `0x4000` are supported by the engine (`FUN_180213c60` compares against
`SHA1[:4]` and `SHA256`) but do not occur in signature version 1.463.330.0. The common
values therefore decode as `0x2000` = CRC32 + exact size and `0x2001` = CRC32 + prefix
match (`0x2001 == 0x2000 | 0x0001`).

### Size handling and prefix matches

`FUN_180212cb4` normally returns `internal_flags & 0x0fffffff`. When that field is the
sentinel `0x0fffffff`, the size is read from the shared hash blob instead, so the
serialised `file_size` is a full `u32` (observed up to ~1 GiB).

When `flags & 0x0001` is **clear**, the record only matches a file whose size equals
`file_size`. When it is **set**, the engine accepts `size <= actual_file_size`, and the
strong hash covers only the first `file_size` bytes: the record matches a prefix of a
longer file (truncated/partial match). This is the common case for the CRC32 form
(~92% of records) and rarer for SHA1 (~64%).

### Trailing name / tag

The base record can be followed by `u8 length` + tag bytes. In the current DB the
trailing tag appears only in `!InfrastructureShared`, where all 35,428 STATIC records
are tagged (5,154 distinct tags); per-threat and `!Infrastructure` records are unnamed.
Tags starting with `#` are engine directives (`FUN_180148d84`); `!` marks
internal/non-customer records (`!#...`).

| tag pattern | meaning |
|-------------|---------|
| `#ClnFile`, `#ClnFile:<minutes>`, `#ClnFileInMin:<minutes>`, `#Clean`, `#CleanFile`, `#clean` | clean/friendly verdict, optional TTL (`FUN_180478774`) |
| `#ClnInst*` | installer-file variant of the clean verdict |
| `#CFG:<A/M/P>:<tag>` | feature-gated directive; `FUN_180213c60` checks the A/M/P features, e.g. `#CFG:A:ClnFile` |
| `#ExpensiveFile` | performance hint ("Engine.Perf.ExpensiveFile") |
| `#Exclusion`, `#Exclusion_<ver>_<reason>`, `#Exclude` | static-match exclusions (some carry a zero strong hash) |
| `#FP:<family>` | false-positive suppression for a family, e.g. `#FP:Bulta` |
| `#<ThreatType>:<platform>/<family>` | classification attached to the fingerprint, e.g. `#PUA:Win32/Creprote`, `#Trojan:JS/Cardst` |
| `!#PUA:Block:...`, `!#ALF:...`, `!#ALFPER:...`, `!#TEL:...`, `!#SLF:...`, `!#STATIC:...` | internal/allow-list/telemetry/test feeds |
| `#MpCloudToVDMBloomFilterXPLAT` | cloud→VDM bloom-filter feed entries |

A tag is not required: most records are pure hashes.

### Samples

```
22 bytes, CRC32, prefix bit:
7952f311 04d126ea 22390208 736e0000 0120 22390208
hash1    hash2    hash3    size=0x6e73 flags=0x2001 crc32 (= hash3, size < 64 KiB)

22 bytes, CRC32, exact size:
f01bb56e 5905aa8c ecafc0bd 00420000 0020 ecafc0bd
hash1    hash2    hash3    size=0x4200 flags=0x2000 crc32 (= hash3)

34 bytes, MD5:
1f79d57e b21ec595 29d988cb 00900000 0100 9a026f3295fefe4c4647ea5ba6bd43da

38 bytes, SHA1:
69860403 923603bc f4533191 6c0c0000 0110 02a27e325ff806402628ac68780906d07f285b9a

22 + 8 bytes, tag `#ClnFile`:
136a3a00 b987d2ac 49e8d167 d0970f00 0020 c83df1cf 08 23 436c6e46696c65
hash1    hash2    hash3    size=0x0f97d0 flags=0x2000 crc32  len tag

size == 0x1000 (all three windows collapse):
7e3da31e 7e3da31e 7e3da31e 00100000 0010 2d9e2f2bc26ecbf19c1d1f3093a03c3c2c7f7091
```

---

## 2. `SIGNATURE_TYPE_SNID` (0x7e)

### Layout

```
offset  size  field
0x00    20    record_sha1      key of the referenced signature record
0x14    1     record_sig_type  signature type of the referenced record
```

Length is always 21.

### What it does

SNID is an indirection / record-reuse entry, not a hash of the file being scanned.
mpengine's record lookup path builds the SNID payload directly:

* `FUN_18010df68` matches a 20-byte record key + a 1-byte type (`+0x14` in the record),
  then calls `FUN_180217edc(out, 0x7e, &record, 0x15)` to emit a 21-byte type-0x7e entry.
* The `SNidSearch` definition command (`FUN_18037dfc0`) parses a 40-hex-char SHA1,
  resolves it to a `RecId` through `FUN_18010dc74`, unpacks the record name via
  `FUN_18015a450`, and emits the reference.

That makes SNID "shared signature record ID": a threat points at another signature
record by SHA1 instead of duplicating its body. This matches the concentration in
`!InfrastructureShared` (447,605 SNIDs in the aggregate bucket).

### The trailing byte

Across all 2.2M SNIDs the last byte takes values that almost all map to signature type
IDs. Top values (count / type):

```
0xcc 430,292  SIGNATURE_TYPE_KCRCEX
0x70 259,218  SIGNATURE_TYPE_TRUSTED_PUBLISHER
0xd3 239,248  SIGNATURE_TYPE_AUTOITHSTR_EXT
0x62 148,372  SIGNATURE_TYPE_LOCALHASH
0x73 144,113  SIGNATURE_TYPE_DELTA_BLOB
0xe4 142,561  SIGNATURE_TYPE_MDBHSTR_EXT
0xcb 135,050  SIGNATURE_TYPE_PESTATICEX
0xd8 131,192  SIGNATURE_TYPE_FASTPATH_TDN
...
```

This is exactly the "referenced record's type" field.

Note: the 20-byte key did **not** match SHA1 of the raw payload, full TLV record, or
plain threat names in the local DB. It is a key into the engine's record store (which is
built from the definition source, including record names/metadata), so a stand-alone
resolver needs that store; it cannot always be reconstructed from the unpacked VDM
alone.

---

## 3. `SIGNATURE_TYPE_KCRCE` (0x80)

### Layout

```
offset  size  field
0x00    4     crc1
0x04    4     crc2
0x08    4     crc3
0x0c    2     region/size   most often 0x1000, then 0x0400; also 0xffc0 / 0xffff
0x0e    2     flags         observed 0x0000, 0x8000, 0xc000
```

Length is always 16.

### Evidence

* `crc1`/`crc2`/`crc3` have full 32-bit entropy (about 47-50% of values above
  `0x80000000`) and are CRC32 values, not file sizes.
* mpengine stores four CRC values per file/region in `FileHashes`: `KCRC1`, `KCRC2`,
  `KCRC3`, `KCRC3n`. Its computation (`FUN_18027b70c`, `FUN_18090fa90`) uses:
  * `0x20` bytes (header),
  * first `0x100` bytes of a section,
  * first `0x400` bytes of a section,
  * first `0x1000` bytes of a section (`KCRC3n`).
* The 16-bit value is a small region descriptor. The common `0x1000`/`0x400` values line
  up with those windows; `0xffc0` (-0x40) and `0xffff` (-1) are consistent with offsets
  relative to EOF (the engine has a `kcrce_scanfilelast` path).
* `0x80` records contain only three CRCs, so this is the compact variant of the
  `KCRC1/2/3/3n` set; the larger `SIGNATURE_TYPE_KCRCEX` (`0xcc`) uses 0x20 bytes
  (`FUN_180925550` copies 8 dwords) and carries more data.

It is a fast "known file" check over a few small CRC windows, used before the expensive
emulation/string engines. The exact mapping of `crc1/2/3` to the four KCRC windows and
the meaning of the `0x8000`/`0x4000` flag bits are the remaining open questions.

### Samples

```
Backdoor:Win32/Hupigon      dff40100 0e1d51ea 41583902 0004 0000
Trojan:MacOS/EICAR...!xp    e8a5368c e231a879 9de802b3 0004 8000
Backdoor:Win32/Amitis.E     353135a1 fafdfc9e 4f0891de 0010 0000
```

---

## Implementation added

New layout parsers (registered in `Vdm.parse_database`):

* `defender2yara/defender/signature/static.py` – `StaticSig`
* `defender2yara/defender/signature/kcrce.py` – `KcrceSig`
* `defender2yara/defender/signature/snid.py` – `SnidSig`
* `tests/test_signature_first3.py` – fixtures from real DB records

`StaticSig` exposes the engine naming as well as the on-disk order: `hash1/2/3` are
kept for compatibility and aliased to `partial_crc1`, `partial_crc3`, `partial_crc2`.
It also decodes `prefix_match` (bit 0) and the strong-hash variants `md5`, `sha1`,
`crc32`, `sha1_32` and `sha256`, plus the inline tag.

They do not yet generate YARA rules for these types. STATIC's SHA1/MD5 trailing hash and
KCRCE's CRCs are hashes of the analysed file, so they are best emitted as hash-based
conditions (or metadata/IOCs) rather than `$string` patterns. For example a STATIC
record can be represented as `filesize == size and hash.sha1(0, filesize) == "..."`;
the CRC32 form is the engine's raw CRC (no final xor), and the two partial windows are
awkward because the last-window offset depends on `file_size`. A future rule generator
should prefer the strong hash and use the partial CRCs only as a prefilter.

