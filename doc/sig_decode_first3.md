# Decoding SNID / STATIC / KCRCE

Research notes for the three most common Defender signature types. Evidence comes from
`cache/threats.db` (sampled across distinct threats, not one family) and from
`cache/mpengine.dll` via the PyGhidra MCP server.

All multi-byte values are little endian.

## TL;DR

| Type | ID | Payload | What it is |
|------|----|--------:|------------|
| `SIGNATURE_TYPE_SNID` | `0x7e` | 21 | Reference to a shared signature record: 20-byte SHA1 key + 1-byte record type |
| `SIGNATURE_TYPE_STATIC` | `0x67` | 22 / 34 / 38 | File hash signature: 3 partial CRC32s + file size + strong hash (CRC32, MD5 or SHA1) |
| `SIGNATURE_TYPE_KCRCE` | `0x80` | 16 | Compact "known file" CRC signature: 3 CRC32s + region/size + flags |

mpengine's `getsigtype` equivalent is `FUN_180337818`; it confirms the IDs (0x7e/0x67/0x80)
in this engine build.

---

## 1. `SIGNATURE_TYPE_STATIC` (0x67)

### Layout

```
offset  size  field
0x00    4     hash1
0x04    4     hash2
0x08    4     hash3        CRC32 over first min(file_size, 0x10000) bytes
0x0c    4     file_size
0x10    2     flags        0x0001 = MD5, 0x1001 = SHA1, 0x2001 = CRC32
0x12    n     file hash    n = 16 (MD5), 20 (SHA1) or 4 (CRC32)
```

Observed lengths in the current DB:

| Length | flags | trailing hash | count in sample |
|-------:|-------|---------------|----------------:|
| 22 | `0x2001` | CRC32 (4 bytes) | 62,660 |
| 34 | `0x0001` | MD5 (16 bytes) | 20 |
| 38 | `0x1001` | SHA1 (20 bytes) | 2,087 |

`flags & 0x0fff == 1` means "has a trailing full-file hash"; the upper nibble selects the
algorithm (`0x0000` MD5, `0x1000` SHA1, `0x2000` CRC32).

### Evidence

* The 22-byte form stores `CRC32(file)` in the trailing dword.
* `hash3 == trailing CRC32` exactly when `file_size <= 0x10000`, and never when
  `file_size > 0x10000` (verified on 1,019 distinct-threat samples: 533 equal, all
  <= 64 KiB; 486 different, all >= 64 KiB).
* mpengine's partial-CRC code (`FUN_1800ee5b8`) computes:
  * `partialcrc2` = CRC32 of the first `min(file_size, 0x10000)` bytes,
  * `partialcrc1` = CRC32 of the first 0x1000 bytes,
  * `partialcrc3` = CRC32 of the last 0x1000 bytes.
  The same values are persisted in the engine's `FileHashes` table
  (`PartialCRC1/2/3`, `KCRC1/2/3/3n`).
* The engine's CRC helper is `FUN_180676c58`: standard reflected CRC-32 (poly
  `0xEDB88320`), initial value `0xffffffff`, **no final xor**. In Python:
  `zlib.crc32(data) ^ 0xffffffff`.
* 38-byte records carry 20 trailing random bytes; this matches the known
  "SHA1 of the file" static form. 34-byte records are the MD5 form (20 test-file
  signatures named `Virus:Win32/MPTestFile.2004` / `Trojan:Win32/Mpteststat`).

`hash1`/`hash2` are the other two partial CRCs. Which is first-window vs last-window is
not proven yet, but the three-CRC set and the `hash3`/file-size relationship are solid.

### Samples

```
22 bytes: 7952f311 04d126ea 22390208 736e0000 0120 22390208
          hash1    hash2    hash3    size=0x6e73 flags=0x2001 crc32
34 bytes: 1f79d57e b21ec595 29d988cb 00900000 0100 9a026f3295fefe4c4647ea5ba6bd43da
38 bytes: 69860403 923603bc f4533191 6c0c0000 0110 02a27e325ff806402628ac68780906d07f285b9a
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

They do not yet generate YARA rules for these types. STATIC's SHA1/MD5 trailing hash and
KCRCE's CRCs are hashes of the analysed file, so they are best emitted as hash-based
conditions (or metadata/IOCs) rather than `$string` patterns.
