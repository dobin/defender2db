# Decoding CKSIMPLEREC, CKOLDREC and NSCRIPT_NORMAL

Follow-up to `doc/sig_type_usage.md`, `doc/sigs/sig_decode_nscript_macro.md`
and `doc/sigs/sig_decode_pestatic_bm_sigtree_ext.md`.

Build analysed: `mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`
(x64, image base `0x180000000`; Ghidra project binary `/mpengine.dll`).

| type | id | base payload | records | what it is | decoder |
|------|----|-------------:|--------:|------------|---------|
| `SIGNATURE_TYPE_CKSIMPLEREC` | `0x50` | 20 B + optional name | 22,446 | literal 4-byte key + header CRC + one region CRC | `defender/signature/cksimplerec.py` (`CkSimpleRecSig`) |
| `SIGNATURE_TYPE_CKOLDREC` | `0x11` | 20 B + optional name | 1,741 | two explicit CRC-32 regions | `cksimplerec.py` (`CkOldRecSig`) |
| `SIGNATURE_TYPE_NSCRIPT_NORMAL` | `0x27` | variable | 10,715 | list of script hash pairs and/or rolling-window hash | `defender/signature/nscript.py` (`NscriptNormalSig`) |

All 34,902 records decode and consume their payload exactly (zero errors,
zero warnings).  `CKSIMPLEREC`, `CKOLDREC` and `NSCRIPT_NORMAL` are **content
checks**, not byte patterns: they store hashes over file regions or normalised
script text.

---

## 1. The `cksig` module and the checksum tables

`CKSIMPLEREC` and `CKOLDREC` belong to the `cksig` module.  Its name string is
at `0x180e77560`; the module table entry at `0x180e54b00` points at the init
`FUN_180a1d2b0`.

`FUN_180a1d2b0` allocates two runtime tables with `FUN_1804eae94`:

| runtime table | entry size | entries | on-disk type | matcher |
|---------------|-----------:|--------:|--------------|---------|
| `DAT_181115c88` | `0x24` | `0x10` | `CKSIMPLEREC` `0x50` | `FUN_1800fdc68` |
| `DAT_181115428` | `0x1c` | `0x12` | `CKOLDREC` `0x11` | `FUN_1800fe028` |

Both matchers take a region-CRC callback:

| address | role |
|--------:|------|
| `0x1800fe530` | CRC-32 of `[offset, offset+length)` in the cached buffer (`FUN_180676c58`) |
| `0x1800fe560` | same, but reads the range through the file reader when it is outside the cached buffer |
| `0x1800fdc68` | `CKSIMPLEREC` matcher; reports type `0x50` through `FUN_18015dde0` |
| `0x1800fe028` | `CKOLDREC` matcher; reports type `0x11` |
| `0x180a1d660` | turns a checksum hit into a detection/feature |

The checksum is the engine CRC-32: init `0xffffffff`, no final xor, i.e.
`zlib.crc32(data) ^ 0xffffffff`.

---

## 2. `SIGNATURE_TYPE_CKSIMPLEREC` (`0x50`)

### Layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 4 | `file_prefix` | **literal first four bytes of the scanned file/buffer** (primary table key) |
| `0x04` | 4 | `header_crc` | CRC-32 of the first `0x10` bytes |
| `0x08` | 2 | `region_offset` | offset of the checked region |
| `0x0a` | 2 | `region_length` | length of the checked region |
| `0x0c` | 4 | `region_crc` | CRC-32 of `[region_offset, region_offset + region_length)` |
| `0x10` | 4 | `flags` | bits 26..29 = scan group; low 26 bits preserved |
| `0x14` | 1 | `name_len` | optional; length **includes** the trailing NUL |
| `0x15` | n | `name` | optional NUL-terminated engine label |

The first field is not a hash.  The matcher is given the first four file bytes
as `param_6` (`FUN_1800fd430` reads them with a 4-byte read) and looks the
record up by that value.  DOS `MZ` files show the literal header in the
record, e.g. `4d 5a 20 00` (`MZ`, last-page field `0x20`, pages `0`) for the
`~SUPD.false` known-file tags.

Matching (`FUN_1800fdc68`):

1. look up the record by the first four file bytes,
2. require `(flags >> 26) & 0xf == scan_group` (caller argument; `0` for the
   normal file scan, `8` for the HLP path),
3. verify `header_crc` over `[0, 0x10)`,
4. verify `region_crc` over the stored offset/length,
5. report a hit for signature type `0x50`.

### Flags

`flags >> 26 & 0xf` is the scan group.  Observed groups: `0` (22,436
records, normal file scan), `8` (8, HLP), `9` (2).  The low 26 bits are kept
verbatim; in the shipped database they are `0..3` plus the high group bits:

| flags | records |
|------:|--------:|
| `0x00000002` | 14,807 |
| `0x00000000` | 3,836 |
| `0x00000001` | 2,174 |
| `0x00000003` | 1,619 |
| `0x20000000` | 8 |
| `0x24000002` | 2 |

### Database coverage

| metric | value |
|--------|------:|
| records | 22,446 |
| in real threats | 22,313 (all anonymous) |
| in `!InfrastructureShared` | 133 (all named) |
| most common region length | `0x40` (4,666), `0x3ef` (2,282), `0x60` (1,511), `0x50` (1,374) |
| most common region offset | `0x10` (11,720), `0` (8,252) |

The named infrastructure records are checksum-keyed **known-file policy tags**,
not detections: `~stuba.slow` (31), `~avir.slow` (10), `~SUPD.false` (9),
`~Dropper.false` (7), `~boot.false` (3), `#Type_Trojan` (3).  The suffix names
the action (`slow` = expensive file, `false` = FP suppression), the same
concept as STATIC's `#ExpensiveFile`/`#FP:` tags.

Example (`Virus:DOS/E9`):

```
prefix=800100bf header_crc=9d4cb9f3 region=95+16 crc=6483a0b2 flags=2
```

`~SUPD.false` (`MZ` header, CRC of the first 1 KiB):

```
prefix=4d5a2000 header_crc=0d76c9d8 region=0+1024 crc=... flags=2
```

### YARA

`CKSIMPLEREC` is expressible in YARA 4.x because the key and the two windows
are all cheap:

```yara
uint32(0) == 0x00205a4d and
hash.crc32(0, 0x10) == 0x0d76c9d8 and
hash.crc32(0, 1024) == 0x...
```

The engine CRC differs from YARA's `hash.crc32` by a final xor
(`hash.crc32 == engine_crc ^ 0xffffffff`), so a rule generator must invert the
stored value.  No generator is wired up yet.

---

## 3. `SIGNATURE_TYPE_CKOLDREC` (`0x11`)

### Layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 2 | `region1_offset` | first region offset (also the runtime group index, `0..0x3f`) |
| `0x02` | 2 | `region1_length` | first region length |
| `0x04` | 4 | `region1_crc` | CRC-32 of region 1 |
| `0x08` | 2 | `region2_offset` | second region offset |
| `0x0a` | 2 | `region2_length` | second region length |
| `0x0c` | 4 | `region2_crc` | CRC-32 of region 2 |
| `0x10` | 4 | `flags` | bits 26..29 = scan group; low bits preserved |
| `0x14` | 1 | `name_len` | optional; one record uses a non-NUL name |
| `0x15` | n | `name` | optional engine label |

`CKOLDREC` is the older, explicit two-region form.  `region1_offset` is only
16 bits and doubles as the lookup group (`FUN_1800fe028` calls the CRC callback
with the group index and `region1_length`).  `region2_offset`/`region2_length`
are the second window.

`region1_length` is `0x10` in almost every record; the second region is the
variable one.  Flags low values 0..3 mirror `CKSIMPLEREC`; groups `1`, `2` and
`4` are used by the infrastructure feeds.

Example (`Virus:DOS/Demi`):

```
region1=6+16 crc=20b72f1a region2=22+34 crc=0f06c414 flags=3
```

Coverage: 1,740 real-threat records, 1 named record
(`~Holupfpos`, a known-file tag); all offsets < 0x400 and lengths < 0x400 in
the shipped database.

---

## 4. `SIGNATURE_TYPE_NSCRIPT_NORMAL` (`0x27`)

`NSCRIPT_NORMAL` is the general script-condition record.  `NSCRIPT_SP`
(`0x28`) and `NSCRIPT_BRUTE` (`0x29`) are compact special cases of the same
condition vector.  The handler is `FUN_180180ef0`, which wraps the shared
`FUN_180180f0c` parser (see `cache/functions_vdm.md` §13).

### Layout

```
u8   name_len            0..0x3f
u8   name[name_len]
u8   count               number of 32-bit script hashes
u32  hash_a[count]
u8   flags
# flags == 0: all hashes are pairwise
u32  hash_b[count]
# flags != 0: first hash belongs to a rolling-window condition
u32  hash1
u32  match_length
u32  hash_b[count]        optional; hash_b[0] is reserved, hash_b[1:] pair with hash_a[1:]
u32  weight               optional trailing dword; only the low byte is used
```

The engine inserts the parsed conditions into two global vectors:

* `flags == 0` – every `{hash_a[i], hash_b[i]}` pair goes into
  `DAT_181106a20` (0x10-byte entries `{hash1, hash2, condition_id, name_id}`).
* `flags != 0` – the first condition goes into `DAT_181106a18` (0x14-byte
  entries `{hash1=hash1, window_length, hash2=hash_a[0], condition_id, flags}`)
  and the remaining `{hash_a[i], hash_b[i]}` pairs go into `DAT_181106a20`.

This is exactly the `NSCRIPT_SP` content in a longer container: `NSCRIPT_SP`
stores `{hash1, flags, hash2, match_length}` and `NSCRIPT_NORMAL` uses
`hash1 = value`, `hash2 = hash_a[0]`, `match_length = window_length`.

### Forms in the database

| form | records | meaning |
|------|--------:|---------|
| flags `0x00`, pairs present | 9,917 | one or more hash pairs |
| flags `0x00`, no pairs | 11 | compact `#fp...`/`#IRC...` interning variant (`hash_b` omitted) |
| flags `0x01` | 429 | rolling-window hash + optional pairs; legacy `:IRC/` case |
| flags `0x02` | 358 | same, second IRC flag value |

All window records have `match_length >= 0x21` (engine minimum), up to 410,747;
only 787 window conditions exist because most records contain multiple pairs.
There are 15,742 hash-pair conditions and 787 window conditions in total.
2,942 records carry the optional trailing weight (`weight & 0xff == 1`).
939 records are named (all in `!InfrastructureShared`), e.g.
`!#TEL:Trojan:PowerShell/JScealDownload.B`, `!#SCRIPT:Trojan:PowerShell/RedPowdump.A`.

Coverage: 10,715 records; 9,775 belong to real threats, 940 to
`!InfrastructureShared`.  All records decode with zero warnings after allowing
the 11-record compact variant.

Real examples:

```
Exploit:JS/CreateText       hash_pairs=[6fe833e8:c1cd1654]
Trojan:JS/Torvil            hash_pairs=[09e7d855:111e001a,182a6ff3:8bd3022d]
Virus:BAT/Ataris.A          window hash1=097bdb77 hash2=96803a40 len=172 flags=1
#fp6234                     compact hash1=66276eb4 flags=0 (2 hashes, no pair array)
```

### Renderability

Both hash arrays are 32-bit hashes of **normalised script text** (lower case,
whitespace removed), not text and not a file hash.  The record can be decoded,
counted and correlated with `NSCRIPT_SP`/`NSCRIPT_BRUTE`, but it cannot be
turned into YARA text.  It is still useful for analysis because it proves which
threats share a script condition even when the readable `NSCRIPT_BRUTE` record
is absent.

---

## 5. Discovery notes

* `cksig` name string `0x180e77560`, module entry `0x180e54b00`, init
  `FUN_180a1d2b0`.
* `FUN_18018152c` is `RegisterForDatabaseRecords`; `FUN_1804eae94` is the
  table constructor used by `cksig`.
* The checksum matcher reports its signature type as an immediate
  (`0x50`/`0x11`) in `FUN_18015dde0`; that is the easiest way to tell which
  table belongs to which type.
* `FUN_180676c58` is the engine CRC-32; `FUN_1800fe530`/`FUN_1800fe560` are the
  region wrappers.
* `NSCRIPT_NORMAL` shares `FUN_180180f0c` with `NSCRIPT_SP`; `:IRC/` names use
  the same flags 1/2 special case.
