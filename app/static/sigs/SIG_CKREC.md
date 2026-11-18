# CK signatures: checksum-region file checks

`SIGNATURE_TYPE_CKSIMPLEREC` (`0x50`) and `SIGNATURE_TYPE_CKOLDREC` (`0x11`)
are Defender's legacy **checksum-region** signatures.  They do not contain byte
patterns.  They identify a file by a few CRC-32 windows at fixed or explicit
offsets, the same idea as the partial CRCs in `STATIC`.

The CRC is Defender's engine CRC-32: initial value `0xffffffff`, no final xor.
In Python it is `zlib.crc32(data) ^ 0xffffffff`; a YARA rule has to invert the
stored value to compare against `hash.crc32`.

## `CKSIMPLEREC` (`0x50`)

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 4 | `file_prefix` | literal first four bytes of the file |
| `0x04` | 4 | `header_crc` | CRC-32 of the first `0x10` bytes |
| `0x08` | 2 | `region_offset` | offset of the checked region |
| `0x0a` | 2 | `region_length` | length of the checked region |
| `0x0c` | 4 | `region_crc` | CRC-32 of that region |
| `0x10` | 4 | `flags` | bits 26..29 = scan group, low bits preserved |
| `0x14` | 1 | `name_len` | optional; includes the trailing NUL |
| `0x15` | n | `name` | optional NUL-terminated engine label |

The first field is not a hash.  Defender reads the first four file bytes and
uses them as the lookup key, so DOS files literally show `4d 5a` (`MZ`) in the
record.  A match needs the prefix, the header CRC, and the region CRC.

`flags >> 26 & 0xf` is the scan group.  Group `0` is the normal file scan,
`8` is the HLP path, `9` is rare.  The low 26 bits are kept verbatim.

Real threats use 22,313 anonymous records.  The 133 named records in the shared
infrastructure bucket are **checksum-keyed known-file policy tags**, not
detections:

```
~stuba.slow      costly installer, skip/defer scanning
~avir.slow
~SUPD.false      known false positive
~Dropper.false
~boot.false
#Type_Trojan
```

This is the same concept as STATIC's `#ExpensiveFile` and `#FP:` tags.
Typical region checks are `0x10+0x40`, `0x10+0x3ef`, `0+0x40` and `0+0x400`.

Example (`Virus:DOS/E9`):

```
prefix=800100bf
header_crc=9d4cb9f3
region=95+16 crc=6483a0b2
flags=2
```

`CKSIMPLEREC` is expressible in YARA:

```yara
uint32(0) == 0x800100bf and
hash.crc32(0, 0x10) == 0x62b3460c and
hash.crc32(0x5f, 0x10) == 0x9b7c5f4d
```

(The CRC values in the example are the stored engine CRCs xored with
`0xffffffff`; the decoder exposes the stored engine values.)

## `CKOLDREC` (`0x11`)

The older two-region form:

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 2 | `region1_offset` | first region offset (also the lookup group, `0..0x3f`) |
| `0x02` | 2 | `region1_length` | first region length (almost always `0x10`) |
| `0x04` | 4 | `region1_crc` | CRC-32 of region 1 |
| `0x08` | 2 | `region2_offset` | second region offset |
| `0x0a` | 2 | `region2_length` | second region length |
| `0x0c` | 4 | `region2_crc` | CRC-32 of region 2 |
| `0x10` | 4 | `flags` | bits 26..29 = scan group |
| `0x14` | 1 | `name_len` | optional |
| `0x15` | n | `name` | optional engine label |

Both regions are explicit, so the record is slightly larger semantically than
`CKSIMPLEREC` even though the on-disk size is the same.  `CKOLDREC` is the
classic DOS/COM/EXE virus check: one fixed-size header window plus one variable
window.

Example (`Virus:DOS/Demi`):

```
region1=6+16   crc=20b72f1a
region2=22+34  crc=0f06c414
flags=3
```

Coverage: 1,740 real-threat records plus one named shared known-file tag
(`~Holupfpos`).

## Why the names are engine labels

The optional name is not the threat name for shared records.  It is an
instruction to the engine: an exclusion, a known-file classification, or a
performance hint.  Real-threat records are anonymous because the enclosing
`THREAT_BEGIN` record already carries the detection name.

## Engine references

* `cksig` module init `FUN_180a1d2b0`; module name `cksig`.
* `CKSIMPLEREC` matcher `FUN_1800fdc68`; `CKOLDREC` matcher `FUN_1800fe028`.
* Region CRC callback `FUN_1800fe530` / `FUN_1800fe560`, engine CRC
  `FUN_180676c58`.
* Hit conversion `FUN_180a1d660`.

Full reverse-engineering notes:
`doc/sigs/sig_decode_ck_nscript_normal.md`.
