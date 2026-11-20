# BOOT: boot image patterns

`SIGNATURE_TYPE_BOOT` (`0x44`) is the **boot image signature** used by the MBR /
VBR / boot-sector scanner.  It is a real byte pattern or a checksummed region,
not a file fingerprint.

```
u8 name_length           0 = anonymous
u8 name[name_length]     feed label, not NUL terminated
u8 blob[32]
```

A blob has two forms, selected by its first byte.

## Normal pattern

```
u8 pattern_length        4..31
u8 pattern[31]           first pattern_length bytes significant, rest zero
```

The first four bytes are compared as a dword; the remaining bytes are compared
byte-wise with `0x90` as a single-byte wildcard.  A `0x90` inside the first
four bytes is literal.

```
Virus:DOS/Half
  80 2e 13 04 03 b9 06 00 d3 e0 2d 00 10 8e c0 33 c0 ...

Virus:DOS/MpTestBoot
  cd 90 cd 33 cd 14 cd 13 c7 16 7a 13 05 40 ...
```

## CRC form

`blob[0] == 0x20` selects the checksummed form:

```
u8  0x20
u8  0x00
u8  anchor[8]            literal first eight bytes at the match position
u16 covered_length
u32 crc32                Defender CRC-32 of [match, match + covered_length)
u8  padding[15]
```

The engine matches the 8-byte anchor, then compares the CRC-32 of the covered
region.  It reports where the signature matched as `bootsigoffset`.

```
Virus:DOS/3nop
  anchor 90 90 90 fa 33 c0 8e d8, length 42, crc32 63fd44a8
```

## Coverage

| metric | value |
|--------|------:|
| records | 1,217 |
| normal / CRC form | 979 / 238 |
| labelled / anonymous | 14 / 1,203 |
| normal pattern length | 4 .. 31 |
| CRC covered length | 14 .. 300 (median 56) |

Real-threat records are anonymous; the labelled ones are shared `!#BOOT:` /
`!#TEL:` definitions (Petya, WhisperGate, BootMgrVbr, DiskCryptor, ...).

The normal form is expressible as a YARA hex string.  The CRC form needs the
match offset before `hash.crc32` can be evaluated, so it is not a plain string
rule.  Full reverse-engineering notes:
`doc/sigs/sig_decode_ndat_brute_boot.md`.
