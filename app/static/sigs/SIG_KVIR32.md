# KVIR32: page fingerprints for packers and entry-point code

`SIGNATURE_TYPE_KVIR32` (`0x20`) is one of Defender's oldest record types.  It
does not contain a byte pattern.  It is a **two-window CRC fingerprint** used
by the page scanner and the PE emulator.

## How a record is built

```
u32 anchor_crc       CRC-32 of 16 bytes at page offset 16 * anchor_window
u32 body_crc         CRC-32 of body_length bytes at body_offset
u16 body_offset      offset inside the 4 KiB page
u16 body_length      body window length
u16 anchor_window    0, 1 or 2 -> anchor at page offset 0, 16 or 32
i16 flags            0 = report, negative (0x8000) = match only
u8  name_length      optional
u8  name[name_length]
```

For each page the engine computes the CRC of a 16-byte window at page offsets
0, 16 and 32, uses it as the lookup key, checks that the stored anchor window
matches, and finally verifies `body_crc` over
`[body_offset, body_offset + body_length)`.

## What it is used for

Despite the name, most records are **packer and entry-point fingerprints**, not
virus detections.  Named shared records look like:

```
!UPX_1_X  !ASProtect  !Themida  !FSG_1_3  !PECompact  !Armadillo  !MPRESS64
```

Emulator records use labels such as
`!#attrmatch_codepatch_EIP_00000009_909090909090`; these identify code patches
at a given entry-point offset.  Real threat owners include
`Trojan:Win32/Dorv.A`, `Trojan:Win32/Tracur`, `VirTool:Win32/CeeInject*` and
file infectors such as `Virus:Win32/Godog`, `Virus:Win32/Xpaj.A` and
`Worm:Win32/Sality.AU`.

A negative `flags` value means "match but do not report": those records feed
the emulator or repair logic only.

## Coverage

| metric | value |
|--------|------:|
| records | 6,595 |
| real-threat records | 5,369 (2,704 threats) |
| shared / named | 1,226 records, 680 labels |
| anchor windows 0 / 1 / 2 | 6,377 / 195 / 23 |
| suppressed (`flags` 0x8000) | 98 |

The CRCs are hash anchors, so the record cannot be turned into a YARA string.
Full reverse-engineering notes: `doc/sigs/sig_decode_kvir32_regkey.md`.
