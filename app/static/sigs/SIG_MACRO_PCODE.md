# MACRO_PCODE / MACRO_PCODE64 signatures: VBA p-code fingerprints

`SIGNATURE_TYPE_MACRO_PCODE` (`0x42`) and `SIGNATURE_TYPE_MACRO_PCODE64`
(`0xcf`) are Defender's **macro p-code** signatures. They are evaluated against
the p-code (compiled byte-code) that Office stores next to a VBA module, after
the engine has decompressed and normalised it — not against the document bytes
and not against the macro source text.

## The short version

A record contains up to three **routine keys** and an optional engine label:

```
u32 key0, key1, key2         0x42 (32-bit keys = CRC-32 only)
u64 key0, key1, key2         0xcf
name                         optional, NUL terminated
```

A 64-bit key packs three values:

```
bits  0..31   CRC-32 of the hashed bytes   (init 0xffffffff, no final xor)
bits 32..47   CRC-16 of the same bytes     (reflected ARC, poly 0xa001, init 0)
bits 48..63   number of bytes hashed
```

`0` (64-bit) or `0xffffffff` (32-bit) in a slot means "not used". A key whose
CRC-16 and length are zero is compared on its CRC-32 alone, which is exactly
what the legacy `0x42` records are.

## Matching

For each VBA module the engine hashes the token stream of the three supported
p-code dialects. Each dialect keeps a rolling hash of every opcode byte and a
second rolling hash of the "significant" opcode subset. The record's first two
keys are looked up in a table sorted by `key1`, then `key0`; a record matches
when both equal the module's hash pair. A record with an unset `key1` matches
on `key0` only. The third key is stored but not consulted by the matcher in the
engine build analysed here.

Because the matched input is normalised p-code, these signatures cannot be
expressed as YARA byte strings.

## Coverage in this database

| metric | `0xcf` | `0x42` |
|--------|-------:|-------:|
| records | 5,978 | 2,434 |
| anonymous (real threats) | 5,925 | 2,432 |
| named (`!InfrastructureShared`) | 53 | 2 |

Typical labels are `!#ALF:Trojan:Win32/NeoHash.macropcode` and
`#Virus:X97M/Laroux.ER`. Example keys (TrojanDownloader:O97M/Donoff):

```
key0 = 0x040abe5934d1240b   crc32=34d1240b crc16=be59 len=1034
key1 = 0x026d08989525b2be   crc32=9525b2be crc16=0898 len=621
key2 = unset
```

The decoder is `defender2yara/defender/signature/macro_pcode.py`
(`MacroPcodeSig`); the full engine analysis is in
`doc/sigs/sig_decode_macro_pcode_lua.md`.
