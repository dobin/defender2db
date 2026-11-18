# KPAT / KPATEX: key patterns

`SIGNATURE_TYPE_KPAT` (`0xbb`) and `SIGNATURE_TYPE_KPATEX` (`0xbc`) are
Defender's **key patterns**: real byte patterns for files or memory regions
that do not have a fixed file format.  They are used by the boot-sector /
MBR / VBR scanner, the memory and decompressed-buffer scanners, and the VBA
macro reader.

Every record starts with a **literal 8-byte anchor** (the engine's fast index
key) followed by the rest of the pattern.

## `KPAT` (`0xbb`)

The remaining bytes are a plain byte pattern.  A `0x90` byte in that part
matches **any single byte**; the 8-byte anchor is always literal and `0x00` is
a literal NUL.

```
Virus:DOS/Rex.1637
  b8 01 03 bb 00 06 b9 01 00 ba 80 00 cd 13 be be 07 80 3c ...
```

Most `KPAT` records are DOS/boot virus code.  Some are text or key-material
patterns (PDF headers, RC4 keys, Meterpreter stubs).

## `KPATEX` (`0xbc`)

The remaining bytes use Defender's extended wildcard language:

| token | meaning |
|-------|---------|
| `90 00` | end of pattern |
| `90 01 n` | skip `n` bytes |
| `90 02 n` | skip 0 to `n` bytes |
| `90 03 ...` | byte class |
| `90 04` / `90 05` | repeat a sub-pattern |
| `90 90` | a literal `0x90` |

```
Worm:Win32/Autorun!inf
  0d 0a 5b 41 75 54 6f 72 75 6e 5d [0-255] 0d 0a 61 63 74 69 4f 4e 3d
```

`KPATEX` records are mostly SWF/ActionScript bytecode, `autorun.inf` text and
shellcode.

## The optional name

A record may end with a short label.  In the shared definition bucket the label
looks like `!#KPAT:PDF_Subtype` and is referenced by aggregator rules as
`KPAT:PDF_Subtype`.  Records that belong to a real threat are anonymous; an
aggregator addresses those as `KPAT:<threat name>`.

## Coverage

| type | records | real-threat records | shared / named |
|------|--------:|--------------------:|---------------:|
| `KPAT` | 208 | 183 | 25 |
| `KPATEX` | 123 | 82 | 41 |

Both are expressible as YARA hex strings (`??`, `[n]`, `[0-n]`), but no rule
generator is wired up.  Full reverse-engineering notes:
`doc/sigs/sig_decode_kpat.md`.
