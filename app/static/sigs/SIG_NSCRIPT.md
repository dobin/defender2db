# NSCRIPT signatures: script content rules

`SIGNATURE_TYPE_NSCRIPT_SP` (`0x28`) and `SIGNATURE_TYPE_NSCRIPT_BRUTE`
(`0x29`) are Defender's **script content signatures**. They are evaluated only
after the engine has identified a file as script text (or extracted script from
an Office/HTML container), not against ordinary executable bytes.

## The short version

* `NSCRIPT_BRUTE` is the readable one: a **normalised script fragment** such as
  `eval(<skip 0..3>)` with wildcards, plus an optional script-type restriction
  and a search direction.
* `NSCRIPT_SP` is the **hash form**: two 32-bit hashes of normalised script
  fragments plus the length of the script window they cover. It contains no
  text, so it cannot be reconstructed.

Both types are produced by the `nscript` module (`FUN_180a65d00` in mpengine).

## `NSCRIPT_BRUTE` (`0x29`)

```
name_len     0..0x3f, 0 = anonymous
name         optional engine list label, e.g. !#SCPT:Trojan:JS/NPMInstall.PR!AMTB
kind/flag    low 7 bits = script type, bit 7 = extra flag
mode         0 = anywhere, 1 = forward, 2 = backward
any_length   skip limit; 0xffffffff = unset
pattern      normalised script text + 0x90 wildcard tokens, ends with 90 00
```

### Script type

| value | type | value | type |
|------:|------|------:|------|
| 1 | VBScript | 5 | PowerShell |
| 2 | JavaScript / JScript | 6 | Python |
| 3 | batch | 0 or 7 | any script type |
| 4 | IRC script | | |

83% of the shipped records are script-type agnostic. JavaScript and PowerShell
are the most common explicit types.

### Wildcards

The pattern is lower-case script text with whitespace removed. `0x90` introduces
wildcard opcodes, the same family used by `PEHSTR_EXT`:

| bytes | meaning |
|-------|---------|
| `90 00` | NUL byte / end of the string |
| `90 01 XX` | skip exactly `XX` bytes |
| `90 02 XX` | skip 0..`XX` bytes |
| `90 1b ...` | loose token; the match does not need to be contiguous |

Other opcodes exist and are rendered generically as `<op NN ...>`.

### What it looks like

```
Trojan:HTML/Webber.A
  <imgwidth=50height=100style="display:none"><skip 0..19>
  <objectdata="http://www.oil-bank.ru/cgi-bin/<skip 7>counter.cgi?action=click">

Worm:Win32/Bagle.O
  <html><body><fontface="system"><objectstyle="display:none"
  data="http://<skip 0..3>.<skip 0..3>.<skip 0..3>.<skip 0..3>:81/<skip 0..8>.php"

Worm:DOS/Crack.B   (IRC worm)
  /msg#gigaviriii'mwideawakeinmykitchen,it'sdarkandi'mlonely,...
```

Real threats contain 32,738 anonymous `NSCRIPT_BRUTE` records. The other
114,976 records are the shared pattern library in `!InfrastructureShared` and
carry reference labels such as `!#SCPT:` (script pattern), `!#JSON:` (JSON
pattern) and `!#SCPT:FakeLogin...`.

Unlike the hash forms, a brute pattern can be converted into a YARA string; the
project exposes `pattern_text` for that purpose.

## `NSCRIPT_SP` (`0x28`)

```
name_len     0..0x3f, 0 = anonymous
name         optional engine list label, e.g. !#TEL:HTML/CoinHive.C!lib
hash1        first normalised-script hash
flags        bit 7 = extra flag; low bits 0..4 observed
hash2        second normalised-script hash
match_length script window length (23..0x1000 in the database)
```

The engine stores `{hash1, match_length, hash2, condition_id, flags}` and
compares the hashes against rolling CRC32/CRC16 values of the script it has
read. `match_length` is the window size, clamped at the engine's 4 KiB script
ring buffer (1,184 records use exactly `0x1000`).

`flags & 0x7f` in `{1, 2}` triggers a legacy special case for names containing
`:IRC/`; bit `0x80` is kept as an extra engine flag.

### Why there is no text

`hash1` and `hash2` are outputs of the script normaliser. The record does not
keep the fragment, the wildcard layout or the anchoring mode. It can be decoded,
counted and correlated, but not turned into a readable pattern.

599 `NSCRIPT_SP` records carry an engine label (484 distinct), mostly exclusions
and telemetry feeds:

```
!#TEL:HTML/CoinHive.C!lib
!#SCPT:O97M/CVE-2012-0158.RA!MTB
!#SCPT:HijackLoader!DSK
!#SCRIPT:Backdoor:Win32/AluminumApt!lowfi
```

## `NSCRIPT_NORMAL` (`0x27`)

`NSCRIPT_NORMAL` is the general container for the same condition vector:

```
u8  name_len; u8 name[name_len]
u8  count
u32 hash_a[count]
u8  flags
flags == 0:  u32 hash_b[count]          every hash is a pair
flags != 0:  u32 hash1, u32 match_length  rolling-window condition
             u32 hash_b[count]          optional; hash_b[0] reserved
optional:    u32 weight                 only the low byte is used
```

With `flags == 0` every `{hash_a[i], hash_b[i]}` pair is a two-hash condition.
With `flags != 0` the first condition is exactly an `NSCRIPT_SP`-style window
(`hash1`, `match_length`, `hash2 = hash_a[0]`); flags `1`/`2` carry the same
legacy `:IRC/` special case.  Real threats contribute 9,775 records; 9,917 are
ordinary hash-pair records, 787 are window conditions, and 11 are a compact
variant without the `hash_b` array.  The hashes are still normalised script
fragments, so this type cannot be rendered as text either.

## Related types

* `NSCRIPT_CURE` (`0x2c`) is a bytecode-like script record used by feeds.
* `MACRO_SOURCE` (`0x43`) is the macro/VBA equivalent of these script rules;
  see `SIG_MACRO_SOURCE.md`.
* `NSCRIPT_NORMAL` (`0x27`) is now decoded; `NSCRIPT_CURE` is not.
