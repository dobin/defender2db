# BRUTE: generic script brute patterns

`SIGNATURE_TYPE_BRUTE` (`0xd0`) is a **script-text brute pattern**.  It uses
the same payload and `0x90` wildcard language as
`SIGNATURE_TYPE_NSCRIPT_BRUTE` (`0x29`), but it is stored in a separate,
script-type-agnostic table.

```
u8  name_length       0..0x3f (0 = anonymous)
u8  name[name_length] feed label, not NUL terminated
u8  kind_and_flag     low 7 bits script kind, bit 7 = extra flag
u8  mode              0 anywhere, 1 forward, 2 backward
u32 any_length        low 16 bits; 0xffffffff = unset
u32 pattern_length
u8  pattern[pattern_length]  normalised script text + 90xx wildcards,
                             ends 90 00
```

In the shipped database **every** record uses script kind 0 ("any"), so a
pattern is not restricted to JS/VBS/PowerShell.  These patterns power the
`BRUTE:JS:Feature:` / `BRUTE:VBS:Feature:` / `BRUTE:PDF:Feature:` feature names
and the `mp.GetBruteMatchData()` / `mp.ReadBruteMatchBuffer()` Lua API.

```
!#SCPT:AICustomDiscovery.ClaudeAgentSDKPy
  any anywhere  'ClaudeAgentOptions'

Backdoor:Win32/Plugx.I
  any forward   \x34\x1d\x1c...<wildcards>
```

## Coverage

| metric | value |
|--------|------:|
| records | 5,703 |
| labelled / anonymous | 3,978 / 1,725 |
| script kind | all "any" |
| mode | anywhere 4,405, forward 1,041, backward 257 |
| pattern length | 6 .. 1,539 (median 25) |
| with wildcard tokens | 2,404 |

The patterns are readable script fragments and can be rendered as YARA
strings/hex (`??` for single-byte wildcards, `[n]` for skips), but no rule
generator is wired up.  Full reverse-engineering notes:
`doc/sigs/sig_decode_ndat_brute_boot.md`.
