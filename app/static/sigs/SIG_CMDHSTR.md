# CMDHSTR_EXT / CMDHSTR_FAST_EXT: command-line content signatures

`SIGNATURE_TYPE_CMDHSTR_EXT` (`0xd7`) and
`SIGNATURE_TYPE_CMDHSTR_FAST_EXT` (`0xdd`) are Defender's **command-line**
signatures. They are matched against the command line of a process (including
task-scheduler and BITS command lines and PowerShell base64-decoded content),
not against the bytes of a file and not against a file hash.

They belong to the same HSTR family as `PEHSTR_EXT`, `DEXHSTR_EXT` and the
other `*HSTR_EXT` types, so they use the same record container and the same
weighted sub-rule model.

## The short version

Each record contains one or more weighted command-line fragments:

```
u16  score_or_flags    usually the total positive weight (and == threshold)
u16  threshold         minimum total weight required for a hit
u16  rule_numbers      number of sub-rules
u8   name[]             NUL-terminated label (empty in real threat records)
sub-rule[rule_numbers]:
    i16 weight          positive = score, negative = exclusion/penalty
    u8  size
    u8  flags           bit 0 case-sensitive, bit 1 wildcards,
                        bit 7 extended header
    u8  extra           only when flags & 0x80
    u8  bytes[size]
u16 tail_word1          optional
u16 tail_word2          optional
```

There is no extra terminator word between the sub-rules and the tails.

Command-line patterns are mostly **UTF-16LE** (Windows command lines are wide
strings), with some plain ASCII. Wildcards from the HSTR opcode table are
embedded as `0x90` tokens.

## Flag bits

| bit | meaning |
|----:|---------|
| `0x01` | case-sensitive match; when clear the engine lower-cases the pattern |
| `0x02` | the pattern contains `90` wildcard tokens; it must end with `90 00` |
| `0x80` | extended header: one `extra` byte sits before the pattern |
| extra `0x01` | additionally register a terminator-less variant of the pattern |

## Wildcards

| token | rendering | meaning |
|-------|-----------|---------|
| `90 00` | (end) | NUL/end of pattern |
| `90 90` | `\x90` | literal `0x90` |
| `90 01 NN` | `<skip NN>` | skip exactly `NN` bytes |
| `90 02 NN` | `<skip 0..NN>` | skip 0..`NN` bytes |
| `90 03 C M mask` | `<any-of {...} xC>` | consume `C` bytes from a byte class |
| `90 04 N L bytes` | `<repeat N of ...>` | repeat one of the listed bytes |
| `90 09 NN MM` | `<op 09 ...>` | engine multi-byte check |

## What it means in practice

The record matches a piece of a command line. For example
(`Trojan:Win32/Kovter.G`):

```
mshta<skip 0..16>javascript:<skip 0..255>new activexobject(
```

and (`TrojanDownloader:PowerShell/Falsip.C`):

```
powershell.exe
=$env:temp+[char][byte]92+'15<skip 0..32>.js';...DownloadFile('http
.jse',$d);Invoke-Item $d;
```

The most common families in this database are ClickFix/SuspClickFix,
PowerShell downloaders, `mshta` launchers, proxy/tamper tools and
credential-dumping utilities.

## Name field

Real-threat records are anonymous. The copies in `!InfrastructureShared` carry
a feed label: `!#SLF:` (most common), `!#TEL:`, `!#ALF:`, `!#HSTR:`, `!#CMD:`,
`!#SLFPER:`, `!#TELPER:` and a few one-offs.

## Coverage in this database

| metric | `0xd7` | `0xdd` |
|--------|-------:|-------:|
| records | 5,415 | 2 |
| real-threat records | 2,941 | 2 |
| shared feed copies | 2,474 | 0 |
| sub-rules | 30,142 | 6 |
| UTF-16LE / ASCII patterns | 27,848 / 2,294 | 0 / 6 |
| wildcard sub-rules | 4,074 | 0 |
| extended-header sub-rules | 1,661 | 0 |
| negative-weight sub-rules | 2,859 | 0 |

`0xdd` (fast variant) has only two `Trojan:Linux/FchsE2ETest*` test records in
the shipped definitions.

## YARA note

The decoder can render the patterns as YARA strings (ASCII or wide hex), and
the project keeps them with the other `*HSTR_EXT` rules. A YARA scan only sees
files, so a CMDHSTR rule is useful when the scanner is pointed at a command
line, a process-creation log or an in-memory wide string. It is not a
file-content hash and generally will not match executable bytes.
