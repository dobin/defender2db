# DEXHSTR_EXT: DEX / Android string-table signatures

`SIGNATURE_TYPE_DEXHSTR_EXT` (`0xbe`) is the Android/Dalvik member of
Defender's HSTR family. It matches weighted string patterns against entries in
a DEX file's string table (`classes.dex`, usually inside an APK).

It is **not** a file hash and not a whole-file fingerprint. It is also not
limited to string identity: a record can require several weighted fragments
and can include HSTR wildcards.

## The short version

```
u16  score_or_flags    usually the same value as threshold
u16  threshold         minimum total weight required for a hit
u16  rule_numbers      number of sub-rules
u8   name[]             NUL-terminated label (empty in real threat records)
sub-rule[rule_numbers]:
    i16 weight
    u8  size
    u8  flags           bit 0 case-sensitive, bit 1 wildcards,
                        bit 7 extended header
    u8  extra           only when flags & 0x80
    u8  bytes[size]
u16 tail_word1          optional
u16 tail_word2          optional ("DEX flags")
```

The sub-rules are UTF-8 DEX string fragments. DEX's `string_data_item`
prefixes every string with a uleb128 length, so signatures commonly skip those
bytes explicitly:

```
68 69 2c 78 69 61 6f 6c 75 90 01 02 68 69 2c 6c 69 71 69 61 6e
"hi,xiaolu"                skip 2        "hi,liqian"
```

## Flag bits

| bit | meaning |
|----:|---------|
| `0x01` | case-sensitive match (the normal case for DEX identifiers) |
| `0x02` | the pattern contains `90` wildcard tokens; it must end with `90 00` |
| `0x80` | extended header: one `extra` byte sits before the pattern |
| extra `0x01` | additionally register a terminator-less variant of the pattern |

## Wildcards

| token | rendering | meaning |
|-------|-----------|---------|
| `90 00` | (end) | NUL/end of pattern |
| `90 01 NN` | `<skip NN>` | skip exactly `NN` bytes (uleb128 length etc.) |
| `90 02 NN` | `<skip 0..NN>` | skip 0..`NN` bytes |
| `90 03 C M mask` | `<any-of {...} xC>` | consume `C` bytes from a byte class |
| `90 04 N L bytes` | `<repeat N of ...>` | repeat one of the listed bytes |
| `90 09 NN MM` | `<op 09 ...>` | engine multi-byte check |

## Examples

`TrojanSpy:AndroidOS/Geimini.A`:

```
hi,xiaolu<skip 2>hi,liqian<skip 2>command ok<skip 2>bye
AdActivity<op 09 0c00>com<any-of {2e} x1>/geinimi
processDOWNLOAD_FAILUE_Action
```

`TrojanSpy:AndroidOS/Adrd.A`:

```
adrd.xiaxiab.com/pic.aspx?im=<op 09 0700>http://
M032890500170758.mp3
go_g1_sms
```

`Trojan:AndroidOS/Denofow.A` stores ten long exact sentences, for example
`Its the Raptures,praise Jebus` and `Prepare to meet thy maker...`.

## Name field and "reference" records

Real-threat records are anonymous. The 287 records in `!InfrastructureShared`
use the name field as a feed label, for example
`!#Tel:Trojan:AndroidOS/Fakecalls.YU`, `!#TEL:Trojan:AndroidOS/Piom.K` and
`!#ALF:Trojan:AndroidOS/...`.

Older tools treated these records as "name references without a pattern".
That is not correct: the sub-rules follow the NUL and are real DEX string
patterns. For example:

```
!#Tel:Trojan:AndroidOS/Fakecalls.YU   -> |*callEntity*|
!#HSTR:AndroidOS/LimtPkg              -> com/limitemp/interstellar/app/
!#PUA:Block:Notifyer.B                -> /MyPushListener, /onejson, strimglink
```

This decoder keeps both the label and the patterns.

## The trailing "DEX flags" word

424 records carry a second tail word (`tail_word2`). Observed values are
1..8, 10, 11, 17, 20, 31, 41, 43 and 46, with 3, 4 and 5 most common. It is a
small option/scoring word, not a byte pattern; its exact engine use has not
been decoded.

## Coverage in this database

| metric | value |
|--------|------:|
| records | 3,053 |
| real-threat records | 2,766 (2,653 threats) |
| shared feed copies | 287 |
| sub-rules | 16,409 |
| case-sensitive sub-rules | 10,402 |
| wildcard sub-rules | 526 |
| extended-header sub-rules | 117 |
| records with the second tail word | 424 |

## YARA note

DEX patterns are plain UTF-8/ASCII fragments, so they convert cleanly to YARA
text or hex strings and remain useful against an extracted `classes.dex` or an
APK. They identify string content, not the APK container or the file hash.
