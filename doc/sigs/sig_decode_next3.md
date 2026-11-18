# Decoding three more VDM signature types

Follow-up to `cache/sig_type_usage.md` / `cache/functions_vdm.md`.

Build analysed: `cache/mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`.
Addresses below are x64 VAs in the Ghidra project binary `/mpengine.dll`.

| type | id | records | what it is | decoder |
|------|----|--------:|------------|---------|
| `SIGNATURE_TYPE_AAGGREGATOREX` | `0xe7` | 61,055 | boolean expression that combines other signature records by name | `defender/signature/aggregator.py` |
| `SIGNATURE_TYPE_VERSIONCHECK`  | `0x7a` | 84,634 | environment/version gate that enables or skips the records that follow it | `defender/signature/versioncheck.py` |
| `SIGNATURE_TYPE_DEXHSTR_EXT`   | `0xbe` | 3,053  | `HSTR_EXT` string pattern against the DEX string table (already parsed; now also exposes the DEX-specific tail) | `defender/signature/hstr.py` (`DexHStrExtSig`) |

All 61,055 + 84,634 + 3,053 records in `threats.db` now parse without errors.

---

## 1. AAGGREGATOREX (`0xe7`) — rule composition

### What it does

An aggregator never inspects the file. It evaluates a boolean expression over
other signature records that are referenced by name, e.g.

```
HSTR:PWS:Win32/Gina.dll&SIGATTR:PWS:Win32/Gina.dll
```

`&` = and, `|` = or, `!` = not, parentheses group. Atoms are
`KIND:Threat:Platform/Family` where `KIND` selects the record class:

| KIND | meaning (from naming and co-occurrence) |
|------|-----------------------------------------|
| `HSTR` / `MHSTR` / `ALF` / `BRUTE` | string-pattern signatures |
| `SIGATTR` | attribute (SIGATTR) record, e.g. `SIGATTR:Trojan:Win32/AgentBypass.gen!B` |
| `SCPT` / `SCRIPT` / `SCRPT` / `Nscript` | script signatures |
| `Lua` / `LUA` | Lua signatures / Lua predicates (`Lua:VB.TotalMethods:39`) |
| `PEPCODE` / `FOP` | PE code / file-offset patterns |
| `AGG` / `AGGR` | another aggregator |
| `RPF` | resource/file pattern |
| `KCRC` / `SNID` / `TARG` / `JAM` / `TEL` / `PUA` / `CONTEXT` | other signature records / attributes |

Most common kinds in the database: `SCPT` (4362 refs), `HSTR` (1609),
`SCRIPT` (1107), `SIGATTR` (597), `MHSTR` (466), `Lua` (267), `KCRC` (111),
`AGGR` (107), `RPF` (106), `BRUTE` (71), `SNID` (51), `AGG` (45).

Aggregators are how one Defender detection reuses another one, and how PUA /
script / behavior clusters are glued together.

### On-disk layout

```
u8   flags           0x00 or 0x01  (0x01 only on 186 records; forwarded to the
                                    expression compiler, meaning not confirmed)
u8   name_length     0x00..0x40; names exist in !InfrastructureShared
u16  body_length
u8   name[name_length]   plain text
u8   body[body_length]   substituted
```

The **body** is obfuscated with a **256-byte static substitution table**
(a permutation, so it is not compression); the optional **name is plain
text**. The loader applies the table to the body right after copying the
record, and interns the name verbatim:

```python
decoded_byte = TABLE[stored_byte]
```

Table VA: **`0x180d9e080`** (256 bytes). It is reproduced verbatim in
`aggregator.py` as `AGGREGATOR_SUBSTITUTION` (plus `encode_aggregator` for the
inverse). After decoding, the body is UTF-8 (a few signatures intentionally
contain Cyrillic/Chinese look-alike characters, e.g.
`Lua:PeCompanyName!Ϻicrоsоft__corpоratiоn`).

### Engine functions

| address | role |
|--------:|------|
| `0x18098f6a0` | `aggregator` module init: allocates the pool, registers the `0x96` and `0xe7` record handlers |
| `0x180185410` | **`0xe7` record handler** (the layout above): validates header, computes `crc32(payload)` and the packed id `crc \| len << 40 \| 0xe7 << 32`, hashes the record for the record store, applies the substitution table, then compiles the expression |
| `0x180d9e080` | 256-byte substitution table |
| `0x1801858a8` | expression compiler/registrar: splits on `&` / `|`, resolves atoms, registers parsed sub-expressions |
| `0x180186b84` | record registration helper (same record store used by SNID) |
| `0x180156440` | runtime evaluator of a stored aggregator (resolves strings from the aggregator string pool, applies operations per record) |
| `0x18098eba0` | interns an attribute name; builds the 8-byte `{hash, 24-bit pool offset, length}` key |
| `0x18098e6d0` | string-pool allocator (`"Aggregator string pool exhausted"` / `"Invalid aggregator string offset"`) |
| `0x18041a5d0` | `0x96` (`AAGGREGATOR`) handler, the older non-`EX` form |

The older `0x96` form uses the same layout and grammar but stores the body in
plain text (handler `FUN_18041a5d0`); it is decoded in
`doc/sigs/sig_decode_aggregator_paths.md`.

---

## 2. VERSIONCHECK (`0x7a`) — environment gate

### What it does

The record is **not a detection and is not registered** as a signature. The
database loader evaluates it immediately and stores only a boolean:

```c
/* FUN_180183894, 0x7a case */
if (bVar11 == 0x7a) {
    if (size < 8) error;
    if (records_enabled || *payload32 == 0)
        records_enabled = FUN_1804f9434(0x7a, size, payload32[0], payload32[1]);
    goto next_record;
}
...
if (!records_enabled) { skip this record; }   /* gates everything that follows */
```

So a `VERSIONCHECK` is a **gate for the records that follow it in the same
threat**: if the local engine/OS/definition environment does not satisfy the
check, the rest of the threat's signatures are not loaded. `check_id = 0`
always passes and is used to re-enable loading; the pair
`check_id = 0x77, value = 1` is the modern unconditional form.

Note the loader's short circuit: when records are already disabled, only a
record whose `check_id == 0` is evaluated. A later conditional gate is skipped,
so only the always-true reset can turn loading back on.

This explains the shape of many threats: real records surrounded by
`VERSIONCHECK` gates, and `0x00000000/0x00000000` stubs (equal to "always
pass"). `FUN_180607434` / `FUN_180607850` (the `badrecs` fixup) even rewrite
unsupported records into zeroed `0x7a` stubs.

### On-disk layout

```
u32 check_id
u32 value
```

### Check ids (`FUN_1804f9434`)

The predicate is `target REL value` and the record passes when it is true.
Ids observed in the database (count of all 84,634 records):

| id | count | meaning (`target REL value`) |
|---:|------:|------------------------------|
| `0x00` | 42,317 | always true (re-enable) |
| `0x77` | 5,252 | engine kind/feature gate; `value == 1` ⇒ always true |
| `0x31` | 3,833 | Defender for Endpoint / "Seville" enabled (`MpSevilleEnable`, flag `+0xb43`) |
| `0x34` | 3,264 | PUA protection enabled (`MpEnablePUS`, engine PUA mode, flag `+0xb47`) |
| `0x38` | 3,113 | definition-version timestamp |
| `0x3c`-`0x3f` | 2,761 each | dword 0..3 of the 16-byte **definition-set digest** (`ctx+0x15870`) |
| `0x58` | 1,448 | `engine_field_0xb98 > value` |
| `0x2c` | 1,232 | definition-version timestamp |
| `0x63`-`0x65` | 1,220 each | dword 0..2 of the **engine-version digest** (`ctx+0x15880`) |
| `0x66` | 1,220 | `engine_field_0x1588c == value` |
| `0x6f` | 990 | `dword(0x15970) > value` |
| `0x14` | 980 | `engine_field_0xb60 == value` |
| `0x29` | 821 | `global_engine_version == value` |
| `0x05` | 678 | definition-version timestamp |
| `0x27` | 557 | `value < os_build` (`ctx+0xb8c`) |
| `0x46` | 402 | `value < timestamp_0x158e0` |
| `0x83` / `0x85` | 310 / 100 | product version `==` / `>` |
| `0x2f`, `0x30`, `0x3a`, `0x40`, `0x3b`, `0x41`, `0x22`, `0x13`, `0x12`, `0x26`, ... | | see table in `versioncheck.py` |

Decoded ranges:

* `0x01`-`0x03` — engine build against the analysed constant `0x65f4` (26100,
  i.e. `1.1.26100.x`): `>` / `<` / `==`.
* `0x04`-`0x35` — mostly `(engine_field ++0xbNN) REL value` triples
  (`<`, `>`, `==` in groups of three), with `bool(flag_0xbNN) == value != 0`
  for the single-byte engine feature flags.
* `0x3c`-`0x3f` — the four dwords of a **16-byte digest of the signature /
  definition version string** (built by `FUN_1805b53c0` from the version
  string that `FUN_18058f8b4` stores at `ctx+0x158b0`). This pins a signature
  block to the exact definition release it was compiled against.
* `0x63`-`0x65`, `0x66` — the same idea for the **engine version** digest
  (`ctx+0x15880..0x15888`).
* `0x05`, `0x2c`, `0x36`, `0x38` — definition-version *timestamp* comparison;
  `0x22`, `0x2d`, `0x37`, `0x39` are the inverted variants (and return true on
  mismatch). The value is `(table_index << 24) | milliseconds`.
* `0x26`-`0x28` — **OS build number**. The values observed are real Windows 10
  builds: 15063 (1703), 16299 (1709), 17763 (1809), 18363 (1909). So
  `ctx+0xb8c` is the OS build; `0xb84` / `0xb88` are the surrounding version
  dwords.
* `0x45`/`0x46` — against a FILETIME-ish value at `ctx+0x158e0`.
* `0x61`/`0x62` — against `ctx+0xbe8`, computed at init as
  `(now - some_install_time) / 864000000000` (days since engine data install).
* `0x6a`-`0x6f` — the high / low dword of the 64-bit value at `ctx+0x15970`.
* `0x75`-`0x77` — engine product/kind enum (`ctx+0xb20` in
  `{7, 18, 21, 23}`, or `0x17`); `0x76`/`0x77` accept a "trivial" value.
* `0x7a`-`0x7c` — `value <= 4` / `>= 4` / `== 4`.
* `0x9a`-`0xa8` — same fields as the earlier ids but with **inverted** sense
  (`pass when not equal`). `0x72` is likewise `pass when != value`.
* `0x4b` — always false (kill switch for subsequent records).

The engine "environment block" starts at `DAT_18111e110 + 0xb20` and is
filled by `FUN_18058f8b4`; it mixes numeric version/product fields, feature
bit flags, OS version and digest fields. `FUN_1804c0978` / `FUN_1804e0920`
return the "platform version" / "product version" ids used by `0x80`-`0x85`.

### Decoded feature flags

The assignments in `FUN_18058f8b4` plus the policy each flag is read from
identify the most common boolean flags. Confirmed meanings:

| flag | meaning | evidence |
|-----:|---------|----------|
| `+0xb42` | Microsoft-internal build | `SQMClient\MSFTInternal` (`FUN_180752530`) |
| `+0xb43` | Defender for Endpoint / "Seville" | `MpSevilleEnable` policy; "Seville" was the codename of Defender ATP/MDE |
| `+0xb44` | Sense/EDR sensor installed | `FUN_180752424` checks `Services\Sense` → `MsSense.exe` |
| `+0xb46` | MBA policy | `MpEnableMBA` policy |
| `+0xb47` | **PUA/PUS protection** | `MpEnablePUS` policy; also engine `puamode` (1 or 2). Heartbeat writes `"puamode"` from `+0x158f8` only when this flag is set (`FUN_1804fe53c`). `FUN_180447d7c` suppresses `PUA:` threats when `+0xb47` is clear. |
| `+0xb49` | automatic sample submission | heartbeat `"autosubmit"`; derived from `autosampleoptinvalue` |
| `+0xb4a` | PUA removal | `MpEnablePUSRemoval` policy |
| `+0xb50` | test signing | `NtQuerySystemInformation(SystemCodeIntegrityInformation)` option bit 1 |
| `+0xb51` | Windows Lockdown Mode | `WldpQueryWindowsLockdownMode` |
| `+0xb52` | Developer Mode | `AppModelUnlock\AllowDevelopmentWithoutDevLicense` |
| `+0xb54` | inside a container | heartbeat `"isincontaineros"` |

Flags without a confirmed meaning stay labelled as internal engine feature
flags. This is what the UI now shows, instead of only `bool(flag_0xb47) ==
True`.

Worked example: `PUA:Win32/Puwaders.C!ml` has
`VERSIONCHECK 0x34/1`, a `NID64`, then `VERSIONCHECK 0x00/0`. The first gate
means the NID64 only loads when PUA protection is enabled, so the PUA detection
only fires on machines with PUA mode on. The second record is only a reset
point: check id 0 returns true immediately and re-enables loading. "Always
true" therefore describes the gate, not the detection.

---

## 3. DEXHSTR_EXT (`0xbe`) — DEX string patterns

### What it is

The Android/Dalvik flavour of the generic `HSTR_EXT` string-pattern signature.
The format is the same as `PEHSTR_EXT` and friends (already handled by
`HStrExtSig`): a header, then weighted sub-rules whose bytes are matched, with
`0x90` wildcard opcodes:

```
90 01 XX     skip exactly XX bytes
90 02 XX     skip 0..XX bytes
90 03 XX YY  one of two byte sequences
90 04/05     regex-like (case sensitive / insensitive)
90 00        end of pattern
```

DEX `string_data_item` entries are prefixed with a uleb128 length (normally two
bytes), so DEX signatures usually look like:

```
03 "hi,xiaolu"  90 01 02  "hi,liqian"  90 01 02 "command ok" 90 01 02 "bye" 90 00
```

The plain parser already produced good YARA strings for all 3,053 records
(verified: no exceptions, no non-printable output).

### Extra DEX-specific detail

1. **Trailing flags word.** The generic layout ends with `u16 0x0000`
   (end of sub-rule list). About 14% of `0xbe` records have one more `u16`
   after that terminator. It behaves like a bitmask (observed values 1, 2, 3,
   4, 5, 6, 7, 8, 10, 11, 17, 20, 31, 41, 43, 46 — all combinations of the
   low six bits), e.g. `Trojan:AndroidOS/FakeInstSms.C` ends with
   `... 00 00 03 00`. Exposed as `DexHStrExtSig.flags` /
   `.flags_present`. The exact bit meanings are not confirmed.
2. **Name-reference form.** 287 `0xbe` records inside the
   `!InfrastructureShared` bucket are not string patterns at all: the reserved
   header byte (offset 6) is `0x21` (`!`) instead of `0`, and the payload is a
   plain text reference such as `#Tel:Trojan:AndroidOS/Fakecalls.YU`. Those are
   detected as `is_name_reference` and left unparsed.

---

## Resulting code

* `defender2yara/defender/signature/aggregator.py` — `AaAggregatorExSig`,
  `decode_aggregator` / `encode_aggregator`, substitution table.
* `defender2yara/defender/signature/versioncheck.py` — `VersionCheckSig`,
  `VERSION_CHECK_IDS` / `ENGINE_FLAGS` tables, `describe()` and
  `describe_version_check()` (user-facing summary, explanation and flag
  meanings, also used by the web UI).
* `defender2yara/defender/signature/hstr.py` — `DexHStrExtSig`.
* `defender2yara/defender/vdm.py` — dispatch for `0xbe`, `0xe7`, `0x7a`.
* `defender2yara/threat_api.py` — `annotate_version_gates()` adds the
  "which following records does this gate control?" / `gated_by` context used
  by the threat page.
* `app/templates/signatures/versioncheck.html`, `app/static/sigs/SIG_VERSIONCHECK.md`
  — the user-facing version-check card and explanation.
* `tests/test_signature_next3.py` — vectors from the real database.
