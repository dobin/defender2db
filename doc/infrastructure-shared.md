# `!InfrastructureShared` — the VDM's shared-definition pool

High-level summary. For per-type decoder details see `doc/sig_type_usage.md` and
`doc/sigs/sig_decode_snid_nid64.md`.

## What it is

`!InfrastructureShared` is not a detection. It is a **pseudo-threat container**
in `mpasbase.vdm` where Defender stores reusable definition bodies that real
threats reference instead of embedding.

The VDM is a linked definition database, not a flat list of malware families:

- A real threat record (`SIGNATURE_TYPE_THREAT_BEGIN` … `THREAT_END`) is mostly
  a list of references.
- Shared bodies are stored once and pulled in through `SIGNATURE_TYPE_SNID`
  (`0x7E`) records: a 20-byte record-store key plus the target signature type.
- The SNID key is Defender's definition-store key, **not** a hash of the record
  payload. Many targets are runtime/cloud records that never ship in the VDM
  (`KCRCEX`, `MDBHSTR_EXT`, `FASTPATH_TDN`, `LOCALHASH`, …). A SNID therefore
  cannot be reliably joined to a bucket record by hashing bytes.

Three "!" macro-buckets cover the infrastructure layer. All use **category 43**
and **severity 255 (unrated)**:

| row | defender_id | contents |
|---|---|---|
| `!InfrastructureShared` | `0x7FFFFFF0` | shared signature bodies and definition feeds |
| `!Infrastructure` | `0x7FFFFFFA` / `0xFFFFFFFA` | engine policy data, mostly trusted publishers |
| `FriendlyFiles` | `0x7FFFFFFF` | 1,125,305 known-good SHA-256 hashes |

Names starting with `!` are Defender's internal namespace. Real detections look
like `Trojan:Win32/...`.

## What lives in the pool

`!InfrastructureShared` is a mixed bag, not just "signature bodies":

- **SNID** — indirection entries (49% of its records), mostly group references
  such as `#TopPkg:Prevalent` → `IL2_PATTERN` and
  `!#OrgSignerRmmNormal` → `AAGGREGATOREX`.
- **LUASTANDALONE** — engine Lua scripts (phases such as `SignatureValidator`,
  `GenFirst`, `GenLast`).
- **NID / NID64** — Defender's internal id / naming table.
- **NSCRIPT_BRUTE** — the shared `!#SCPT:` / `!#JSON:` script-pattern library.
- **STATIC / KCRCE / CK records** — known-file and policy tags (`#ClnFile`,
  `#ExpensiveFile`, `#FP:`, `~avir.slow`, …).
- **VDLL_X86 / VDLL_X64** — embedded PE images used by the emulator
  ("virtual DLLs"). The payload starts with an `MZ` header.
- **VERSIONCHECK, AAGGREGATOREX, trusted-publisher/allow-list data**, and more.

85 distinct signature types occur in the pool.

## Statistics

Database used below: signature `1.463.330.0`, engine `1.1.26100.4`
(imported 2026-11-18).

### Share

| metric | value |
|---|---:|
| `threats.db` signature rows | 9,712,585 |
| record bytes | 400.1 MB |
| `!InfrastructureShared` records | 911,958 |
| its record bytes | 149.6 MB |
| share of rows | 9.4% |
| share of bytes | 37.4% |
| `mpasbase.vdm` alone (288.9 MB, 6,186,772 records) | 14.7% of records / **51.8% of bytes** |

It is the largest single record group by bytes — 3.7× `FriendlyFiles`
(40.5 MB).

### Composition

| type | records | % rows | bytes |
|---|---:|---:|---:|
| SNID | 447,605 | 49.1% | 19.9 MB |
| NSCRIPT_BRUTE | 114,976 | 12.6% | 14.3 MB |
| NID | 105,537 | 11.6% | 2.9 MB |
| LUASTANDALONE | 66,308 | 7.3% | 25.6 MB |
| STATIC | 35,428 | 3.9% | 1.9 MB |
| VERSIONCHECK | 23,738 | 2.6% | 0.3 MB |
| PEHSTR_EXT | 23,163 | 2.5% | 4.8 MB |
| AAGGREGATOREX | 14,644 | 1.6% | 2.0 MB |
| NID64 | 12,029 | 1.3% | 0.2 MB |
| KCRCE | 8,287 | 0.9% | 0.4 MB |
| VDLL_X86 | 750 | 0.1% | 49.9 MB |
| VDLL_X64 | 195 | <0.1% | 4.3 MB |

By bytes: **VDLL images 36%**, Lua 17%, SNID 13%, NSCRIPT_BRUTE 10%.

### Labels

- 811,487 records (89%) carry a label; 273,911 distinct labels.
- Largest groups: `#TopPkg:Prevalent` (317,749), `!#OrgSignerRmmNormal`
  (131,524), `#ClnFile` (8,410), `#CFG:A:ClnFile` (2,766),
  `#ExpensiveFile` (1,986), `#Tag` (1,587), then `!#ALF:`, `!#SCPT:`,
  `!#SLF:`, `!#TEL:`, `!#HSTR:`, `!#PUA:` feeds.

### Decode coverage

- 877,582 decoded, 2,199 partial, 32,179 unsupported.
- Unsupported records account for **69.3 MB (46% of the pool's bytes)**, mostly
  VDLL_X86/X64 (54.2 MB). VDLL is the main decode blind spot.

### Real detections vs pseudo-threats

| group | containers | signature rows | bytes |
|---|---:|---:|---:|
| real detections (`category_id != 43`) | 367,915 | 3.76 M | 117.5 MB |
| pseudo/internal (`category_id == 43`) | 6,137 | 5.95 M | 282.6 MB |

Only ~3.0 M signature references back the 367,915 real detection records; the
majority of the VDM is definition plumbing.

## Practical guidance

- For "what malware is in here", filter `WHERE t.category_id != 43`.
- To drop only the three macro-buckets:
  `WHERE t.defender_id NOT IN (0x7FFFFFF0, 0x7FFFFFFA, 0xFFFFFFFA, 0x7FFFFFFF)`.
- Do not discard the pool entirely: it holds the ASR/Lua logic
  (`defender2yara/main.py` targets `2147483632` for ASR) and the
  `!#ALF` / `!#SLF` / `!#SCPT` definition feeds.
- For YARA generation most of the pool is not matchable content: SNID/NID/
  VERSIONCHECK are indirections or gates, Lua is engine logic, and script/HSTR
  feeds already have subset-expansion guard rails in
  `defender2yara/yara/condition.py`.
