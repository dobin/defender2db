# Decoding SNID and NID64

Follow-up to `doc/sigs/sig_decode_more3.md` (NID, sig trees) and
`doc/sigs/sig_decode_first3.md` (SNID, STATIC, KCRCE). This note covers the two
remaining reference record types in the top of `cache/sig_type_usage.md`:

| type | id | records in `threats.db` | threats using | what it is |
|------|----|------------------------:|--------------:|------------|
| `SIGNATURE_TYPE_SNID` | `0x7e` | 2,203,169 | 21,422 | reference to a shared signature record by 20-byte store key + type |
| `SIGNATURE_TYPE_NID64` | `0xce` | 1,919 | 1,522 | NID with a 64-bit id |

Build analysed: **x64** `mpengine.dll`, engine `1.1.26100.4`, signature
`1.463.330.0`. Addresses are VAs in the Ghidra project for that build. (The file
under `cache/mpengine.dll` in this checkout is the **32-bit** engine; use the x64
copy from the Defender package for these addresses.)

Payload statistics below come from the merged 288 MB VDM record stream
(`cache/_mpas_merged.bin`, 6,186,772 records) and from `cache/threats.db`.  The
merged stream is the **deduplicated record compendium** (for example it contains
262,852 STATIC records, the same number as the "unique records in merged VDM"
figure in `cache/sig_type_usage.md`), so its counts are unique record bodies, not
per-threat references.  `threats.db` counts every reference inside every threat.

---

## 1. SNID (`0x7e`) — shared-record reference

### Layout

```
u8  record_key[20]     key of the referenced record in the record store
u8  record_sig_type    signature type of the referenced record
u8  name[]             optional NUL-terminated group/definition name
```

* Base form: 21 bytes (`2,046,138` records in the merged stream).
* Extended form: 21 + name (up to 78 bytes observed; `436,206` records, `39,133`
  distinct names). All extended records are in `!InfrastructureShared`.

### Engine evidence

`FUN_18010df68(table, out, bucket, query, out_recid)` is the lookup that builds
the SNID payload:

* The record-store table has 32-byte entries. Bytes `0x00..0x13` are the 20-byte
  key, the record type is at `+0x14`.
* The query is a 20-byte key (`query+0x10`) plus a type (`query+8`); the bucket
  index is the first dword of the key.
* After a `(key, type)` match it copies the entry's 20-byte key and the type byte
  at `+0x14` into a 21-byte buffer and calls
  `FUN_180217edc(out, 0x7e, buffer, 0x15)`.

So the on-disk record is literally a serialised `(store key, record type)` pair.
`FUN_18010dc74` is the wrapper that tries the two record tables (`table+8` and
`table+0x90`); the `SNidSearch` definition command (`FUN_18037dfc0`) takes a
40-character SHA-1 string, converts it to 20 bytes and calls this wrapper.

The record store is keyed by `(20-byte key, type)`, so SNID is a deduplication
entry: a threat references a shared record instead of embedding its body. A match
on an SNID does not detect anything by itself; the engine resolves the reference
and evaluates the target record.

### The key is opaque, not a payload hash

We tested whether the 20-byte key is a hash of a shipped record:

* SHA-1 of every record payload (6,146,878 unique hashes) and of every full TLV
  (6,146,959) against all 2,481,835 unique SNID keys: **2 hits**, both accidental
  matches on a 4-byte all-zero `THREAT_END` payload.
* MD5 of payload/TLV and SHA-1 truncated to 16 bytes: **no hits**.

The key is the record store's own key (a definition-identity hash, e.g. computed
from the definition source), not a hash of the serialised VDM payload. This is
consistent with `SNidSearch` accepting a SHA-1 supplied by definition authors.

Some families use a 16-byte key zero-padded into the 20-byte field. Measured
effective key length (leading/trailing zero bytes stripped) per referenced type:

| referenced type | effective length | padding | examples |
|---|---:|---|---|
| `LOCALHASH` `0x62` | 16 | 4 zero bytes at the end | 112,674 records |
| `FTRIE_POS` `0xcd` | 16 | 4 zero bytes at the end | 15,432 |
| `GENSFX` `0x56` | 16 | 4 zero bytes at the end | 1,731 |
| `MACHOHSTR_EXT` `0x8d` | 16 | 4 zero bytes at the front | 194 |
| `ELFHSTR_EXT` `0x8c` | 16 | 4 zero bytes at the front | 158 |
| most others (`KCRCEX`, `IL2_PATTERN`, …) | 20 | none | — |

That padding matches the internal key structs of those record families (digest +
size/flags word), not a different hash algorithm.

### Referenced types

`2,482,344` SNID records in the merged stream, by referenced type:

| type | id | references | present in VDM? |
|---|---:|---:|---|
| `KCRCEX` | `0xcc` | 422,922 | no (runtime) |
| `IL2_PATTERN` | `0xa6` | 317,749 | yes (140) |
| `TRUSTED_PUBLISHER` | `0x70` | 258,943 | yes (92,919) |
| `AUTOITHSTR_EXT` | `0xd3` | 236,753 | yes (119) |
| `MDBHSTR_EXT` | `0xe4` | 142,695 | no (cloud/MDB) |
| `PESTATICEX` | `0xcb` | 132,413 | no |
| `FASTPATH_TDN` | `0xd8` | 128,975 | no |
| `LOCALHASH` | `0x62` | 113,525 | no (runtime) |
| `EXPLICITRESOURCEHASH` | `0xd9` | 73,143 | no |
| `AAGGREGATOREX` | `0xe7` | 55,275 | yes (24,260) |
| `NID64` | `0xce` | 20,635 | yes (12,109) |
| `CMDHSTR_FAST_EXT` | `0xdd` | 63,398 | no |
| `RESEARCH_TAG` | `0xdc` | 50,924 | no |
| `DELTA_BLOB` | `0x73` | 49,926 | no |

A large share of the targets are runtime or cloud records, which is why the
SNID body is not present in the local database. The type distribution is also a
useful map of what gets shared: keyed CRC records, .NET IL patterns, trusted
publishers, AutoIt/MDB strings, PE static records and fastpath data.

Unknown type bytes seen as SNID targets: `0x07`, `0x0b`, `0x15`, `0x16`, `0x19`,
`0x3a`, `0x3f`, `0x4d`, `0x52` (the engine's type-name function returns
`SIGNATURE_TYPE_UNKNOWN` for these too), plus `0xdd` / `0x6d` / `0x6e` /
`0x81` / `0x92` / `0x94` / `0xb9` / `0xec..0xef` which were missing from
`constant/sig_types.py` and have now been added.

### Extended name = group, not target

All named SNIDs live in `!InfrastructureShared` and the names are lists/groups:

| group | entries | referenced type |
|---|---:|---|
| `#TopPkg:Prevalent` | 317,749 | `IL2_PATTERN` |
| `!#OrgSignerRmmNormal` | 55,275 | `AAGGREGATOREX` |
| `!#ALF:Trojan:PDF/Phish.1111!atmn` | 1,074 | `DELTA_BLOB` |
| `!#AGGR:VibrantGondala` | 69 | `EXPLICITRESOURCE` |
| `!#NID:DLLHijack.DSK5` | 44 | `LOCALHASH` |

Each group name maps to exactly one referenced type in the current database. The
name is never the owner threat name (`0 / 436,206` match `THREAT_BEGIN` names),
and it is not `sha1(name)` of the key either. It is the name of the shared
group/definition whose members are the referenced records.

### Decoded fields (`SnidSig`)

`record_sha1` / `record_key`, `key_hex`, `key_core`, `key_is_padded`,
`record_sig_type_id` / `reference_type_id`, `record_sig_type` /
`reference_type`, `record_name` / `group_name`, `record_name_raw`, `is_named`,
`describe()`.

---

## 2. NID64 (`0xce`) — 64-bit NID

### Layout

```
u64 key          64-bit id (often a packed record id)
u8  kind         namespace/table id
u8  name[]       optional NUL-terminated definition group name
```

* Base form: 9 bytes (`12,007` records in the merged stream).
* Named form: 9 + name (`102` records, `17` distinct names; names up to
  `#HighTrustPublisher_VLC`).

NID64 is the 64-bit variant of NID, not a new concept: same fields, same table
semantics, same optional group name. It exists because NID's 32-bit id space is
too small for record ids (which carry a 32-bit CRC plus type and size).

### Engine evidence

NID64 has its own table (`DAT_181115c48`, with a `0x1ce` sub-table):

| address | function / role |
|--------:|-----------------|
| `0x180a19c7c` | NID64 table constructor (`*table = 0xce`; calls `FUN_180a1b678`) |
| `0x180a1b678` | NID64 table registration; hooks `thunk_FUN_1803f4988` (reader) and `thunk_FUN_1802c3204` (indexer) |
| `0x1803f4988` | entry builder: requires `size >= 9`, stores `u64 key`, `u8 kind` at `+8`, name id at `+0xc`, extra at `+0x10`; bytes `9..` are an interned name |
| `0x18015d3f0` | generic table lookup: 24-byte entries `{u64 key, u8 kind, pad, u32 name_id, u32 extra}`, binary search by key, then match `kind` |
| `0x18015d2d4` | search both NID64 tables by `(kind, key)`; used by the commands |
| `0x18015d164` | public NID64 lookup wrapper used by modules |
| `0x180b1e6d0` | `Nid64Search <kind> <id>` definition command; resolves the record and unpacks its name |
| `0x180336368` | membership filter: `NID64(kind, id)` exists? Used e.g. for revoked-certificate checks |

The NID equivalent is the same design with 16-byte entries and 5-byte payloads:
`0x18015c56c` (lookup), `0x180a19d88` (table constructor), `0x1800e1cc0`
(`NidSearch`), `0x1803f4988`'s 32-bit sibling `FUN_180a1bb04`.

`FUN_18015c56c` is also where the packed record id formula is visible:

```c
local_58 = key;                 // u32
local_54 = kind;                // u8
uVar9 = FUN_180676c58(&local_58, 5);   // Defender CRC-32, init 0xffffffff, no final xor
local_100 = uVar9 | 0x55500000000;     // crc | 0x55 << 32 | 5 << 40
```

So a record id is `crc32(payload) | sig_type << 32 | payload_size << 40`. The
STATIC builder (`FUN_180210f20`) uses the same formula with type `0x67`.

### The NID64 key is usually a packed record id

Interpreting bits 32..39 as a signature type and bits 40..63 as a payload size
gives a very regular picture:

| embedded type | records |
|---|---:|
| `NID64` `0xce` (size 9) | 4,667 |
| `STATIC` `0x67` (sizes 22/38/…) | 3,720 |
| `REVOKED_CERTIFICATE` `0x6c` (size 35/…) | 1,118 |
| `AAGGREGATOREX` `0xe7` | 539 |
| `SNID` `0x7e` (size 21) | 511 |
| `NID` `0x55` (size 5) | 314 |
| `PEHSTR_EXT` `0x78` | 265 |
| `SIGTREE_BM` `0xb3` | 174 |
| `PCODEVALIDATOR` `0xb8` | 132 |
| `PEHSTR` `0x61` | 120 |
| `TRUSTED_PUBLISHER` `0x70` (size 23) | 97 |
| others | ~400 |

Cross-check: rebuilding `crc32(payload) | type << 32 | size << 40` for every
record in the merged stream resolves **5,141 of 12,109** NID64 keys exactly.
4,077 of those targets are other NID64 records, 531 STATIC records, 312
aggregator records, 123 SNID records, 90 trusted-publisher records, etc. The remaining
6,968 keys point at ids that are not shipped (runtime/cloud records), or use a
namespace whose ids are not record ids.

This also explains why NID64 looks recursive: many namespace `0x67` entries are
ids of NID64 records that themselves reference further records; walking the
links ends at a NID or STATIC record. That is a graph of id memberships, not a
chain of embedded payloads.

### Namespaces (`kind`) and names

| kind | records | observed meaning |
|------|--------:|------------------|
| `0x67` | 8,982 | STATIC-table members (ids of NID64/STATIC/SNID/NID/sig-tree/…) |
| `0x50` | 2,879 | CKSIMPLEREC-table members (STATIC, revoked certs, aggregators) |
| `0x84` | 97 | high-trust publisher names (`#HighTrustPublisher_VLC`, `_Gimp`, `_FireFox`, …) |
| `0xe4` | 80 | `MDBHSTR_EXT` names; `!#Allow:GoLang/StandardFunc` lists Go standard functions this way |
| `0x5c` | 37 | threat-name ids |
| `0x6e` | 10 | script-brute HSTR names (`SIGNATURE_TYPE_SCRIPTBRUTEHSTR_EXT`) |
| `0x57` | 10 | `UNPLIB` ids |
| `0x6a` | 7 | removal-policy ids |
| `0x7b` | 4 | sample-request names |
| `0x5e`, `0x3a`, `0x80` | 1 each | filename, telemetry and KCRCE ids |

Only 102 entries are named; 97 of those are the high-trust publisher list. As
with NID, the name is a group/list name, not the name of the referenced record.

Two specific examples:

```
# !#Allow:GoLang/StandardFunc (80 NID64 records, no other signature)
key=0x478d41ea53957601 kind=0xe4   -> MDBHSTR_EXT record, size 0x96
key=0x106d99db6eece403 kind=0xe4   -> MDBHSTR_EXT record, size 0x96

# !InfrastructureShared (12,029 NID64 records)
key=0x00001770da1e201c kind=0x84   "#HighTrustPublisher_VLC"
      -> crc 0xda1e201c, type 0x70 (TRUSTED_PUBLISHER), size 0x17 (23)
```

The first example is an allow-list: the threat is nothing but references to
function-name records. The second is a naming layer for trusted publishers.

### Decoded fields (`Nid64Sig`)

Everything from `NidSig` plus `packed_crc32`, `packed_sig_type_id`,
`packed_sig_type`, `packed_size`, `has_record_id_layout`, `key_bytes`. A
`NID64_KIND_LABELS` table in `nid.py` provides the best-effort namespace labels
above.  `has_record_id_layout` only checks that the embedded type is known and
the embedded size is plausible for a VDM record; it does not prove the record
exists (for example the GoLang allow-list keys have a coincidental `0xea`
"type" and a 4.7 MB "size").

---

## 3. What changed in the project

* `defender2yara/defender/signature/snid.py` — richer `SnidSig` (key core/padding,
  group name, referenced type aliases).
* `defender2yara/defender/signature/nid.py` — `Nid64Sig` packed-record-id
  decoding and namespace labels.
* `defender2yara/defender/constant/sig_types.py` — added/corrected the type
  names recovered from `FUN_180337818` (`BRUTEHSTR_EXT`, `SCRIPTBRUTEHSTR_EXT`,
  `DELTA_BLOB_ZSTD`, `VDLL_ARM64`, `ASCRIPTHSTR_EXT`, `MAC_MONITORING_FLAGS`,
  `WASMHSTR_EXT`, `CERT_STORE_ENTRY`, `CMDHSTR_FAST_EXT`, `DATABASE_CERT2/3`,
  `BM_ENV_VAR_MAP`, `ARHSTR_POSIX_EXT`; ARM64 corrections).
* `defender2yara/defender/dbthreat.py` — `snid_signatures`; NID64 is populated
  into `nid_signatures` alongside NID.
* `defender2yara/defender/dbthreat.py` — every signature also stores `record_id`
  (`crc32(payload) | type << 32 | size << 40`) in a deferred, indexed column.
* `defender2yara/threat_api.py` — `RecordIdResolver` resolves NID64 keys against
  that column for the HTML page, REST API and MCP; old databases without the
  column report resolution as unavailable instead of failing.
* `app/templates/signatures/nid64.html` — the NID64 card links to the referenced
  record and its owning threat.
* `app/views.py` and `app/templates/threat.html` — the decoded-record set keeps
  SNID records out of the raw dump, and the threat page has `nid`/`snid`
  sections.
* `app/static/sigs/SIG_SNID.md` — user-facing SNID explanation;
  `SIG_NID.md` covers NID/NID64, and `SIG_NID64.md` is the focused NID64 page.
* `tests/test_signature_three_more.py` — real vectors for the new fields;
  `tests/test_dbthreat.py` covers the legacy pickle path and UI sections.

YARA generation is unaffected: SNID still has no inline pattern, and NID64 is a
reference/id entry. Both are decoded and displayed, but only their target types
are useful for pivoting.

## 4. Open questions / follow-ups

* `SIGNATURE_TYPE_SNIDEX` (`0xe5`) and `SNIDEX2` (`0xe6`) are separate types and
  were not decoded here. There are only 49 `0xe6` records in `threats.db`, and
  `0xe5` is not in the merged stream, so they are low priority.
* The exact definition-identity hash used for the SNID 20-byte key is not
  derivable from the VDM payload. Reproducing it would require the definition
  source text or the engine's record-store builder, not the shipped data.
* Several SNID target types (`0x07`, `0x0b`, `0x15`, `0x16`, `0x19`, `0x3a`,
  `0x3f`, `0x4d`, `0x52`) have no name in `FUN_180337818`; they are likely
  internal/older types. They can still be displayed as `UNKNOWN(0x..)`.
* NID64 kind labels are inferred from the shipped names and from the embedded
  record ids; the engine does not expose a namespace-name table.
