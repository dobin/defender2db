# Decoding PESTATIC, BM_INFO and the SIGTREE attribute model

Follow-up to `cache/sig_type_usage.md`, `doc/sigs/sig_decode_more3.md` and
`doc/sigs/sig_decode_snid_nid64.md`.

Build analysed: `mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`
(x64, image base `0x180000000`; Ghidra project binary `/mpengine.dll`).

| type | id | records | what it is | decoder |
|------|----|--------:|------------|---------|
| `SIGNATURE_TYPE_PESTATIC` | `0x87` | 595,192 | PE region fingerprint: three CRC-32 windows | `defender/signature/pestatic.py` (`PestaticSig`) |
| `SIGNATURE_TYPE_PESTATICEX` | `0xcb` | 0 | same, with a 16-byte MD5 region hash | `pestatic.py` (`PestaticSig`) |
| `SIGNATURE_TYPE_BM_INFO` | `0xa8` | 4,192 | behaviour-detection metadata: id spec + telemetry policy | `defender/signature/bm_info.py` (`BmInfoSig`) |
| `SIGNATURE_TYPE_SIGTREE` | `0x40` | 15,058 | attribute decision tree, values only | `sigtree.py` (`SigTreeSig`) |
| `SIGNATURE_TYPE_SIGTREE_EXT` | `0x41` | 4,207 | the same tree with inline patterns/hashes | `sigtree.py` (`SigTreeSig`) |

All records of these types in the shipped database now decode and consume their
payload exactly.  The only non-`decoded` results are 23 `!#ALF` PESTATIC feed
records whose window length has the top bits set (reported as `partial`).

---

## 1. PESTATIC (`0x87`) and PESTATICEX (`0xcb`)

### What it is

PESTATIC is Defender's **per-region PE fingerprint**, the same idea as STATIC
but scoped to a piece of a PE rather than the whole file.  It is not a byte
pattern and cannot be expressed as YARA strings; it is a known-file / known-
region reputation record used for vulnerable drivers, clean and exclusion
lists.

The in-record name is an engine directive, not a threat name.  Examples from
`!InfrastructureShared`:

```
!#ESRP:PEStatic:iobios64.sys
!#ESRP:PEStatic:cpqsysio64.sys
!#ESRP:PEStatic:nsih.sys
!#SLF:ProcessInjector.BTP
!#TEL:VulnerableDriver:Win32/BootRepairDriver
```

`!#ESRP:PEStatic:<name>.sys` entries are the ESRP / vulnerable-driver list,
`!#SLF` and `!#ALF` are allow/exclusion feeds and `!#TEL` marks telemetry-only
rules.

### Engine evidence

| Address | Function / role |
|--------:|-----------------|
| `0x180b56870` | `pestatic` module init (module table entry name `0x180f5a190`) |
| `0x180b55508` | PESTATIC context: two sub-tables, types `0x87` and `0x187` |
| `0x180b55618` | PESTATICEX context: types `0xcb` and `0x1cb` |
| `0x180b55964` | emit `0x87` TLV: `FUN_180217edc(out, 0x87, record, 0x10)` — four dwords |
| `0x180b559c4` | emit `0xcb` TLV: `FUN_180217edc(out, 0xcb, record, 0x20)` — eight dwords |
| `0x180b5589c` | PESTATIC id: `crc32(record, 0x10) \| 0x10 << 40 \| 0x87 << 32` |
| `0x180b558fc` | PESTATICEX id: `crc32(record, 0x20) \| 0x20 << 40 \| 0xcb << 32` |
| `0x180242d2c` | attribute 0/1 of the current region: CRC32 of the first `0x40` / `0x200` bytes |
| `0x18024368c` | PESTATIC verifier: `crc_head`, `crc_prefix`, then `CRC32(first N)` |
| `0x180243960` | iterate PE sections with raw size `> 0x1ff`, match each section |
| `0x180243844` | build the region `{direct_ptr, file_offset, scan_ctx}` from the section table |
| `0x180240ff0` | additionally match `0x1000`-aligned slices of an unpacked buffer |
| `0x180a626b0` | additionally match custom PE sub-objects (resources/version data) |
| `0x180b531fc` / `0x180b52fb0` | PESTATICEX scan / verifier (MD5 of `[offset, offset+length)`) |
| `0x1805c4a10` / `0x1805c4a40` / `0x1805c4a60` | MD5 init / update / finalise |

Key points from the decompilation:

* `FUN_180b55508` writes the type byte `0x87` into the container and registers
  the reader `thunk_FUN_180b55a2c`, which returns a 20-byte internal entry
  (`4 × u32` payload + record id at `+0x10`).
* The `0x1XX` type (`0x187` / `0x1cb`) is an internal table selector, not an
  on-disk record type.
* `FUN_18024368c` reads `param_2[3]` as the end position, continues a running
  CRC from the region start and compares it with `param_2[2]`.  That is
  `CRC32(first N)`.
* `FUN_180242d2c` computes the first two values with windows `0x40` and `0x200`
  (`FUN_180243a54(..., 0x40)` / `(..., 0x200)`).
* The engine CRC is CRC-32 with init `0xffffffff` and no final xor
  (`FUN_180676c58`).
* The region type/index is **not** stored in the record.  The engine simply
  compares the CRCs of every candidate region, so a record only matches a
  region whose bytes hash to the same values.

### On-disk layout

PESTATIC (`0x87`), 16 bytes:

```
u32 crc_head        CRC32 of the first 0x40 bytes of the region
u32 crc_prefix      CRC32 of the first 0x200 bytes of the region
u32 crc_region      CRC32 of the first hashed_length bytes
u32 hashed_length
```

PESTATICEX (`0xcb`), 32 bytes:

```
u32 crc_head        CRC32 of the first 0x40 bytes of the region
u32 crc_prefix      CRC32 of the first 0x200 bytes of the region
u8  md5[16]         MD5 of hashed_length bytes at hashed_offset
u32 hashed_length
u32 hashed_offset
```

Both may be followed by a one-byte length and a non NUL-terminated name (the
same convention as KCRCE/STATIC).  All 1,579 extended records match
`16 + 1 + name_len` exactly; no `0xcb` record exists in the shipped database.

### Database measurements

Merged `mpasbase + mpasdlta + mpavbase + mpavdlta` stream:

| metric | value |
|--------|------:|
| `0x87` records | 595,192 |
| base 16-byte records | 593,613 |
| named records (`!InfrastructureShared` only) | 1,579 |
| distinct `crc_head` values | 259,245 |
| `hashed_length == 0x200` | 83,105 |
| ... with `crc_region == crc_prefix` | 83,105 (100%) |
| `hashed_length < 0x200` | 7 |
| `hashed_length > 64 MiB` | 92 |
| implausible lengths (top bits set) | 23 |
| `0xcb` records | 0 |

The `hashed_length == 0x200` relation is the direct confirmation of the window
order: a 0x200-byte region hash is by definition the `crc_prefix` value.

Window-length distribution:

| `hashed_length` | records |
|-----------------|--------:|
| `< 0x200` | 7 |
| `0x200 .. 0x10000` | 280,224 |
| `0x10000 .. 1 MiB` | 295,957 |
| `1 MiB .. 16 MiB` | 16,247 |
| `16 MiB .. 1 GiB` | 1,155 |
| `> 1 GiB` (top bits set) | 23 |

The seven sub-0x200 records (lengths `0x47`, `0x51`, `0x57`, `0x90`, `0x93`,
`0xe8`, `0x147`) cannot match a section, because `FUN_180243960` only scans
sections larger than `0x1ff`.  They belong to the unpacked-buffer/custom-object
paths (`FUN_180240ff0` / `FUN_180a626b0`), which is also why their windows may
be that small.

23 `!#ALF`/`!#TEL` feed records store a length with the top bit(s) set
(`0x80001000` × 17, `0x800003b4`, `0x80000400`, `0x8002d04f`, `0xc0000403`,
`0xc0000c70`, `0xc004077e`).  The low 30 bits always look like a plausible
window (`0x1000`, `0x3b4`, `0x403`, ...), so the top bits are probably flags in
the same dword.  The base matcher does not mask them, so these records are
flagged with a decode warning rather than interpreted.

### Decoded fields (`PestaticSig`)

`crc_head`, `crc_prefix`, `crc_section` (PESTATIC), `md5` / `md5_hex`
(PESTATICEX), `hashed_length`, `hashed_offset` (PESTATICEX), `record_name`,
`packed_record_id`, `section_crc_equals_prefix`, `decode_warnings`,
`describe()`.

`packed_record_id` is the engine's record id
`crc32(payload) | type << 32 | size << 40`, useful for cross-referencing NID64
keys (which are packed record ids too).

---

## 2. BM_INFO (`0xa8`)

### What it is

BM_INFO is **behaviour-monitoring detection metadata**.  It does not match
anything itself; it attaches a reporting/remediation policy to a behaviour
signature id.  The engine parses it into a `BmDetectionDetails` object
(vftable `0x180dc8c30`, 0x50 bytes) stored in the global table
`DAT_181126100` and looked up later by `(id, scope)`.

Examples decoded from the database:

```
flags=0x0001 id=33  tags=Low:Telemetry
flags=0x0100 id=33  tags=Low:UI+RemediateProcess+FastRemediation+Telemetry
flags=0x0004 id=33  tags=Low:UI+RemediateProcess+RemediateBaseFile+
                          FastRemediation+Telemetry
flags=0x0004 id=33,33+Packed,33+System32
                    tags=Low:Telemetry,Medium:Telemetry,High:Telemetry
```

### Engine evidence

| Address | Function / role |
|--------:|-----------------|
| `0x1803859d0` | BM_INFO record builder/loader; validates the length-prefixed fields and registers the record |
| `0x180385ce4` | allocate a `BmDetectionDetails`, call the constructor, insert it |
| `0x180385dd4` | append the object to the table vector at `DAT_181126100 + 0x40` |
| `0x1804424d4` | `BmDetectionDetails` ctor: `+0x10` registration index, `+0x14` option word, requires `< 0x1000` |
| `0x180442588` | parse id spec: first token -> default id (`+0x18`, must be `< 100`), rest -> `FUN_180bd13dc` |
| `0x180bd13dc` | parse `id+Packed` / `id+System32` and store the pair at `+0x38` |
| `0x1804426c0` / `0x180442794` | parse `Level:Action+Action`, store masks at `+0x20` (Low), `+0x28` (Medium), `+0x30` (High) |
| `0x18044293c` | fold `+`-separated action names into a bit mask |
| `0x18055c56c` | action name -> bit table |
| `0x180719580` | case-insensitive wide-string compare used for every name |
| `0x180271d50` / `0x1802729a0` | lookup by `(id, scope)`; FNV-1a hash over the 4-byte key |
| `0x180311b38` | debug dump of a behaviour report (`BEGIN BM telemetry`) |

`FUN_1803859d0` is the authoritative layout: it emits the TLV
`FUN_180217edc(out, 0xa8, payload, size)`, then:

1. `u16` at `+0` — group length.  When non-zero it is the length of a
   NUL-terminated group block that follows and the record is registered with
   `FUN_180185dbc` (named/grouped registration), otherwise with
   `FUN_180186b84`.
2. `u16` option word (the "first field" `uVar1`), stored at
   `BmDetectionDetails+0x14`.
3. `u16` length + NUL-terminated id spec.
4. `u16` length + NUL-terminated tag list.

Every length includes the trailing NUL, and the engine checks the last byte is
zero.

### On-disk layout

```
u16 group_len                0 in every shipped record
u8  group[group_len]         optional NUL-terminated group/list name
u16 options                  engine requires < 0x1000
u16 id_spec_len
u8  id_spec[id_spec_len]     "<id>[,<id>+<scope>...]"
u16 tags_len
u8  tags[tags_len]           "<level>:<action>[+<action>...],..."
```

### `id_spec`

`FUN_180442588` tokenises on `,`; the first token is the **default signature
id** (decimal, `< 100`) and the remaining tokens are
`<id>+<scope>` overrides handled by `FUN_180bd13dc`, which only accepts the
scopes `Packed` and `System32`.

The 4,192 shipped records use only seven distinct specs:

| spec | records |
|------|--------:|
| `33` | 4,117 |
| `66` | 49 |
| `33,33+Packed,33+System32` | 21 |
| `33,16+Packed,17+System32` | 2 |
| `34,33+Packed,33+System32` | 1 |
| `50` | 1 |
| `66,33+Packed` | 1 |

So the default id is 33 for 4,140 records (98.8%); the per-scope overrides exist
because the same behaviour signature gets a different id when the file is
packed or located in `System32`.

### `tags` and the telemetry policy

`FUN_1804426c0` tokenises on `,` and `FUN_180442794` splits each item on `:`
into a level (`Low`, `Medium`, `High`) and a `+`-separated action list.
`FUN_18044293c` folds the action names into a 64-bit mask via
`FUN_18055c56c`, and the three masks are stored separately on the object.

Action name -> bit (from `FUN_18055c56c`):

| action | bit | action | bit |
|--------|-----|--------|-----|
| `EventLog` | `0x00000001` | `BootScan` | `0x00020000` |
| `Telemetry` | `0x00000002` | `DriverScan` | `0x00040000` |
| `UI` | `0x00000004` | `WMIScan` | `0x00080000` |
| `RemediateProcess` | `0x00000008` | `FastRemediation` | `0x00100000` |
| `RemediateBaseFile` | `0x00000010` | `RemediateMultiProcess` | `0x00200000` |
| `AlwaysSendSamples` | `0x00000020` | `InformCamp` | `0x00800000` |
| `SendModules` | `0x00000040` | `MonitorEop` | `0x01000000` |
| `SingleProcessScan` | `0x00000080` | `MonitorProcTreeEop` | `0x02000000` |
| `AllProcessScan` | `0x00000100` | `SetProcessTainted` | `0x04000000` |
| `EmsScan` | `0x00001000` | `SmsScan` | `0x08000000` |
| `RegKeyValueScan` | `0x00004000` | `FdrProcess` | `0x10000000` |
| `TurnNriOn` | `0x00010000` | `FdrFile` | `0x20000000` |
| `ParentInfo` | `0x40000000` | `SmsAsyncScanEvent` | `0x80000000` |
| `EmsMappedScan` | `0x100000000` | `SenseETW` | `0x200000000` |
| `BootBackup` | `0x400000000` | `BootRestore` | `0x800000000` |
| `MemoryQuery` | `0x1000000000` | `PurgeClipboardContent` | `0x2000000000` |

Names are compared case-insensitively (`FUN_180719580` lower-cases ASCII), which
is why the database contains variants like `SmsScan`, `SMSSCAN` and `Smsscan`.

Database tag statistics:

| metric | value |
|--------|------:|
| distinct tag lists | 197 |
| distinct action names used | 31 |
| `Low:` only | 4,126 |
| `Medium:` only | 50 |
| `Low+Medium` / `Medium+High` | 3 / 2 |
| `Low+Medium+High` | 11 |
| most common actions | `Telemetry` 4,184, `UI` 520, `RemediateProcess` 447, `FastRemediation` 377, `ParentInfo` 285 |

No record uses the optional `group` field (`group_len == 0` everywhere), and
every option word is below `0x1000` (engine constraint).  The observed option
values (`0x0000`, `0x0001`, `0x0002`, `0x0004`, `0x0020`, `0x0040`, `0x0080`,
`0x0100`, `0x0400`, ...) look like feature bits; their names are not recovered.

### Decoded fields (`BmInfoSig`)

`group`, `flags`, `flags_in_range`, `id_spec`, `default_signature_id`,
`scope_ids`, `tags`, `levels` (per-level tag names and mask), `action_mask`,
`action_names`, `decode_warnings`, `describe()`.

---

## 3. SIGTREE / SIGTREE_EXT / SIGTREE_BM — the attribute model

The payload format was already decoded in `doc/sigs/sig_decode_more3.md`.  The
new part is what the words *mean*, which is also why `SIGTREE_EXT` needs no
separate parser: the three handlers (`FUN_1803a0220` for `0x40`,
`FUN_1803a0190` for `0x41`, `FUN_1803a0100` for `0xb3`) are byte-for-byte
identical and only differ in the diagnostic id and the registered record type.

### Attribute ids

`FUN_1803a02a8` copies the edge word `y` to the internal node's first dword.
The tree walker (`FUN_1803a02a8` -> `FUN_1800d0ebc` -> `FUN_1800d2510`)
binary-searches the node index by the `u16` at `node+0` and compares it with
the current match context's attribute id (`ushort` at context `+0x22`).  So:

```
y & 0xffff  = attribute id (the sigattr field being compared)
```

The per-object-class wrappers (`FUN_18024eae8`, `FUN_18024f048`,
`FUN_18024ec90`, `FUN_18024f138`, ...) pass the attribute id in `DX`, e.g.
`0x7001`, `0x7010`, `0x7033`, `0x7043`, `0x7084` for the NRI notifier
(`FUN_1805556bc`, class `NRISigattrNotifier`).

Observed namespaces per `tree_kind` (shipped database):

| kind | edges (`0x40`) | edges (`0x41`) | attribute ids | interpretation |
|-----:|---------------:|---------------:|---------------|----------------|
| 0 | 1,771 | 12 | `0x5100` | one fixed attribute |
| 1 | 2,338 | 131 | `0x5000`..`0x5004` | small attribute set |
| 2 | - | - | `0x40xx` | behaviour-monitoring events (`0xb3` only) |
| 3 | 42,090 | 12,870 | `0x3003`..`0x30xx` | file/PE metadata (version info, names, etc.) |
| 4 | 1,554 | 722 | `0x5200`..`0x5203` | small attribute set |
| 5 | 105,581 | 55,964 | `0x6028`, `0x606f`, `0x6072`, ... | process attributes |
| 6 | 49,544 | 65,349 | `0x7002`, `0x7010`, `0x7043`, ... | NRI network attributes |

Kind 2 (`SIGTREE_BM`) uses `0x4000`/`0x4010`/`0x4011`/`0x40ff`/`0xf000` and
accounts for the 25,735 inline behaviour patterns and 21,729 MD5 hashes.

The `0x30xx` trees explain the 15,058 `0x40` records with file names such as
`Aconti`, `AdRotator` or `AdultChat` in their owning threats: they are file/PE
metadata trees for PUA families, and the `z`/`w` values are probably CRCs of
PE version-info strings (the usual PUA matching surface).

### Edge semantics

```
u32 x      right flags (byte 0), left flags (byte 1)
u32 y      attribute id (low 16 bits), right length (byte 2), left length (byte 3)
u32 z      expected value / precomputed CRC for the left side
u32 w      expected value / precomputed CRC for the right side
u32 extra  variant >= 1: bit 8 = right opcode blob, bit 16 = left opcode blob
```

`FUN_1803a02a8` stores `z`/`w` as the node's left/right value words, then
overwrites them when an inline pattern or opcode blob is present.  Therefore:

* **`0x40` SIGTREE** has no inline conditions at all (0 patterns, 0 hashes in
  the whole database).  The only leaf data are the precomputed `z`/`w` values
  compared against the live attribute (window length from the high bytes of
  `y`); the flag bits select the comparison mode.
* **`0x41` SIGTREE_EXT** uses the same tree and adds the embedded leaves:
  47,140 patterns and 15,467 MD5 hashes.  That is the "EXT": the condition
  blobs are in the record instead of only precomputed CRC values.
* **`0xb3` SIGTREE_BM** is the behaviour-monitoring flavour with kind 2 and
  carries most of the behaviour string patterns.

Per-side flag bits observed in the database:

| flags | where | meaning |
|------:|-------|---------|
| `0x00` | all types | value/CRC compare against `z`/`w` (prefix window of `length`) |
| `0x01`, `0x02`, `0x04`, `0x40`, `0x44` | all types | comparison/action modifiers (not fully confirmed) |
| `0x10` | `0x41` / `0xb3` only | inline pattern follows (`y` high byte = length) |
| `0x50`, `0x54` | `0x41` / `0xb3` | `0x40 \| 0x10` = inline UTF-16LE pattern |

`0x40` uses flags such as `0x02` and `0x44` purely as comparison modifiers
(there is no condition blob to consume); `0x41`/`0xb3` combine the same bits
with `0x10`/opcode blobs to select wide text or a hash.

`SigTreeEdge` now exposes `attribute_id`, `left_value`/`right_value` (the
`z`/`w` words when that side has no inline condition), `left_flags_text` /
`right_flags_text`, and `SigTreeSig` exposes `attribute_ids`,
`attribute_namespace` and `has_inline_conditions`.

### Statistics

| type | records | edges | inline patterns | hashes | names | variants |
|------|--------:|------:|----------------:|-------:|------:|----------|
| `0x40` | 15,058 | 202,878 | 0 | 0 | 5,041 | 0 only |
| `0x41` | 4,207 | 135,048 | 47,140 | 15,467 | 2,002 | 0: 3,688, 1: 82, 4: 437 |
| `0xb3` | 17,940 | 71,533 | 25,735 | 21,729 | 473 | 0: 9,460, 1: 2,236, 2: 419, 3: 801, 4: 5,024 |

Records per kind:

`0x40`: 0 (190), 1 (1,232), 3 (6,928), 4 (265), 5 (6,033), 6 (410).
`0x41`: 0 (3), 1 (36), 3 (1,829), 4 (90), 5 (1,202), 6 (1,047).

---

### What the BM edge words actually mean

`SIGTREE_BM` (`0xb3`, `tree_kind == 2`) edges are **behaviour-monitoring event
predicates**, not opaque "node/action words":

```
y & 0xffff   BM event id (see FUN_1809f649c)
x & 0xff     right condition flags
x >> 8 & 0xff left condition flags
x >> 16      node control bits (not fully decoded)
y >> 24      left hash window / inline length
y >> 16 & 0xff right hash window / inline length
z            CRC32 of the left attribute text (or a condition-record id)
w            CRC32 of the right attribute text (or a condition-record id)
```

`FUN_1809f649c` is the engine's own BM event-id -> name helper.  It maps the
whole `0x4000..0x40b1` range, e.g. `0x4011 = BM_ProcessStart`,
`0x4017 = BM_EngineInternal`, `0x4009 = BM_RegistrySetValue`,
`0x406b = BM_SignatureTrigger`, `0x40b0/0x40b1 = BM_PipeCreate/PipeOpen`.
`FUN_18052e7cc` shows the same ids being emitted from the event categories.

Two ids are synthetic and do not appear in that switch:

* `0xf000` is `LuaCallSigattrBM`: `FUN_180157be0` rewrites the context
  attribute id to `0xf000` when a node has the Lua-callback control bit.  The
  live value is a BM group name such as `!BMGroup:Emotet_ProcExclusions.QA`
  (observed at runtime); it is not a normal event field.
* `0x40ff` is a **signature anchor**, not a live event.  All 4,407 `0x40ff`
  edges in the shipped database have an "any" right side, a 36-character left
  value, and the node is either the root (control bit `0x0004`) or the final
  node.  The left value is either a CRC32 of an opaque 36-character identifier
  (3,809 edges) or an inline **MD5** of it (598 edges).  Related rules share
  the same anchor; e.g. `0x8e454e61` is used by 96 rules added as one group,
  `0x2453f5cd` by 30, and so on.

  Evidence that it is a compiler-assigned rule/group identity rather than a
  live attribute:

  * it is not produced by the BM event switch or by any BM event emitter in
    mpengine (the literal `0x40ff` only occurs in an unrelated bit mask);
  * in many trees it is the **first** node with the root control bit, where a
    root condition would have to be true before any event can be checked;
  * the same value is reused by groups of rules compiled together, which does
    not happen for a process/file/registry value;
  * no plaintext candidate in the VDM or mpengine produces these CRCs/MD5s.
    A scan of every ASCII/UTF-16 string and every 26/36-character window in
    all four VDM files and mpengine found no match; the one `!BMGroup:Emotet`
    hit is a 32-bit collision and does not explain the group.
  * runtime instrumentation of `FUN_1800d5880` never sees `0x40ff` as a
    condition operand; it is handled by the tree-walker/anchor path, not the
    live-value matcher.

  Treat the prefix argument as an opaque `signature_anchor_id`.  Do not guess a
  GUID from a CRC match; use `sigtree_value_crc()` only to test a specific
  candidate, and expect that the compiler id is not present in the VDM.

#### Condition flags (`FUN_1800d5880`)

For a value-only condition the matcher behaves as follows:

| flag | meaning |
|-----:|---------|
| `0x01` | **suffix**: hash the last `length` characters (offset `live_len - length`) |
| `0x02` | **any**: return true without inspecting the value |
| `0x04` | **exact**: require `live_len == length`, then hash the prefix |
| `0x08` | case-sensitive hash / memcmp variant |
| `0x10` | inline pattern blob follows in the record |
| `0x20` | list / any-of: resolve an attribute record and test alternatives |
| `0x40` | wide UTF-16LE value |
| `0x80` | invoke an engine callback before comparing |

Without `0x01`/`0x04` the condition is a **prefix** match of `length`
characters/bytes; that is why the length is called a hash window.  This is
also why the same edge can match a long path with a short suffix, e.g.
`0x41` = wide + suffix, `0x40` = wide + prefix, `0x44` = wide + exact.

#### Value words are CRC32, not opaque actions

`FUN_1802371d0` hashes the live attribute with `FUN_1806765c0` (narrow) or
`FUN_180676604` (wide).  The CRC is CRC-32 with init `0xffffffff`, no final
XOR, and ASCII case folding; wide strings hash their characters as
lowercased UTF-16LE code units.  The compile-time `z`/`w` words are the same
CRC, so some can be resolved to the original text by matching known strings.

**Runtime confirmation.**  Hooking `FUN_1800d5880` and logging the value
descriptor at `param_5` (pointer at `+0`, flags at `+0xa`; a zero stored length
means "read to the NUL") shows the real value the engine hashes.  For
`BM_ProcessStart` / `BM_ProcessCreate` (`0x4010`/`0x4011`) the value is the
**full process command line**, not just the image path.  Observed examples:

```
C:\Program Files\Git\cmd\git.exe
"C:\Program Files\Git\cmd\git.EXE" --git-dir C:\Users\...\snapshot
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.EXE" -NoLogo ...
```

This is why the 26-character `CobaltStrike.J!sms` value is a **command-line
suffix**, not a file-path suffix: the J rule chains on an SMS detection and on
a process whose command line ends with a particular 26-character string.  A
filesystem-only dictionary (all files under `C:\Windows`, `Program Files`,
`%TEMP%`, ...) will not find it.  The engine's own runtime log is the reliable
way to recover it: run the behaviour with the matcher probe attached and read
the `attr=0x4011 v="..."` line.  The generic probe and target-table generator
are described in §5.

| value (length) | text |
|----------------|------|
| `0x98e9d724` (10) | `SMS_THREAT` |
| `0x67f1cc42` (11) | `BM_FILEOPEN` |
| `0x6bf27ea1` (21) | `BM_BLOCKPROCESSCREATE` |
| `0x6dfb367b` (8) | `CmdLowfi` |
| `0x35c89e67` (9) | `INTEGRITY` |
| `0xf9ab6713` (9) | `FILE_COPY` |
| `0xc7f18c20` (15) | `\powershell.exe` |
| `0xe0b63504` (8) | `\cmd.exe` |
| `0x7072d606` (13) | `\rundll32.exe` |
| `0xfe3a6f6a` (12) | `\wscript.exe` |
| `0x25be5a07` (13) | `\certutil.exe` |
| `0xde038d24` (9) | `mshta.exe` |

These are candidate matches, not proof; CRC32 collisions are possible.

`BM_EngineInternal` (`0x4017`) is the generic internal event bus.  Its first
parameter is a **tag** such as `SMS_THREAT`, `BM_FILEOPEN`, `CmdLowfi`,
`INTEGRITY` or `FILE_COPY`, and its second parameter is the tag payload
(threat name, path, command line, ...).  In the `!sms` signatures the payload
is a threat name: the `w` words match the CRC of ordinary `threat.name`
values.  This is how a behaviour signature can chain on another detection.

#### Worked example: `Behavior:Win32/CobaltStrike.J!sms`

The record (local id `2465931`, 4 edges, variant 0) decodes to:

| # | event | left | right |
|--:|-------|------|-------|
| 1 | `BM_ProcessStart` (`0x4011`) | command-line suffix, 26 wide chars, CRC `0xf4202780` | any |
| 2 | `BM_EngineInternal` (`0x4017`) | wide prefix `SMS_THREAT` | `HackTool:Win32/CobaltStrike.I!sms` |
| 3 | `BM_EngineInternal` (`0x4017`) | wide prefix `SMS_THREAT` | `HackTool:Win64/CobaltStrike.I!sms` |
| 4 | `BM_SignatureAnchor` (`0x40ff`) | 36-character opaque anchor id, CRC `0x1762ac1e` | any |

Edge 2/3 are a detection chain: the `J` behaviour signature fires when the
`I` SMS threat (32- or 64-bit) has been detected.  Edge 1 is a real
command-line suffix predicate; the exact 26-character suffix needs a sample or
the runtime probe.  Edge 4 is the signature's compiler-assigned anchor id, not
a live value; `0x1762ac1e` must stay opaque rather than be guessed from a CRC
match.

## 4. Resulting code

* `defender2yara/defender/signature/pestatic.py` — `PestaticSig`,
  `defender_crc32`.
* `defender2yara/defender/signature/bm_info.py` — `BmInfoSig`,
  `BM_ACTION_BITS`, `bits_to_names`, `names_to_bits`.
* `defender2yara/defender/signature/sigtree.py` — attribute id / value
  properties, flag rendering, `TREE_KIND_ATTRIBUTE_NAMESPACES`,
  `BM_EVENT_NAMES`, `BM_EVENT_VALUE_HINTS` / `bm_event_value_hint()`,
  `KNOWN_VALUE_STRINGS`, `sigtree_value_crc()`, `describe_side()` and
  `enrich_sigtree_details()`.  Edge details now include `value_hint` (for
  example `process command line` for `0x4010`/`0x4011`).
* `defender2yara/threat_api.py` — enriches stored sig-tree details on read so
  the HTML/API/MCP views show the decoded event names without re-importing the
  database.
* `defender2yara/defender/vdm.py` — dispatch for `0x87`, `0xcb` and `0xa8`.
* `tests/test_signature_pestatic_bm.py` — vectors from the real database.

None of these types emits YARA output: PESTATIC is a region hash, BM_INFO is
reporting metadata, and the sig-tree boolean/edge model is still not confirmed
(the extracted patterns and hashes remain available on the parsed object).

## 5. Runtime recovery of opaque value words

Static dictionaries are not sufficient: some value words are hashes of runtime
values (command lines, registry paths) and some are compiler-assigned ids.
The reliable general method is to observe the engine while it evaluates the
tree, or to observe the exact bytes it hashes.

The laboratory probes used for this report live in the companion
`DefenderReversingHelper` checkout (`dll_injector/detours_payload/`):

| probe | hook | what it records |
|-------|------|-----------------|
| `MpTreeProbe.c` | `mpengine+0xd0ebc` (`FUN_1800d0ebc`), `+0x6765c0`/`+0x676604` (`FUN_1806765c0`/`FUN_180676604`) | BM event id + value descriptors, and **any narrow/wide CRC input whose result is in a generated target table** |
| `MpMatchProbe.c` | `mpengine+0xd5880` (`FUN_1800d5880`) | node attr id, expected hash (`cond`/`w`), live value string and flags for every condition match |

`mptree_targets.h` is generated from the database: the `0x40ff` value words
plus any other unresolved words.  In this repository use:

```powershell
python tools/sigtree_probe.py targets --out mptree_targets.h --header --all-unresolved
python tools/sigtree_probe.py parse C:\data\mptree_probe_<pid>.log --out resolved.json
```

The `parse` command verifies every log line against `sigtree_value_crc()` before
accepting a `hash -> text` pair.  The hooks are installed with the existing
`injector.exe ... --ppl --allow-dynamic-code --fix-handle --kernel-thread
--restore` flow.  Only matching CRC inputs are written, so the log stays small
even during a full scan.

The key runtime facts recovered this way:

* `BM_ProcessStart`/`BM_ProcessCreate` values are full **command lines**;
* `BM_ModuleLoad` values are module paths;
* the `0xf000` Lua callback receives `!BMGroup:<name>` values;
* `0x40ff` is never seen by the condition matcher as an operand — it is an
  anchor/metadata node, not a value condition.

This also produces a reusable CRC dictionary: every `CRC <kind>
result=0x... text="..."` line is a verified `(hash, text)` pair.  Feed those
pairs back into `KNOWN_VALUE_STRINGS` (or a side-car table) to make future
imports decode the same words without re-running the engine.

## 6. Open questions

* The BM_INFO option word (`+0x14`, `< 0x1000`) is stored but its bit names are
  not recovered.  It is not the same namespace as the tag/action mask.
* The 23 `!#ALF` PESTATIC feed records with the top bits set in the length word
  need a different interpretation (flags?) and are currently only flagged.
* The sigattr attribute-id -> field-name mapping is per object class and was
  not recovered; only the namespaces above are known.
* `0x40ff` is a compiler-assigned signature anchor/group id.  The engine does
  not expose the original 36-character string, and it is not present in the
  VDM; only its CRC32 or MD5 is shipped.  The exact id remains opaque.
* The 26-character command-line suffix of `CobaltStrike.J!sms`
  (`0xf4202780`) remains unresolved.  It is a real command-line condition;
  recover it by running a triggering sample with the matcher probe, not by
  guessing from CRC32.
* Tree variants with an inline **MD5** condition on `0x40ff` (598 edges) use
  the same opaque anchor; the MD5 is not the MD5 of any threat name, file name
  or condition text in the VDM.
* The upper 16 bits of `x` (node control bits, e.g. `0x04`, `0x02`) change how
  the walker advances between nodes.  They are exposed as `control_flags` but
  the full state machine (`FUN_180157be0`) is not decoded yet.
* Value words that are not in the known-value table remain 32-bit CRCs; they
  cannot be inverted, only matched against candidate strings with
  `sigtree_value_crc()` or captured at runtime as above.
