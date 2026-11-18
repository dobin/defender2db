# Decoding NID, SIGTREE_BM and PEHSTR_EXT

Follow-up to `cache/sig_type_usage.md` and `doc/sigs/sig_decode_next3.md`.
SNID and NID64 have a dedicated follow-up in
`doc/sigs/sig_decode_snid_nid64.md`; the NID64 details below are summarised there in
more depth.

Build analysed: `cache/mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`.
Addresses are x64 VAs in the Ghidra project binary `/mpengine.dll`.

| type | id | records | what it is | decoder |
|------|----|--------:|------------|---------|
| `SIGNATURE_TYPE_NID` | `0x55` | 282,484 | 32-bit object id + attribute kind, optionally a name string | `defender/signature/nid.py` (`NidSig`) |
| `SIGNATURE_TYPE_NID64` | `0xce` | 13,948 | same, with an 8-byte id | `nid.py` (`Nid64Sig`) |
| `SIGNATURE_TYPE_SIGTREE_BM` | `0xb3` | 17,940 | behaviour-monitoring decision tree | `defender/signature/sigtree.py` (`SigTreeSig`) |
| `SIGNATURE_TYPE_SIGTREE` / `_EXT` | `0x40` / `0x41` | 15,058 / 4,207 | the same tree format, non-BM flavours | `sigtree.py` (`SigTreeSig`) |
| `SIGNATURE_TYPE_PEHSTR_EXT` | `0x78` | 100,643 | HSTR byte-pattern signature (extended header) | `defender/signature/hstr.py` (`HStrExtSig`) |

All records of these types in `threats.db` now parse without errors, and every
sig-tree record consumes its payload exactly.

---

## 1. NID (`0x55`) and NID64 (`0xce`) — numeric / name id table

### What it is

NID is the 32-bit pointer-free counterpart of SNID.  A NID record identifies an
object or definition by a numeric id plus a one-byte *kind* (namespace /
attribute id).  The long form additionally carries the name the id stands for.

Engine evidence:

* `FUN_18015c56c` is the hash-table lookup used by `NidSearch`.  It searches a
  table of 16-byte entries `{u32 key, u8 kind, u32 value_a, u32 value_b}` for a
  matching `(key, kind)` pair.
* On a match it builds the record id from a 5-byte buffer
  `{u32 key, u8 kind}` and `crc32`:
  `packed = crc32(key,kind) | 0x55 << 32 | 5 << 40`, i.e. the on-disk record
  payload is exactly five bytes.
* `FUN_1800e1cc0` is the `NidSearch` definition command handler.  It takes two
  numeric arguments, calls `FUN_18015c56c` on both internal tables
  (`DAT_181115c40` / `DAT_181115c40+0x90`), resolves the `RecId` with
  `FUN_180157248` and unpacks the name with `FUN_18015a450`.
  `Nid64Search` is the 64-bit variant (handler `FUN_180b1e6d0`).
* The tables are created in `FUN_180a1d2b0` -> `FUN_180a19d88` (type `0x55`) and
  `FUN_180a19c7c` (the NID64 table), eight per scan-object class.
* `FUN_18015b364` shows how a loaded NID is consumed: it looks up ids
  `0x2b`, `0x2c`, `0x2d`, `0x2e`, `0x31`, `0x32`, `0x35`, `0x36`, `0x42`,
  `0x43`, `0x45`, `0x46`, `0x48`, `0x49`, `0x4a`, `0x4b` and uses the result to
  toggle engine features such as VMM grow, deep analysis, exhaustive HSTR, API
  and SEH limits.  Those small ids line up with the `NID_*` name table
  (`NID_SCAN_ALG`, `NID_ENABLE_VMM_GROW`, ... at `0x180c77480`+).  So the
  one-byte `kind` is a namespace/attribute id from that enum family; database
  records also use larger ids (e.g. `0xdf`, `0xe7`) from the same namespace.

### On-disk layout

```
u32 key          object / definition id (u64 for NID64)
u8  kind         attribute / namespace id
u8  name[]       optional NUL-terminated text
```

* Real threats only use the 5-byte reference form
  (`SIGNATURE_TYPE_NID` 191,951 records, all size 5).
* The long form appears in `!InfrastructureShared` (90,533 `0x55` records and
  102 `0xce` records) and maps the id to a record name, e.g.

  ```
  2d719019 3a "#LOWFI:AGG:Chindo.A1"
  b9920000 e7 "!#OrgSignerRmmNormal"
  430fd011 7c "#TEL"
  ```

  The names are ordinary NUL-terminated ASCII/UTF-8 and are 100% printable and
  exactly terminated in the shipped database.

`record_key` is not a CRC of any sibling record, the threat name or the name
string; it is the numeric id assigned by the definition compiler.  For a few
traffic types it happens to equal `crc32(name)` (the `#<guid>`/`#TEL` records,
1,631 cases), which is consistent with the id namespace being CRC-derived for
those record classes.

### NID64 key = packed record id

NID64 uses the same three fields with an 8-byte key.  For record-backed
namespaces that key is the engine's packed record id:
`crc32(payload) | sig_type << 32 | size << 40` (the formula is visible in the
NID lookup `FUN_18015c56c` and in the STATIC builder).  In the shipped database
5,141 of 12,109 NID64 keys resolve exactly to a record in the merged VDM stream.
The table is otherwise the NID table design: 24-byte entries
`{u64 key, u8 kind, u32 name-id, u32 extra}`, lookup by `(key, kind)`, and the
same optional definition-group name.  See `doc/sigs/sig_decode_snid_nid64.md` §2.

### Decoded fields (`NidSig`)

`record_key`, `record_kind`, `record_name`, `record_name_raw`, `has_name`,
`trailing`, `describe()`.

`Nid64Sig` adds `packed_crc32`, `packed_sig_type(_id)`, `packed_size`,
`has_record_id_layout`, `key_bytes`, and NID64-specific `kind_label`s.

---

## 2. SIGTREE / SIGTREE_EXT / SIGTREE_BM (`0x40`, `0x41`, `0xb3`)

### What it is

A serialized decision tree used by behaviour monitoring (`0xb3`) and by the
older generic/EXT sig trees (`0x40`/`0x41`).  Leaves are string patterns
(byte or UTF-16LE, with HSTR wildcards) or hashes (MD5 / SHA-1 / SHA-256).
The strings are real behavioural indicators, e.g.:

```
Behavior:Win32/Renos217
  left pattern: "%windows%\" <skip 0..18> ".exe"

Behavior:Win32/EyeStye_Installation
  left pattern: "hkcu\software\microsoft\windows\currentversion\run\" \
                <skip 0..20> ".exe"

Behavior:Win32/CertutilPE.A
  left MD5: 19a96cbb96e159392dce94b4c7bc003e
```

### Engine evidence

* `sigtree` module init `FUN_180916b80` (module name at `0x180e77858`) registers
  three record handlers with `FUN_18018152c`:
  * `FUN_1803a0220` for `0x40`
  * `FUN_1803a0190` for `0x41`
  * `FUN_1803a0100` for `0xb3`
  All three immediately tail-call the shared parser `FUN_1803a02a8`, selecting
  a per-kind context with `&DAT_181112bf0 + kind * 0xa0`; `kind >= 7` is
  rejected.  The only difference is the diagnostic id (`0x4b`/`0x4c`/`0x4d`)
  and the signature type passed to the record registrar.
* `FUN_1803a02a8` reads the edge list and builds 0x24-byte internal nodes.
* `FUN_1803a08fc` turns a condition blob into a record (length + bytes) and
  computes its CRC; for inline patterns it additionally builds a
  first-byte/character map via the two pattern tables `0x180c70a80` and
  `0x180c70b80`.
* `FUN_1803a0b20` reads an opcode byte and chooses the condition size:
  `1` = variable (length from the edge; doubled when flag `0x40`),
  `2` = `0x10` bytes, `3` = `0x14`, `4` = `0x20`.  These are MD5, SHA-1 and
  SHA-256.
* `FUN_180186df4` interns the name/id strings; `FUN_180186b84` registers the
  resulting record with `(type, size, key, 16-byte digest, name id)`.

### On-disk layout

```
u8   edge_count
u8   variant          0..4; number of optional words per edge
u8   unknown
u8   tree_kind        0..6 (index of the per-kind context)
u8   name[]           NUL-terminated, normally empty (max 0x40)
u32  meta             only when variant > 2
edge[edge_count]:
    u32 x             right flags (b0), left flags (b1)
    u32 y             right inline length (b2), left inline length (b3)
    u32 z
    u32 w
    u32 extra         only when variant >= 1
                      bit 8  = right condition has an opcode blob
                      bit 16 = left condition has an opcode blob
    u32 extra2        only when variant >= 2
    condition blobs, left first then right:
        inline (flag 0x10)  -> x's length bytes follow
        opcode blob         -> one opcode byte + data
```

Key detail: the per-side flag bytes live in `x` but the inline lengths live in
`y` (`x` byte0/byte1 = right/left flags, `y` byte2/byte3 = right/left lengths).
An earlier reading of the decompiler swapped these and made no record line up.

### Conditions

* Inline pattern `flag & 0x10`: raw bytes; blobs are byte strings or UTF-16LE
  strings with the HSTR `0x90` opcodes embedded (`90 00` end, `90 01 XX` skip
  XX, `90 02 XX` skip 0..XX, `90 03/04/05` alternatives / regex).
  `decode_tree_pattern()` renders them, e.g.
  `"%windows%\<skip 0..18>.exe"`.
* Opcode `1`: variable inline pattern.
* Opcode `2`: 16-byte MD5; `3`: 20-byte SHA-1; `4`: 32-byte SHA-256.
  Only opcode `2` occurs in the shipped database (37,196 blobs).
* Observed flag values: `0x40`/`0x41` for hashes, `0x50`/`0x54` for inline
  patterns.  Bit `0x10` marks an inline pattern; bit `0x04` seems to mark
  UTF-16 vs bytes; the low bits are comparison/action flags and are not
  interpreted.

### Statistics

```
edge_count      1..15+ (2 is most common)
variant         0: 28,206  1: 2,318  2: 419  3: 801  4: 5,461
tree_kind       0x40/0x41: 0..6; 0xb3: always 2
conditions      all three types: 55,365 right patterns, 17,510 left patterns,
                31,650 left MD5, 5,546 right MD5
```

### Decoded fields (`SigTreeSig`)

`edge_count`, `variant`, `tree_kind`, `name`, `meta`, `edges` (with
`left_flags`/`right_flags`/`left_length`/`right_length`), `patterns`, `hashes`,
`is_behavior`, `describe()`.

The YARA rule generator still only consumes HSTR/HSTR_EXT signatures.  Sig
trees are not emitted as YARA yet because the boolean relationship between
edges (and the meaning of the action words `z`/`w`/`extra`) is not confirmed;
the extracted patterns and hashes are available on the parsed object for
downstream users.

---

## 3. PEHSTR_EXT (`0x78`) — name field, rule count, trailing flags

The payload is the documented extended-HSTR structure, with three corrections
found by checking all 100,643 `0x78` records (and all other `*HSTR_EXT` types,
~145k records):

```
u16  unknown            total positive weight in most records
u16  threshold          minimum total sub-rule weight
u16  rule_numbers       number of sub-rules
u8   name[]             NUL-terminated name/reference (empty in compiled records)
sub-rule[rule_numbers]:
    i16  weight
    u8   size
    u8   flags          bit 0 case-sensitive, bit 1 wildcard, bit 7 extended
    u8   extra          only when flags & 0x80
    u8   bytes[size]
u16  tail_word1         optional (engine record+0x10)
u16  tail_word2         optional (engine record+0x0c)
```

> **Update (tenth round):** the flag byte is now fully decoded from
> `FUN_180183298`: `0x01` = case-sensitive, `0x02` = wildcard pattern,
> `0x80` = one extra byte before the pattern.  The old special-casing of
> `0x88`/`0x90` was wrong.  See
> `doc/sigs/sig_decode_cmdhstr_dexhstr.md` and `cache/functions_vdm.md` §18.

1. **Byte 6 is not a reserved byte.**  It is the first byte of a
   NUL-terminated name.  Compiled records store just `0x00` there, which is why
   the sub-rules appeared to start at offset 7.  `!InfrastructureShared`
   records store a definition name and then *still* carry the normal sub-rule
   stream, e.g.

   ```
   010001000100  "!#HSTR:StringCodeForMshta.A!pli" 00
     01 00 05 80 01 "mshta"  00 00
   ```

   Before this change the 23,162 named `0x78` records were parsed as garbage
   sub-rules.

2. **`rule_numbers` is authoritative.**  Scanning until a zero weight overruns
   some records (e.g. `VirTool:Win32/CeeInject.gen!HP`, which has 4 sub-rules
   and a 4-byte tail).  Using the count makes every `*HSTR_EXT` record consume
   its payload exactly.

3. **Trailing words.**  Up to two `u16` option words follow the sub-rule list;
   there is no explicit terminator between the last sub-rule and the tails.
   `HStrExtSig` exposes `tail`, `end_marker` (first word), `flags` (second
   word) and `flags_present`.

The DEX flavour (`DexHStrExtSig`) keeps its old convenience attributes
(`is_name_reference`, `name_reference`) while sharing the new parser; the
sub-rules after a named record are now kept instead of discarded.

---

## Resulting code

* `defender2yara/defender/signature/nid.py` — `NidSig`, `Nid64Sig`.
* `defender2yara/defender/signature/sigtree.py` — `SigTreeSig`,
  `SigTreeEdge`, `SigTreeCondition`, `decode_tree_pattern`, `SIGTREE_SIGS`.
* `defender2yara/defender/signature/hstr.py` — generic `HStrExtSig` name /
  rule-count / tail parsing; `DexHStrExtSig` compatibility.
* `defender2yara/defender/vdm.py` — dispatch for `0x55`, `0xce`, `0x40`,
  `0x41`, `0xb3`.
* `tests/test_signature_three_more.py` — vectors from the real database.
