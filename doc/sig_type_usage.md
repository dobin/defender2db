# Signature type usage in `cache/threats.db`

Counts are actual signature records, unpacked from every `threatObject` blob (not just the per-threat unique `sigs` column).

**Totals**

- Threats analysed: **374,048** (aggregate pseudo-threats excluded, see bottom)
- Signature records: **6,833,550**
- Including the aggregate records: **8,964,111** records

## Most-used signature types (real threats)

| # | Signature type | ID | Signatures | % | Threats using | Current handling |
|---|----------------|----|-----------:|---:|--------------:|------------------|
| 1 | `SIGNATURE_TYPE_SNID` | `0x7E` | 2,203,169 | 32.24% | 21,422 | parsed (key + referenced type + group) |
| 2 | `SIGNATURE_TYPE_STATIC` | `0x67` | 2,070,731 | 30.30% | 64,425 | parsed (partial CRCs / hash / tags) |
| 3 | `SIGNATURE_TYPE_KCRCE` | `0x80` | 1,332,539 | 19.50% | 59,566 | parsed (layout / CRCs) |
| 4 | `SIGNATURE_TYPE_PESTATIC` | `0x87` | 593,613 | 8.69% | 13,088 | parsed (PE region CRCs + name) |
| 5 | `SIGNATURE_TYPE_NID` | `0x55` | 176,947 | 2.59% | 55,092 | parsed (id/kind/name) |
| 6 | `SIGNATURE_TYPE_PEHSTR_EXT` | `0x78` | 77,480 | 1.13% | 66,748 | parsed (YARA, name + flags) |
| 7 | `SIGNATURE_TYPE_VERSIONCHECK` | `0x7A` | 60,880 | 0.89% | 13,900 | parsed (env gate) |
| 8 | `SIGNATURE_TYPE_REVOKED_CERTIFICATE` | `0x6C` | 53,348 | 0.78% | 1,372 | parsed (revoked cert) |
| 9 | `SIGNATURE_TYPE_AAGGREGATOREX` | `0xE7` | 46,411 | 0.68% | 32,601 | parsed (expression) |
| 10 | `SIGNATURE_TYPE_NSCRIPT_SP` | `0x28` | 35,154 | 0.51% | 10,320 | parsed (script hash pair + window) |
| 11 | `SIGNATURE_TYPE_NSCRIPT_BRUTE` | `0x29` | 32,738 | 0.48% | 12,332 | parsed (readable script pattern) |
| 12 | `SIGNATURE_TYPE_CKSIMPLEREC` | `0x50` | 22,313 | 0.33% | 8,503 | parsed (4-byte file key + header/region CRCs + flags + name) |
| 13 | `SIGNATURE_TYPE_SIGTREE_BM` | `0xB3` | 17,467 | 0.26% | 13,654 | parsed (behaviour tree) |
| 14 | `SIGNATURE_TYPE_MACRO_SOURCE` | `0x43` | 16,158 | 0.24% | 7,167 | parsed (macro routine key sequence) |
| 15 | `SIGNATURE_TYPE_SIGTREE` | `0x40` | 10,017 | 0.15% | 8,433 | parsed (attribute tree) |
| 16 | `SIGNATURE_TYPE_NSCRIPT_NORMAL` | `0x27` | 9,775 | 0.14% | 6,626 | parsed (hash pairs / rolling-window condition list) |
| 17 | `SIGNATURE_TYPE_PEHSTR` | `0x61` | 6,906 | 0.10% | 6,355 | parsed (YARA) |
| 18 | `SIGNATURE_TYPE_AAGGREGATOR` | `0x96` | 6,646 | 0.10% | 3,858 | parsed (plaintext expression) |
| 19 | `SIGNATURE_TYPE_FOLDERNAME` | `0x60` | 6,055 | 0.09% | 2,020 | parsed (CSIDL root + path/glob) |
| 20 | `SIGNATURE_TYPE_MACRO_PCODE64` | `0xCF` | 5,925 | 0.09% | 1,128 | parsed (3 p-code routine keys) |
| 21 | `SIGNATURE_TYPE_MACROHSTR_EXT` | `0x8F` | 5,693 | 0.08% | 4,047 | parsed (YARA) |
| 22 | `SIGNATURE_TYPE_KVIR32` | `0x20` | 5,369 | 0.08% | 2,704 | parsed (page anchor + body CRCs, packer/emulator labels) |
| 23 | `SIGNATURE_TYPE_BM_INFO` | `0xA8` | 4,192 | 0.06% | 1,716 | parsed (id spec + telemetry tags) |
| 24 | `SIGNATURE_TYPE_REGKEY` | `0x63` | 3,911 | 0.06% | 542 | parsed (hive + key/value condition) |
| 25 | `SIGNATURE_TYPE_CMDHSTR_EXT` | `0xD7` | 2,941 | 0.04% | 2,737 | parsed (command-line strings + flags/wildcards) |
| 26 | `SIGNATURE_TYPE_DEXHSTR_EXT` | `0xBE` | 2,766 | 0.04% | 2,653 | parsed (DEX strings + flags/wildcards) |
| 27 | `SIGNATURE_TYPE_FILEPATH` | `0x5F` | 2,479 | 0.04% | 515 | parsed (CSIDL root + path/glob) |
| 28 | `SIGNATURE_TYPE_MACRO_PCODE` | `0x42` | 2,432 | 0.04% | 2,116 | parsed (3 32-bit p-code keys) |
| 29 | `SIGNATURE_TYPE_SIGTREE_EXT` | `0x41` | 2,205 | 0.03% | 1,712 | parsed (tree + attribute ids) |
| 30 | `SIGNATURE_TYPE_ELFHSTR_EXT` | `0x8C` | 1,944 | 0.03% | 1,905 | parsed (YARA) |
| 31 | `SIGNATURE_TYPE_NID64` | `0xCE` | 1,919 | 0.03% | 1,522 | parsed (id/kind/name + packed record id) |
| 32 | `SIGNATURE_TYPE_CKOLDREC` | `0x11` | 1,740 | 0.03% | 1,000 | parsed (two CRC-32 regions + flags + name) |
| 33 | `SIGNATURE_TYPE_BRUTE` | `0xD0` | 1,725 | 0.03% | 96 | parsed (generic script brute pattern) |
| 34 | `SIGNATURE_TYPE_BOOT` | `0x44` | 1,203 | 0.02% | 1,131 | parsed (boot image pattern / CRC region) |
| 35 | `SIGNATURE_TYPE_ASEP_FILEPATH` | `0x71` | 1,191 | 0.02% | 210 | parsed (CSIDL root + path/glob; ASEP variant) |
| 36 | `SIGNATURE_TYPE_FOPEX` | `0x89` | 1,189 | 0.02% | 410 | parsed (literal prefix + wildcard code body + offset) |
| 37 | `SIGNATURE_TYPE_PEBMPAT` | `0x95` | 955 | 0.01% | 352 | raw only / unimplemented |
| 38 | `SIGNATURE_TYPE_MACHOHSTR_EXT` | `0x8D` | 952 | 0.01% | 927 | parsed (YARA) |
| 39 | `SIGNATURE_TYPE_NDAT` | `0xA9` | 837 | 0.01% | 459 | parsed (typed data / regex + label) |
| 40 | `SIGNATURE_TYPE_FOP` | `0x7F` | 790 | 0.01% | 468 | parsed (literal file-offset code pattern) |
| 41 | `SIGNATURE_TYPE_ARHSTR_EXT` | `0xC5` | 622 | 0.01% | 457 | parsed (YARA) |
| 42 | `SIGNATURE_TYPE_AUTOITHSTR_EXT` | `0xD3` | 576 | 0.01% | 523 | parsed (YARA) |
| 43 | `SIGNATURE_TYPE_LUASTANDALONE` | `0xBD` | 452 | 0.01% | 405 | parsed (wrapper + Lua chunk + phase) |
| 44 | `SIGNATURE_TYPE_JAVAHSTR_EXT` | `0xBF` | 342 | 0.01% | 186 | parsed (YARA) |
| 45 | `SIGNATURE_TYPE_HOSTSENTRY` | `0x64` | 204 | 0.00% | 2 | raw only / unimplemented |
| 46 | `SIGNATURE_TYPE_KPAT` | `0xBB` | 183 | 0.00% | 178 | parsed (8-byte anchor + literal/wildcard tail) |
| 47 | `SIGNATURE_TYPE_POLYVIR32` | `0x21` | 151 | 0.00% | 148 | raw only / unimplemented |
| 48 | `SIGNATURE_TYPE_KPATEX` | `0xBC` | 82 | 0.00% | 71 | parsed (8-byte anchor + wildcard-opcode tail) |
| 49 | `SIGNATURE_TYPE_FOPEX64` | `0xC9` | 55 | 0.00% | 54 | raw only / unimplemented |
| 50 | `SIGNATURE_TYPE_UNKNOWN` | `??` | 50 | 0.00% | 47 | raw only / unimplemented |
| 51 | `SIGNATURE_TYPE_SNIDEX2` | `0xE6` | 49 | 0.00% | 2 | raw only / unimplemented |
| 52 | `SIGNATURE_TYPE_MSILFOP` | `0xBA` | 36 | 0.00% | 31 | raw only / unimplemented |
| 53 | `SIGNATURE_TYPE_FOP64` | `0xC8` | 15 | 0.00% | 13 | raw only / unimplemented |
| 54 | `SIGNATURE_TYPE_DEFAULTS` | `0x58` | 14 | 0.00% | 7 | raw only / unimplemented |
| 55 | `SIGNATURE_TYPE_PUA_APPMAP` | `0xE8` | 8 | 0.00% | 8 | raw only / unimplemented |
| 56 | `SIGNATURE_TYPE_VBFOP` | `0xB4` | 2 | 0.00% | 2 | raw only / unimplemented |
| 57 | `SIGNATURE_TYPE_DOSHSTR_EXT` | `0x8E` | 1 | 0.00% | 1 | parsed (YARA) |
| 58 | `SIGNATURE_TYPE_INNOHSTR_EXT` | `0xD4` | 1 | 0.00% | 1 | parsed (YARA) |
| 59 | `SIGNATURE_TYPE_EXPLICITRESOURCE` | `0xD6` | 1 | 0.00% | 1 | raw only / unimplemented |
| 60 | `SIGNATURE_TYPE_DMGHSTR_EXT` | `0xEA` | 1 | 0.00% | 1 | parsed (YARA) |

## Newly implemented parsers

The first three types now have structural decoders (mpengine function notes in
`cache/functions_vdm.md`):

- `SIGNATURE_TYPE_SNID` (`0x7e`, 21 B + optional name): 20-byte record SHA1 +
  referenced signature type, followed by an optional NUL-terminated inline name.
  It is an indirection to a shared signature record, not a file hash.
- `SIGNATURE_TYPE_STATIC` (`0x67`, 22/34/38/50 B + optional name): three partial
  CRC32 windows (first 0x1000 / last 0x1000 / first min(size, 0x10000)), file size,
  a flags word (bit 0 = prefix match, bits 12..14 = strong-hash algorithm), the
  selected strong hash, then an optional one-byte-length-prefixed tag.
- `SIGNATURE_TYPE_KCRCE` (`0x80`, 16 B + optional name): three CRC32s + region/window
  word + flags, then an optional one-byte-length-prefixed name.

Implemented in `defender2yara/defender/signature/{snid,static,kcrce}.py` and wired into
`Vdm.parse_database`. These are hash/reference signatures, so they are decoded structurally
but do not emit YARA string patterns yet.

## Deep dive: `SIGNATURE_TYPE_STATIC` (`0x67`)

STATIC is Defender's **known-file fingerprint / file reputation** record, not just a
detection hash. mpengine loads it into the static-match table (`FUN_18092e220`,
`FUN_18092be48`) next to the trusted-publisher (`0x70`) and revoked-certificate (`0x6c`)
tables, and matches it in the static (non-emulated) pass (`FUN_18028c670` →
`FUN_180214dec` → `FUN_180213c60`). A match can raise a detection, mark the file
clean/friendly, flag it as expensive, apply an FP suppression/exclusion, or attach a
classification.

### Layout

| offset | size | field | meaning |
|-------:|-----:|-------|---------|
| `0x00` | 4 | `hash1` | partial CRC1: first `min(size, 0x1000)` bytes, zero padded to 0x1000 (lookup key) |
| `0x04` | 4 | `hash2` | partial CRC3: last 0x1000 bytes of the first `size` bytes (zero padded in front when short) |
| `0x08` | 4 | `hash3` | partial CRC2: first `min(size, 0x10000)` bytes |
| `0x0c` | 4 | `file_size` | full `u32` size (the engine's internal value is 28-bit or resolved from the hash blob) |
| `0x10` | 2 | `flags` | bit 0 = prefix match, bits 12..14 = strong-hash algorithm |
| `0x12` | n | strong hash | 4 (CRC32), 16 (MD5), 20 (SHA1), 4 (SHA1[:4]) or 32 (SHA256) |
| `0x12+n` | 1 | `name_len` | optional extended record |
| `0x13+n` | .. | `name` | tag, not NUL-terminated |

The on-disk order is **CRC1, CRC3, CRC2**. `hash1` is the table index; the matcher then
verifies `hash3`, `hash2`, the `#CFG:` gate and finally the strong hash over the first
`size` bytes (`FUN_1800f1728`). The engine CRC is CRC-32 with init `0xffffffff` and no
final xor (`FUN_180676c58`), i.e. `zlib.crc32(data) ^ 0xffffffff`.

Validated over the merged compendium (262,852 unique records):

* all 75 records with `file_size == 0x1000` have `hash1 == hash2 == hash3` (the three
  windows cover the same 4 KiB),
* `hash3 == trailing CRC32` for every `file_size <= 0x10000` record (16,243); never
  for larger files (227,284); the only exceptions are 4 `!#Exclusion:` records with a
  zero strong hash,
* 11,965 records have `hash2 == 0x38e3ffee`, which is exactly the engine CRC of 0x1000
  zero bytes (zero-filled tail windows, common for Mach-O/installer files).

### Flags

| value | meaning |
|-------|---------|
| `0x0000` | MD5 (16 bytes) |
| `0x1000` | SHA1 (20 bytes) |
| `0x2000` | CRC32 (4 bytes) |
| `0x3000` | SHA1[:4] (4 bytes; engine-supported, not present in this DB) |
| `0x4000` | SHA256 (32 bytes; engine-supported, not present in this DB) |
| `0x0001` | prefix/truncated match: accept `size <= file_size` instead of exact equality |

The prefix bit changes the strong-hash range to the first `file_size` bytes, so the
record matches a prefix of a longer file. In this DB 1,922,006 of 2,106,159 records
(91.3%) set it. `0x2001` is literally `0x2000 | 0x0001`: both are CRC32 records, and the
only difference is that `0x2001` accepts a file larger than the stored size while `0x2000`
requires an exact size match.

### Tags

The trailing `name_len`/`name` appears only in `!InfrastructureShared`, where all 35,428
STATIC records are tagged (5,154 distinct tags); per-threat records are unnamed. Tags
are engine directives, not the threat name:
`#ClnFile[:N]` (clean with TTL), `#ClnInst*` (installer variant), `#CFG:A:ClnFile`
(feature gate), `#ExpensiveFile` (perf), `#Exclusion*`/`#Exclude`, `#FP:<family>`,
`#PUA:...`/`#Trojan:...` (classification to attach), and internal `!#ALF/!#ALFPER/
!#TEL/!#SLF/!#STATIC` feeds. `#MpCloudToVDMBloomFilterXPLAT` marks cloud-generated
bloom-filter entries.

### Coverage in this DB

| metric | value |
|--------|------:|
| records | 2,106,159 (35,428 with an inline tag) |
| threats using STATIC | 64,425 |
| unique records in merged VDM | 262,852 |
| CRC32 form | 2,025,689 (96.2%) |
| SHA1 form | 80,350 (3.8%) |
| MD5 form | 120 (mostly `!#STATIC:`/`!#SLF:` test records) |
| 22-byte base records | 2,005,848 |

Full layout/matching notes: `doc/sigs/sig_decode_first3.md` §1. Parser:
`defender2yara/defender/signature/static.py` (`StaticSig` now exposes
`partial_crc1/2/3`, `prefix_match`, `md5/sha1/sha1_32/sha256/crc32` and the tag).
YARA cannot express the partial windows cheaply; if rules are ever emitted, use
`filesize == size and hash.<algo>(0, filesize) == ...` and keep the CRCs as prefilters.

## Second round: aggregator, version gate, DEX strings

Three more types now have structural decoders (full notes in
`doc/sigs/sig_decode_next3.md`):

- `SIGNATURE_TYPE_AAGGREGATOREX` (`0xe7`): a boolean expression over other signature
  records (`HSTR:...&SIGATTR:...`). The body is obfuscated with a static 256-byte
  substitution table (`mpengine` VA `0x180d9e080`); the optional name is plain text.
  Parsed into a readable expression string.
- `SIGNATURE_TYPE_VERSIONCHECK` (`0x7a`): `u32 check_id, u32 value` environment gate.
  It is evaluated by the loader and, when False, causes the following records of the
  threat to be skipped. Decoded into a predicate (`os_build < 17763`,
  `definition_set_digest[0] == 0x02da09d4`, always-true, ...).
- `SIGNATURE_TYPE_DEXHSTR_EXT` (`0xbe`): identical to the other `*HSTR_EXT` patterns
  (already parsed into YARA), plus an optional trailing flags word present in ~14% of
  records.  The full flag/encoding model and the named-record (still patterned)
  form are covered in the tenth round below.

Wired into `Vdm.parse_database` and covered by `tests/test_signature_next3.py`.
All 61,055 / 84,634 / 3,053 records of these types in `threats.db` parse cleanly.

## Third round: NID, sig trees, PEHSTR_EXT header

Three more areas now have structural decoders (full notes in
`doc/sigs/sig_decode_more3.md`):

- `SIGNATURE_TYPE_NID` (`0x55`) and `SIGNATURE_TYPE_NID64` (`0xce`): a
  `u32`/`u64` object id plus a one-byte attribute/namespace id, optionally
  followed by a NUL-terminated name.  Real threats only use the 5/9-byte
  reference form; the long form in `!InfrastructureShared` maps ids to record
  names.  Decoded into `key`, `kind` and `name`.  NID64 keys are often packed
  record ids (see the fourth round below).
- `SIGNATURE_TYPE_SIGTREE_BM` (`0xb3`, and the shared-format `0x40` /
  `0x41`): a decision tree with up to 15+ edges; leaves are byte / UTF-16LE
  patterns with HSTR wildcards, or MD5/SHA-1/SHA-256 hashes.  Fully walked
  (17,940 + 15,058 + 4,207 records) and exposed as `SigTreeSig` with
  `edges`, `patterns`, `hashes` and `decode_tree_pattern()`.
- `SIGNATURE_TYPE_PEHSTR_EXT` (`0x78`, already emitted to YARA): the byte at
  offset 6 is the start of a NUL-terminated name (empty in compiled records,
  a definition name in `!InfrastructureShared`), `rule_numbers` bounds the
  sub-rule list, and the optional trailing flags word is now exposed.

Wired into `Vdm.parse_database` and covered by
`tests/test_signature_three_more.py`.  All 282,484 NID, 13,948 NID64, 37,205
sig-tree and 100,643 PEHSTR_EXT records parse cleanly.

## Fourth round: SNID and NID64 deep dive

Full write-up: `doc/sigs/sig_decode_snid_nid64.md`. User-facing pages:
`app/static/sigs/SIG_SNID.md`, `app/static/sigs/SIG_NID.md` and
`app/static/sigs/SIG_NID64.md`.

### `SIGNATURE_TYPE_SNID` (`0x7e`)

SNID is a **shared-record reference**, not a detection.  The base record is 21
bytes: a 20-byte record-store key followed by the referenced record's signature
type.  The optional extended form appends a NUL-terminated **group/definition**
name (never the owner threat name).  mpengine builds the base record in
`FUN_18010df68` from a `(20-byte key, type)` record-store lookup and
`SNidSearch` (`FUN_18037dfc0`) takes a SHA-1 string and resolves it the same way.

Database measurements (merged 288 MB record compendium = unique record bodies,
2,482,344 SNID records):

| metric | value |
|--------|------:|
| base 21-byte records | 2,046,138 |
| extended/named records | 436,206 (39,133 distinct names) |
| unique keys | 2,481,835 (509 duplicate uses) |
| named records outside `!InfrastructureShared` | 0 |

Referenced types (top): `KCRCEX` 422,922, `IL2_PATTERN` 317,749,
`TRUSTED_PUBLISHER` 258,943, `AUTOITHSTR_EXT` 236,753, `MDBHSTR_EXT` 142,695,
`PESTATICEX` 132,413, `FASTPATH_TDN` 128,975, `LOCALHASH` 113,525,
`EXPLICITRESOURCEHASH` 73,143, `AAGGREGATOREX` 55,275, `NID64` 20,635.  Many
targets (`KCRCEX`, `LOCALHASH`, `FASTPATH_*`, `EXPLICITRESOURCEHASH`) are
runtime/cloud records, so the body is not shipped.

The 20-byte key is the record store's key, **not** a hash of the shipped payload:
SHA-1/MD5 of every record payload/TLV reproduces only 2 of the 2.48M keys (both
accidental matches on a 4-byte `THREAT_END`).  Some families use a 16-byte key
zero-padded to 20 bytes: `LOCALHASH` / `FTRIE_POS` / `GENSFX` pad at the end,
`MACHOHSTR_EXT` / `ELFHSTR_EXT` pad at the front.

The extended name is the group/list the referenced records belong to, e.g.
`#TopPkg:Prevalent` (317,749 `IL2_PATTERN` refs), `!#OrgSignerRmmNormal` (55,275
`AAGGREGATOREX` refs), `!#AGGR:VibrantGondala` (69 `EXPLICITRESOURCE` refs),
`!#NID:DLLHijack.DSK5` (44 `LOCALHASH` refs).

Decoder: `defender2yara/defender/signature/snid.py` (`SnidSig`, exposes
`key_hex`, `key_core`, `key_is_padded`, `reference_type`, `group_name`,
`is_named`).  `NiceThreat` now keeps `snid_signatures` and the UI renders them;
they are still excluded from YARA output because there is no inline pattern.

### `SIGNATURE_TYPE_NID64` (`0xce`)

NID64 is the 64-bit sibling of NID: `u64 key, u8 kind, optional name`.  The
engine stores it in a dedicated table (`FUN_180a19c7c` / `FUN_180a1b678` ->
entry builder `FUN_1803f4988`) and looks entries up by `(key, kind)`
(`FUN_18015d3f0`, `FUN_18015d2d4`, `Nid64Search` `FUN_180b1e6d0`).  The payload
is stored via the same reader/table design as NID, only the key is 8 bytes.

For record-backed namespaces the key is the engine's packed record id:
`crc32(payload) | signature_type << 32 | payload_size << 40` (the formula is
visible in `FUN_18015c56c` and in the STATIC builder).  Rebuilding that id for
every record in the merged stream resolves **5,141 of 12,109** NID64 keys
exactly: 4,077 target other NID64 records, 531 STATIC, 312 aggregators, 123
SNID, 90 trusted publishers, 4 revoked certs, 2 `AAGGREGATOR`, 1 `NSCRIPT_BRUTE`,
1 NID.  The rest
point at runtime/cloud records or non-record id namespaces.

Observed `kind` namespaces (merged stream, 12,109 records):

| kind | records | meaning |
|------|--------:|---------|
| `0x67` | 8,982 | STATIC-table members (ids of NID64/STATIC/SNID/NID/sig-tree/… records) |
| `0x50` | 2,879 | CKSIMPLEREC-table members (STATIC, revoked certs, aggregators) |
| `0x84` | 97 | high-trust publisher names (`#HighTrustPublisher_VLC`, `_Gimp`, …) |
| `0xe4` | 80 | `MDBHSTR_EXT` names; `!#Allow:GoLang/StandardFunc` is 80 such references |
| `0x5c` | 37 | threat-name ids |
| `0x6e` | 10 | script-brute HSTR names |
| `0x57` | 10 | `UNPLIB` ids |
| others | 14 | sample-request, filename, removal-policy, KCRCE, telemetry ids |

Only 102 records carry an inline name (17 distinct names); 97 are the high-trust
publisher list.  As with NID, the name describes the group/list, not the target.

Decoder: `Nid64Sig` in `nid.py` now exposes `packed_crc32`,
`packed_sig_type(_id)`, `packed_size`, `has_record_id_layout`, plus
`NID64_KIND_LABELS`.  `NiceThreat.nid_signatures` contains both NID and NID64
and the UI shows the decoded packed id.  YARA generation is unaffected.

Also recovered while decoding the referenced types: `FUN_180337818` gave the
missing/corrected names in `constant/sig_types.py` (`BRUTEHSTR_EXT`,
`SCRIPTBRUTEHSTR_EXT`, `DELTA_BLOB_ZSTD`, `VDLL_ARM64`, `ASCRIPTHSTR_EXT`,
`MAC_MONITORING_FLAGS`, `WASMHSTR_EXT`, `CERT_STORE_ENTRY`,
`CMDHSTR_FAST_EXT`, `DATABASE_CERT2/3`, `BM_ENV_VAR_MAP`,
`ARHSTR_POSIX_EXT`, and the ARM64 corrections for `TUNNEL_ARM64` /
`THREAD_ARM64`).

## Fifth round: PESTATIC, BM_INFO and the sig-tree attribute model

Full write-up: `doc/sigs/sig_decode_pestatic_bm_sigtree_ext.md`.  Engine
function notes were added to `cache/functions_vdm.md` §12.

- `SIGNATURE_TYPE_PESTATIC` (`0x87`, 16 bytes + optional name) is the
  `!#ESRP:PEStatic:`/`!#SLF:`/`!#TEL:` family.  It is **not** a byte pattern:
  it stores three CRC-32 windows of a PE region — first `0x40`, first `0x200`
  and first `hashed_length` bytes (the engine CRC, init `0xffffffff`, no final
  xor).  Matching walks every PE section larger than `0x1ff`, every
  `0x1000`-aligned region of an unpacked buffer, and custom PE sub-objects such
  as resources/version data (`FUN_180243960`, `FUN_180240ff0`,
  `FUN_180a626b0`).  The region index is not stored; only the CRCs are.
  `SIGNATURE_TYPE_PESTATICEX` (`0xcb`, 32 bytes) is the same idea with a
  16-byte MD5 of `[hashed_offset, hashed_offset + hashed_length)` instead of
  `crc_region` (no shipped records).
- `SIGNATURE_TYPE_BM_INFO` (`0xa8`) is behaviour-monitoring detection
  metadata, not a detection: an optional group name, an option word, a
  numeric signature-id spec (`33,33+Packed,33+System32`) and a
  comma-separated `Level:Action+Action` telemetry policy.  mpengine parses it
  into `BmDetectionDetails` (`FUN_1803859d0`, `FUN_1804424d4`).
- `SIGNATURE_TYPE_SIGTREE_EXT` (`0x41`) was already parsed; the new part is
  the interpretation.  `y & 0xffff` is the sigattr **attribute id**, the tree
  kinds map to attribute namespaces (`0x30xx` = file/PE metadata, `0x60xx` =
  process, `0x70xx` = NRI network, ...) and `z`/`w` are the precomputed
  32-bit attribute values.  `SIGTREE` (`0x40`) only carries those CRC
  comparisons (0 inline patterns), while `SIGTREE_EXT` (`0x41`) adds the
  inline pattern/hash leaves — that is what "EXT" means.

Coverage in the shipped database:

| type | records | decoded |
|------|--------:|---------|
| `PESTATIC` `0x87` | 595,192 | 593,613 base + 1,579 named, 0 errors |
| `PESTATICEX` `0xcb` | 0 | - |
| `BM_INFO` `0xa8` | 4,192 | all consume their payload exactly |
| `SIGTREE` `0x40` | 15,058 | 202,878 edges, 0 inline conditions |
| `SIGTREE_EXT` `0x41` | 4,207 | 135,048 edges, 47,140 patterns, 15,467 MD5 |
| `SIGTREE_BM` `0xb3` | 17,940 | 71,533 edges, 25,735 patterns, 21,729 hashes |

Decoders: `defender2yara/defender/signature/pestatic.py` (`PestaticSig`),
`bm_info.py` (`BmInfoSig`) and the extended `sigtree.py` edge/condition
model.  Wired into `Vdm.parse_database`; tests in
`tests/test_signature_pestatic_bm.py`.  None of the three feeds YARA: PESTATIC
is a region hash, BM_INFO is reporting metadata and sig trees still lack a
confirmed boolean/edge model.

## Sixth round: script and macro source signatures

Full write-up: `doc/sigs/sig_decode_nscript_macro.md`.  Engine notes were added
to `cache/functions_vdm.md` §13.  User-facing pages: `app/static/sigs/SIG_NSCRIPT.md`
and `app/static/sigs/SIG_MACRO_SOURCE.md`.

These three types are **content signatures for scripts and macros**, not file
fingerprints.  The `nscript` module (`FUN_180a65d00`) registers `0x27`/`0x28`/
`0x29`/`0x2c`; the `macro` module (`FUN_180a50370`) registers `0x42`/`0x43`/
`0xcf`.

### `SIGNATURE_TYPE_NSCRIPT_BRUTE` (`0x29`)

The only one of the three that contains readable content.  Layout::

    u8  name_len (0..0x3f); u8 name[name_len]
    u8  kind_and_flag    bits 0..6 script type, bit 7 extra flag
    u8  mode             0 = anywhere, 1 = forward, 2 = backward
    u32 any_length       low 16 bits; 0xffffffff = unset
    u32 pattern_length
    u8  pattern[pattern_length]    normalised script text + 0x90 wildcards
                                   (always ends 90 00)

The script-type byte is a one-based index into the `Nscript:Type_*` table at
`0x180f130d0`: 1 vbs, 2 js, 3 bat, 4 irc, 5 ps, 6 py; 0/7 = any (internal
enum 6).  Distribution: any 122,960, js 11,405, ps 5,335, vbs 5,203, bat 1,542,
py 1,200, irc 69.  371 records set the kind byte's high bit (engine flag
`0x0400`).

Patterns are lower-case script fragments with whitespace removed.  `90 00` is
a NUL/terminator, `90 01 XX` skips XX bytes, `90 02 XX` skips 0..XX, and the
remaining entries of the 50-entry opcode table at `0x180c94d50` are other
engine wildcards (notably `90 1b`, the "loose" token that clears flag
`0x0800`).  `decode_script_pattern()` renders the text, e.g.:

    Worm:Win32/Bagle.O
      <html><body><fontface="system"><objectstyle="display:none"
      data="http://<skip 0..3>.<skip 0..3>.<skip 0..3>.<skip 0..3>:81/<skip 0..8>.php"

Real threats contribute 32,738 anonymous records.  The other 114,976 records
are the shared `!#SCPT:`/`!#JSON:` pattern library in
`!InfrastructureShared` (94,272 distinct reference labels).  This is the one
type from this round that can feed YARA generation.

### `SIGNATURE_TYPE_NSCRIPT_SP` (`0x28`)

Compact hash form of a script condition::

    u8  name_len (0..0x3f); u8 name[name_len]
    u32 hash1
    u8  flags            bit 7 separate flag; low bits 0..4 observed
    u32 hash2
    u32 match_length     script window length, 1..0x1000

`FUN_180181720` stores `{hash1, match_length, hash2, condition_id, flags}` in
the script-condition vector.  `match_length` is the secondary sort key and is
clamped at `0x1000` (1,184 records), which is the engine's script ring-buffer
size.  `flags & 0x7f` in {1, 2} triggers a legacy `:IRC/` name special case;
bit `0x80` becomes an extra in-memory flag.  Both dwords are hashes of
normalised script fragments, so the record cannot be converted to YARA text.
599 records are named (484 labels), all `!#TEL:`/`!#SCPT:`/`!#SCRIPT:` feeds.

The closely related `NSCRIPT_NORMAL` (`0x27`) is now decoded in the seventh
round below; `NSCRIPT_CURE` (`0x2c`, bytecode-like) remains unimplemented.

### `SIGNATURE_TYPE_MACRO_SOURCE` (`0x43`)

Ordered sequence of normalised macro/VBA routine hashes::

    u8  name_len (0..0x3f); u8 name[name_len]
    u32 header          bits 0..5 = routine count, bits 6+ = source kind
    u32 hash_low[count]
    u32 hash_high[count]    optional, stored after the whole low array

Each `(hash_low, hash_high)` pair is one 64-bit routine key (27,655 keys in
16,210 records).  Source kinds are compared for equality, not OR-ed
(`FUN_18024dc90`): `0` Word 6 / Excel 5 macro source (3,078 records), `2`
Excel formula (15), `4` VBA source + p-code (9,074), `8` Excel-formula
routines / `xfcrcs` (4,043).  Legacy Word/Excel5 records normally omit the
high array (7,000 records); VBA and formula records usually include it (9,210).

`FUN_1802f7e98` walks the `Mp*Routines` streams and calls
`FUN_1802f81bc(ctx, kind, stream, count)`, which maps each 8-byte key to the
records that require it.  `FUN_18024dc90` then requires the record's keys to
occur **in order** in that stream.  The keys are internal routine hashes, not
file hashes, and cannot be reversed to macro text; the database indexes them in
`macro_routine_key` so the threat page can show which other detections require
the same routine.  Only 52 records are named (33 `!#SSF:`/`!#ALF:`/`!#SLF:`/
`!#Mcrosrc:`/`!#ASR` feed labels).

### Coverage

| type | records | decoded | named |
|------|--------:|--------:|------:|
| `NSCRIPT_SP` `0x28` | 35,753 | 35,753 | 599 |
| `NSCRIPT_BRUTE` `0x29` | 147,714 | 147,714 | 114,976 |
| `MACRO_SOURCE` `0x43` | 16,210 | 16,210 | 52 |

Decoders: `defender2yara/defender/signature/nscript.py` (`NscriptSpSig`,
`NscriptBruteSig`) and `macro_source.py` (`MacroSourceSig`).  Wired into
`Vdm.parse_database` / `Vdm.decode_record`; tests in
`tests/test_signature_nscript_macro.py`.

## Seventh round: CK checksum records and NSCRIPT_NORMAL

Full write-up: `doc/sigs/sig_decode_ck_nscript_normal.md`.  Engine notes were
added to `cache/functions_vdm.md` §13.

The `cksig` module (`FUN_180a1d2b0`) handles the legacy **checksum-region**
signatures.  These are not byte patterns: they store CRC-32 windows over file
ranges and are evaluated by `FUN_1800fdc68` (`0x50`) and `FUN_1800fe028`
(`0x11`).  The CRC is the engine CRC-32 (init `0xffffffff`, no final xor).

### `SIGNATURE_TYPE_CKSIMPLEREC` (`0x50`)

Layout::

    u32 file_prefix      literal first four bytes of the file (lookup key)
    u32 header_crc       CRC-32 of the first 0x10 bytes
    u16 region_offset
    u16 region_length
    u32 region_crc       CRC-32 of [region_offset, region_offset + region_length)
    u32 flags            bits 26..29 = scan group; low 26 bits preserved
    u8  name_len         optional; includes the trailing NUL
    u8  name[name_len]   optional engine label

The first field is **not** a hash; the matcher receives the first four file
bytes and uses them as the table key, so DOS files literally show `4d 5a`
(`MZ`).  A hit requires the key, the header CRC, and the region CRC to match.
`flags >> 26 & 0xf` selects the scan group (0 normal file scan, 8 HLP, 9).
Real threats use 22,313 anonymous records; the 133 named records in
`!InfrastructureShared` are checksum-keyed known-file policy tags such as
`~stuba.slow`, `~avir.slow`, `~SUPD.false` and `#Type_Trojan`, the same concept
as STATIC's `#ExpensiveFile`/`#FP:` tags.  `CKSIMPLEREC` is expressible in
YARA (`uint32(0)` plus two `hash.crc32` windows), but no generator is wired up.

### `SIGNATURE_TYPE_CKOLDREC` (`0x11`)

The older two-region form, now decoded as well::

    u16 region1_offset    also the runtime group index (0..0x3f)
    u16 region1_length    almost always 0x10
    u32 region1_crc
    u16 region2_offset
    u16 region2_length
    u32 region2_crc
    u32 flags             bits 26..29 = scan group
    optional u8 name_len + name

1,740 real-threat records plus one named known-file tag (`~Holupfpos`).

### `SIGNATURE_TYPE_NSCRIPT_NORMAL` (`0x27`)

The general script-condition container (handler `FUN_180180ef0` wrapping the
shared `FUN_180180f0c` parser)::

    u8  name_len; u8 name[name_len]
    u8  count
    u32 hash_a[count]
    u8  flags
    flags == 0:  u32 hash_b[count]       every hash is pairwise
    flags != 0:  u32 hash1, match_length, optional u32 hash_b[count]
    optional u32 weight                  only the low byte is used

With `flags == 0` every `{hash_a[i], hash_b[i]}` pair is inserted into the
script hash-pair vector (`DAT_181106a20`).  With `flags != 0` the first entry
becomes a rolling-window condition in `DAT_181106a18`
(`{hash1, match_length, hash2=hash_a[0], flags}`) and the remaining pairs are
added as above.  That is exactly the `NSCRIPT_SP` content in a longer
container, including the legacy `:IRC/` flags 1/2 special case.

Coverage: 10,715 records (9,775 real threats, 940 shared).  Forms: 9,917
ordinary hash-pair records, 11 compact records with no pair array, 429 + 358
window records (flags `0x01`/`0x02`).  15,742 hash-pair conditions and 787
window conditions, 2,942 trailing weights, 939 named shared records.  All
records decode with zero warnings.

| type | records | decoded | named | notes |
|------|--------:|--------:|------:|-------|
| `CKSIMPLEREC` `0x50` | 22,446 | 22,446 | 133 | 22,313 real, all anonymous |
| `CKOLDREC` `0x11` | 1,741 | 1,741 | 1 | 1,740 real |
| `NSCRIPT_NORMAL` `0x27` | 10,715 | 10,715 | 939 | 11-record compact variant |

Decoders: `defender2yara/defender/signature/cksimplerec.py`
(`CkSimpleRecSig`, `CkOldRecSig`) and `NscriptNormalSig` in `nscript.py`.
Wired into `Vdm.decode_record`; tests in
`tests/test_signature_ck_nscript_normal.py`.  None of the three feeds YARA:
the CK records are region hashes and `NSCRIPT_NORMAL` stores only script
hashes.

## Eighth round: plaintext aggregators and path signatures

Full write-up: `doc/sigs/sig_decode_aggregator_paths.md`.  Engine notes were
added to `cache/functions_vdm.md` §15.

Three more types now have structural decoders.  All 18,291 records parse with
zero errors and zero warnings.

- `SIGNATURE_TYPE_AAGGREGATOR` (`0x96`) is the **legacy plaintext form of
  `AAGGREGATOREX`**.  Same header (`u8 flags, u8 name_len, u16 body_len, name,
  body`) and the same expression compiler (`FUN_1801858a8`), but the body is
  plain ASCII instead of being substituted with the `0xe7` table at
  `0x180d9e080`.  The optional name is plain text in both forms.  Handler
  `FUN_18041a5d0`.  9,757 records: 6,646 in real threats (anonymous) and 3,111
  shared records with `!#...` feed names.
  Example: `VirTool:Win32/Injector` ->
  `SLFPER:Win32/InjectsRundll32&(Lua:IsEnterprise|IsSeville)`.
- `SIGNATURE_TYPE_FILEPATH` (`0x5f`) and `SIGNATURE_TYPE_FOLDERNAME` (`0x60`)
  are **path conditions**, not hashes: `u16 root_id` plus a case-insensitive
  path/glob with no NUL terminator.  The root id is a Windows CSIDL
  (`0x25` System32, `0x26` Program Files, `0x1a` AppData, `0x24` windir, ...)
  or an engine pseudo-folder: `0xfffb` system drive, `0xfffc`
  `%CommonProgramFiles%`, `0xfffd` `%allusersprofile%`, `0xfffe` `%temp%`,
  `0xffff` literal absolute path.  `?`/`*` are glob wildcards.  Coverage:
  2,479 FILEPATH records (515 threats) and 6,055 FOLDERNAME records (2,020
  threats), e.g. `FILEPATH %temp%\s.cmd`,
  `FILEPATH %CommonProgramFiles%\microsoft shared\greenav20??.exe`,
  `FOLDERNAME %ProgramFiles%\common files\kuum`.

Decoders: `AaAggregatorSig` in `defender2yara/defender/signature/aggregator.py`
(the `0xe7` parser was refactored into a shared `_AggregatorSig` base) and
`FilePathSig` / `FolderNameSig` in
`defender2yara/defender/signature/pathname.py`.  Wired into
`Vdm.decode_record`; tests in `tests/test_signature_aggregator_paths.py`.
None of the three feeds YARA: an aggregator references other rules, and a path
record is not a file-byte pattern.

## Ninth round: macro p-code fingerprints and standalone Lua scripts

Full write-up: `doc/sigs/sig_decode_macro_pcode_lua.md`.  Engine notes were
added to `cache/functions_vdm.md` §16 and §17.  User-facing pages:
`app/static/sigs/SIG_MACRO_PCODE.md` and `app/static/sigs/SIG_LUA.md`.

### `SIGNATURE_TYPE_MACRO_PCODE64` (`0xcf`) and `MACRO_PCODE` (`0x42`)

These are **VBA p-code fingerprints**, not file hashes.  The `macro` module
(`FUN_180a50370`) registers them next to `MACRO_SOURCE`; the parsers
`FUN_180432b10` (`0xcf`) and `FUN_180432aa0` (`0x42`) read three routine keys
and an optional NUL-terminated feed name (e.g.
`!#ALF:Trojan:Win32/NeoHash.macropcode`).

Each 64-bit key is `crc32 | crc16 << 32 | length << 48`: Defender CRC-32 (init
`0xffffffff`, no final xor), reflected CRC-16/ARC (init 0) and the number of
bytes hashed.  The 32-bit form keeps only the CRC-32, so its length/CRC-16
fields are zero.  A slot of `0` (64-bit) or `0xffffffff` (32-bit) means "not
used".

At scan time `FUN_18024a84c` / `FUN_18024b1dc` walk the decompressed p-code of
each VBA module for the three supported p-code dialects and keep a rolling hash
of every opcode byte plus one of the "significant" opcode subset
(`0x180c953c0`, opcode tables `0x180f0a1d8` / `0x180f0b198` / `0x180f0c1d8`).
`FUN_18024d118` then queries the record table with those hash pairs;
`FUN_18024d8a4` walks the table group with the same key1 and requires key0 to
match (a record with an unset key1 matches on key0 alone, via the fallback
index `DAT_1811069d0`).  The third key is stored and re-serialised but **not
consulted by the matcher** in this build.

Coverage: 5,978 `0xcf` records (5,925 real threats, 53 named shared) and 2,434
`0x42` records (2,432 real, 2 named).  key0 lengths span 10..55,202 bytes and
key1 lengths 0..17,767.  They are internal routine hashes, so no YARA output.

### `SIGNATURE_TYPE_LUASTANDALONE` (`0xbd`)

A **standalone MpLua script**: `u8 name_len, u8 phase, u16 attributes_len,
u32 body_len`, then name, NUL-separated `name\0value\0` attribute pairs and a
Lua 5.1 chunk.  66,760 records (66,606 with the normal 12-byte MpLua header,
154 with the headerless `01 00 …` variant; 66,308 of them in
`!InfrastructureShared`, all named, 452 real-threat records anonymous).

Byte 1 is an index into the engine's 36-entry **phase table** at
`0x180c6a650` (`FUN_180494924` resolves phase names to it): `Unknown`,
`Infrastructure`, `Deprecated`×6, `PEPREEMU`, `PEPOSTEMU`, `PELast`,
`PEFinalizer`, `GenFirst`, `GenLast`, `PreRemediation`, `PostRemediation`,
`IETrigger`, `DetectionSpecific`, `ProcessInspector`, `UACTrigger`, `FFR`,
`SignatureValidator` (63,291 records), `MacroSource`, `DynamicSignature`,
`GenFinalizer`, `HipsRuleDefinition`, `RtpSkipRule`, `RtpSkipRuleEx`,
`OnDetection`, `GenConsolidator`, `MachOGen`, `MemScan`, `GenEarly`,
`OnImageConfig`, `MpDiag`, `ELFGen`.

Attributes are `name\0value\0` pairs: `Includes` (7,035; comma-separated
library lists such as `BMLuaLib`, `TechniqueTracker`, `LuaFuncHelper`),
`ObMpAttributes` (2,121; obfuscated values), `Flags` (1,188) and
`ObProcessAttributes` (3).  `Ob`-prefixed values are decoded by the engine with
`FUN_1805afc44` plus the substitution table at `0x180dc18a0`.

The body is a normal Lua 5.1 chunk (`FUN_1803e6f18` → `FUN_180a9a76c`): function
prototypes, 32-bit string lengths, **signed integer** number constants and
debug info (dropped by the loader).  `LuaSig` walks all of it: 69,057 function
prototypes, 2,241,907 instructions and 631,623 string constants in this DB.  The
154 headerless (`01 00 …`) records keep the same wrapper but substitute their
`code` arrays with a byte-wise chained cipher (the engine's 256-byte table at
`0x180dc18a0`); `LuaSig` reverses it, so all 154 decode to valid Lua 5.1
(`code_encoding = "substituted"`) and 144 decompile cleanly.  A script is
detection logic, so it does not become a YARA byte pattern; the decompiled source
and the constants are the useful output.

Decoders: `defender2yara/defender/signature/macro_pcode.py` (`MacroPcodeSig`)
and the rewritten `defender2yara/defender/signature/lua.py` (`LuaSig`, plus
`parse_lua_chunk`, `phase_name` and `split_attributes`; the instruction cipher
lives in `lua_crypto.py`).  Wired into `Vdm.decode_record`; tests in
`tests/test_signature_macro_pcode_lua.py`.

## Tenth round: command-line HSTR and DEX HSTR

Full write-up: `doc/sigs/sig_decode_cmdhstr_dexhstr.md`.  Engine notes were
added to `cache/functions_vdm.md` §18.  User-facing pages:
`app/static/sigs/SIG_CMDHSTR.md` and `app/static/sigs/SIG_DEXHSTR.md`.

Both types are members of the engine's shared **HSTR** family
(`FUN_180a1f948`, type table `0x180c8b800`, generic parser `FUN_180182d14`,
pattern compiler `FUN_180183298`, matcher `FUN_180249264`).  They use the same
container and weighted sub-rules as `PEHSTR_EXT`; only the scan target and the
sub-rule flag combination differ.

### `SIGNATURE_TYPE_CMDHSTR_EXT` (`0xd7`)

Kind 11 in the HSTR type table: a **command-line content signature**.  It is
matched against process command lines by the `cmdlinescan` module
(`FUN_180afde40`, main scan `FUN_180554374`, callback `FUN_180afce70`), not
against file bytes.  The engine callers are `HSTR_CALLER_CMDLINE`,
`HSTR_CALLER_TSKSCHED_CMDLINE` and `HSTR_CALLER_BITS_CMDLINE`; `#ClnCmdLine`
is the clean-verdict tag.

* 5,415 records in `cache/threats.db`: 2,941 real-threat records (2,737
  threats) and 2,474 `!InfrastructureShared` copies; 30,142 sub-rules.
* Patterns are 92% UTF-16LE and 8% ASCII.  4,074 sub-rules use HSTR
  wildcards (`90 01`/`90 02`/`90 03`); 399 are case-sensitive; 1,661 use the
  extended header (`flag 0x80`, `extra == 1`); 2,859 have negative weights
  (exclusion/penalty conditions).
* Real-threat records are anonymous.  Shared copies are labelled
  `!#SLF:` (2,060), `!#TEL:` (324), `!#ALF:` (43), `!#HSTR:` (11), `!#CMD:`
  (11), `!#SLFPER:` (11), `!#TELPER:` (8), plus a few one-offs.
* Example (`Trojan:Win32/Kovter.G`):
  `mshta<skip 0..16>javascript:<skip 0..255>new activexobject(`.
  The dominant families are ClickFix/SuspClickFix, PowerShell downloaders and
  `mshta` launchers.
* The optional tail word is zero in 5,394 records (21 use 1/2/5/6/10) and no
  record has a second tail word.

`SIGNATURE_TYPE_CMDHSTR_FAST_EXT` (`0xdd`, kind 16) is the same layout on the
fast/low-fi command-line path; only two records exist (both
`Trojan:Linux/FchsE2ETest*` test strings) and they now decode as well.

### `SIGNATURE_TYPE_DEXHSTR_EXT` (`0xbe`)

Kind 5: the Android/Dalvik **DEX string-table** member.  Patterns are UTF-8
string fragments (with uleb128-length skips and byte classes), mostly
case-sensitive.  The earlier 287 "name reference" records in
`!InfrastructureShared` are not pattern-less: the sub-rules follow the label
and are now kept and rendered.

* 3,053 records: 2,766 real (2,653 threats) and 287 shared; 16,409 sub-rules.
* 10,402 case-sensitive sub-rules, 526 with wildcards, 117 extended-header
  sub-rules, 424 records with the second tail word ("DEX flags", values 1..46).
* Example (`TrojanSpy:AndroidOS/Geimini.A`):
  `hi,xiaolu<skip 2>hi,liqian<skip 2>command ok<skip 2>bye` and
  `AdActivity<op 09 0c00>com<any-of {2e} x1>/geinimi`.

### Shared sub-rule flags (corrected)

The engine reads the sub-rule byte after the size as a flag byte
(`FUN_180183298`): bit `0x01` = case-sensitive, bit `0x02` = wildcard pattern
(must end in `90 00`, case folding is wildcard-aware), bit `0x80` = one
`extra` byte precedes the pattern; `extra` bit 0 makes the engine register an
additional terminator-less variant (internal flag `0x400`).  The old parser
special-cased `0x88`/`0x90` and shifted the pattern by one byte; that is fixed
in `HStrExtSubRule`, which now also exposes `case_sensitive`, `wildcard`,
`extended`, `extra`, `variant` and `entry_size`.

`CMDHSTR_EXT`/`CMDHSTR_FAST_EXT` are now decoded by `CmdHStrExtSig`,
`DEXHSTR_EXT` by `DexHStrExtSig` (both in
`defender2yara/defender/signature/hstr.py`), and `decode_hstr_pattern()`
renders UTF-16LE/ASCII literal runs plus the wildcard tokens.  Tests:
`tests/test_signature_cmdhstr.py`; existing DEX tests were updated because
named records keep their sub-rules.

## Eleventh round: key patterns (KPAT / KPATEX)

Full write-up: `doc/sigs/sig_decode_kpat.md`.  Engine notes were added to
`cache/functions_vdm.md` §19.

`SIGNATURE_TYPE_KPAT` (`0xbb`) and `SIGNATURE_TYPE_KPATEX` (`0xbc`) are the
only implemented types besides HSTR whose payload is directly a matchable
**byte pattern**.  They are not format-specific: one `kpat` matcher is used by the
boot-sector / MBR / VBR scan, memory and decompressed-buffer scans and the VBA
macro reader.  Both types share one layout::

    u8  pattern_length          total length, 8 + len(tail); 9..197 observed
    u8  anchor[8]               literal first 8 bytes (Aho-Corasick key)
    u8  tail[pattern_length-8]  remaining pattern bytes
    u8  name_length             optional
    u8  name[name_length]       optional aggregator reference label

* `KPAT` tails are literal bytes in which `0x90` is a single-byte wildcard;
  `0x00` stays a literal NUL.  The anchor is always literal, even when it
  contains `0x90`.
* `KPATEX` tails use the HSTR `0x90` wildcard language (terminator `90 00`,
  skip `90 01 n`, skip range `90 02 n`, byte class `90 03`, repeat
  `90 04`/`90 05`, literal `90 90`) and must end with `90 00`; the loader
  validates them with `FUN_1802b1974`.

The engine finds the 8-byte anchor with the multi-pattern matcher
(`FUN_180047200` inside `FUN_1800fa880`) and only then verifies the tail, byte
by byte for `KPAT` or through the wildcard matcher `FUN_180049320` for
`KPATEX`.  The two tables (`DAT_181115ca0` / `DAT_181115c90`, element type
`0x4bb` / `0x4bc`) are registered by the HSTR module init `FUN_180a1f948`,
not by a dedicated parser: they use the generic template loader
(`FUN_1804eae94` + `FUN_180181cc4`, template at `0x180f07500`).

The optional name is the group label used by aggregator expressions.  It is
written `!#KPAT:<label>` (or `!#TEL:KPAT:...`, `!#SLFPER:KPAT:...`) in
`!InfrastructureShared` and referenced as `KPAT:<label>`; real-threat records
are anonymous and are addressed through their owner
(`KPATEX:Worm:INF/Autorun.A`).

Coverage in `cache/threats.db`:

| type | records | real (threats) | shared | named | decoded |
|------|--------:|---------------:|-------:|------:|--------:|
| `KPAT` `0xbb` | 208 | 183 (178) | 25 | 9 labels | 208, 0 warnings |
| `KPATEX` `0xbc` | 123 | 82 (71) | 41 | 31 labels | 123, 0 warnings |

`KPAT` is dominated by DOS/boot-sector code (`Virus:DOS/Rex.1637`,
`Virus:DOS/AOS`) plus PDF/key-material patterns.  `KPATEX` is dominated by
SWF/ActionScript bytecode, `autorun.inf` text and shellcode.  Both are
expressible in YARA hex; the decoder renders `pattern_hex` (`??`, `[n]`,
`[0-n]`, `( aa | bb )`) but no generator is wired up.  Decoders:
`KpatSig` / `KpatExSig` in `defender2yara/defender/signature/kpat.py`,
wired into `Vdm.decode_record`; tests in `tests/test_signature_kpat.py`.

## Twelfth round: VDLL virtual DLL images

Full write-up: `doc/sigs/sig_decode_vdll.md`.  User-facing page:
`app/static/sigs/SIG_VDLL.md`.  Decoder: `VdllSig` in
`defender2yara/defender/signature/vdll.py`; tests in
`tests/test_signature_vdll.py`.

`SIGNATURE_TYPE_VDLL_X86` (`0x79`) and `SIGNATURE_TYPE_VDLL_X64` (`0x7c`)
are not fingerprints: the TLV payload is a complete PE DLL image starting
directly with `MZ`.  They are the emulator's "virtual DLLs"; the export
directory name is the Windows module being emulated (`MSHTML.DLL`,
`LZ32.DLL`, `BASESRV.DLL`, `api-ms-win-core-*.dll`, …) and the exports are
the API entry points.

There are 945 records in `!InfrastructureShared` (750 x86, 195 x64;
54.2 MB, 36% of the bucket's bytes).  They contain 135,017 exports, 33,257 of
them forwarded, and 7,311 imports.  All 945 payloads now decode as PE32/PE32+
DLLs with the expected machine (`0x14c` / `0x8664`).  This closes the last
large undecoded region of `!InfrastructureShared`.

VDLL_META (`0xb5` / `0xe1`) records remain opaque; they are not needed to
parse an image, because the PE itself carries the module name and API surface.

## Thirteenth round: KVIR32 page fingerprints and REGKEY registry conditions

Full write-up: `doc/sigs/sig_decode_kvir32_regkey.md`.  Engine notes were
added to `cache/functions_vdm.md` §21.

These were the last two large undecoded types.  Neither contains an inline
byte pattern, so neither feeds YARA generation.

### `SIGNATURE_TYPE_KVIR32` (`0x20`)

A **two-window CRC page fingerprint**, not a byte pattern.  Layout::

    u32 anchor_crc      CRC-32 of 16 bytes at page offset 16 * anchor_window
    u32 body_crc        CRC-32 of body_length bytes at body_offset
    u16 body_offset     offset inside the scanned page
    u16 body_length     body window length
    u16 anchor_window   0, 1 or 2 -> anchor at page offset 0, 16 or 32
    i16 flags           0 = report; negative (0x8000) = match only
    u8  name_length     optional
    u8  name[name_length]

The page scanner (`FUN_180118728`) computes the CRC of the 16-byte windows at
`page + 16*i`, looks up `anchor_crc` (`FUN_18011804c`), requires the stored
window index to match, and finally verifies the body window with
`FUN_1804a4c5c` (CRC-32 of `[body_offset, body_offset + body_length)`,
possibly spanning pages).  A negative `flags` value suppresses the report;
those records only feed the emulator/repair logic.  The optional name is not
part of the record id (`crc32(16 bytes) | 0x20 << 32 | 0x10 << 40`).

Despite the name, the type is mostly used for **packer and entry-point
fingerprints**.  All 1,226 shared records are named (680 labels) -
`!UPX_1_X`, `!ASProtect`, `!Themida`, `!FSG_1_3`, `!PECompact`, `!Armadillo`,
`!MPRESS64`, ... - and many real-threat records are emulator conditions such
as `!#attrmatch_codepatch_EIP_00000009_909090909090`.  Real owners include
`Trojan:Win32/Dorv.A` (548), `Trojan:Win32/Tracur`, `VirTool:Win32/CeeInject*`
and the Sality/Godog/Xpaj file infectors.

Coverage: 6,595 records (5,369 real, 2,704 threats).  `anchor_window` 0/1/2 =
6,377/195/23; `flags` 0/0x8000 = 6,497/98; 6,239 records have
`body_offset == 16 * anchor_window`.  Body lengths are dominated by 64 (3,101),
36 (1,006) and 1024 (449); offsets stay <= 768 and offset+length <= 16,384.
All 6,595 records decode with zero errors and zero warnings.

### `SIGNATURE_TYPE_REGKEY` (`0x63`)

A **registry condition** evaluated against the live registry, not a file
signature::

    u16 hive            1 HKCR, 2 HKCU, 3 HKLM, 4 HKU (accepted, unused)
    u16 key_length
    u8  key[key_length]
    u16 value_length
    u8  value[value_length]

The key is stored relative to the hive.  A literal `\\` in the key separates
the key path from the **value name**; an empty value string means "the key
exists", a non-empty one is the expected value data.  `FUN_1802b27c0`
(resmgr, registered by `FUN_1809382c0` next to FILEPATH/FOLDERNAME) validates
the hive and lengths, splits the key at the first `\\`, strips one of eleven
well-known path prefixes (`FUN_1802b34f4`, table `0x180d82b50`), interns the
data and registers the condition.  Matching is case-insensitive and treats `/`
as `\` (`FUN_1803c3420` / `FUN_18093a800`); entries with a value name live in
one table and "key + value data, any value name" entries in another.

The hive ids are inferred from the stored keys: HKCR holds only extension keys
and ProgIDs, HKCU the per-user `Software\VB and VBA Program Settings` family,
HKLM the `SYSTEM\CurrentControlSet` / Winlogon / Internet Settings family.
A hive id outside 1..4 makes the engine ignore the record; the database has one
such `0xffff` record.

Coverage: 3,911 records used by 542 threats; HKLM 2,526, HKCU 1,310, HKCR 74
and one invalid.  476 records pin a value name (72 with an empty name, e.g.
`.z\\`) and 269 carry expected value data.  All records parse; the invalid-hive
record is flagged `partial`.  Top owners are adware/browser-modifier families
(`Hotbar` 167, `BrowserModifier:Win32/Zwangi` 162, `...Cometsystems` 104,
`Rogue:Win32/SpyAxe` 86).

Examples: `HKCU\Software\kuum` (existence),
`HKLM\SYSTEM\CurrentControlSet\Services\Wmi\Parameters\\ServiceDll =
"%SystemRoot%\System32\WdmWmi.dll"`,
`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\\ProxyServer
= "77.78.240.167:80"` and `HKCR\.z\\ = "WinZipper.z"`.

Decoders: `Kvir32Sig` in `defender2yara/defender/signature/kvir32.py` and
`RegKeySig` in `defender2yara/defender/signature/regkey.py`.  Wired into
`Vdm.decode_record`; tests in `tests/test_signature_kvir_regkey.py`.

## Fourteenth round: NDAT typed strings, generic BRUTE and BOOT images

Full write-up: `doc/sigs/sig_decode_ndat_brute_boot.md`.  Engine notes were
added to `cache/functions_vdm.md` §22.  These were the last three types that
still contained matchable/typed content but were only stored as raw records.

All 7,781 NDAT, 5,703 BRUTE and 1,217 BOOT records decode with zero errors and
zero warnings.

### `SIGNATURE_TYPE_NDAT` (`0xa9`)

A **typed named-data record**, not a file fingerprint::

    u32 data_length
    u8  data[data_length]    # NUL included for strings, raw bytes for RKPAT/regex
    u8  type                 # NDAT class 1..23
    u8  label[]              # optional NUL-terminated feed label (!#NRI:..., #NoApiCallCounting)

The record is parsed by the generic template interpreter
(`FUN_180181cc4`, template `0x180f073e0`) registered by the `cksig` module as
type `0x4a9` (`0x400 | 0xa9`).  The 0x18-byte table entry is
`{u32 data_len, u32 condition_id, ptr data, u8 type}`; the commit callback
`FUN_180280ab0` dispatches on the type byte through `DAT_181115430`.

The first 14 NDAT names are in `0x180c77f98` and the enum is one-based:
1 `PROJECTPATH_REGEX`, 2 `PROJECTNAME_REGEX`, 3 `DONTCOUNT_API`, 4
`FIRE_EVENT`, 5 `LOGSKIP_ENTRY`, 6 `VFS_LINK`, 7 `API_ATTRIBUTE`, 8 `RKPAT`,
9 `EBHASHDATA`, 10 `PDBPATH_REGEX`, 11 `PDBNAME_REGEX`, 12
`INCLUDE_DNS_CACHE_INFO`, 13 `REGEXP_GENERIC`, 14 `DBTAG`.  Types 15..23 are
the NRI/AIMCP classes: domain, HTTP-header, generic regexp, certificate
subject, response/body, certificate bytes, LSASS audit rule, `RtpSkipRuleEx`
(22) and transport (23).

The engine registers `RtpSkipRule` for type 5 and `RtpSkipRuleEx` for type 22;
`NdatRegExpMatch` only accepts type 13.  `FUN_18024ff68` compares a record's
string with a candidate, and `FUN_180b1e590` implements the
`NdatRegExpMatch <type 13> <regex>` definition command over the
NUL-terminated vector `DAT_181123f88`.

Coverage: 7,781 records, 3,360 labelled / 4,421 anonymous, 99.8% textual, data
length 1..3,345 (median 39).  Real-threat usage is dominated by VBA project
paths (`PROJECTPATH`, 368), PDB paths (753) and the Alureon/Sirefef raw code
patterns (`RKPAT`, 33); the rest are shared infrastructure tables
(`LOGSKIP_ENTRY` 3,584, `DONTCOUNT_API` 969, `VFS_LINK` 1,215, NRI domain 264,
cert subject 278, ...).

Examples: `MSVCRT.DLL!cos` (`#NoApiCallCounting`),
`*.VHDX.|*|Microsoft-Hyper-V`, `C:\WINDOWS\SYSTEM32\MFC71.DLL>...\MFC42.DLL`,
`^Subject: CN=aaatus\.com`, `AUDIT_M1:9e6c4e1f-...`, `slootni.com`.

### `SIGNATURE_TYPE_BRUTE` (`0xd0`)

The **generic script brute pattern**: the exact `NSCRIPT_BRUTE` (`0x29`)
payload (name, kind byte, mode, `any_length`, wildcard pattern ending `90 00`)
but stored in a separate, script-type-agnostic table.  The record sets are
disjoint (no `0xd0` payload duplicates a `0x29` payload).

`0xd0` is registered by the **kcrce module** (`FUN_180927150` ->
`FUN_180927754`), not by `nscript`: parser `FUN_1801828c0`, table tag `brut`
(`0x62727574`), commit `FUN_180517e50` (builds a dedicated Aho-Corasick matcher
`DAT_1811152c8`), driver `FUN_180517568`.  The in-memory entry is
`{pattern ptr, condition id, anchor offset/length, any_length, pattern_length,
mode, kind, variant, high flag}`.

Coverage: 5,703 records, 3,978 labelled / 1,725 anonymous; **all use script
kind 0 ("any")**; mode anywhere 4,405, forward 1,041, backward 257;
`any_length` unset in 5,649; pattern length 6..1,539 (median 25); 2,404
patterns contain wildcard tokens.  These are the patterns behind the
`BRUTE:JS:Feature:` / `BRUTE:VBS:Feature:` / `BRUTE:PDF:Feature:` features and
the `mp.GetBruteMatchData()` / `mp.ReadBruteMatchBuffer()` Lua API.  Example:
`!#SCPT:AICustomDiscovery.ClaudeAgentSDKPy` -> `ClaudeAgentOptions`.

### `SIGNATURE_TYPE_BOOT` (`0x44`)

The **boot image signature** used by the MBR/VBR/boot-sector scanner::

    u8 name_length           0 = anonymous
    u8 name[name_length]     feed label (!#BOOT:..., !#TEL:...)
    u8 blob[32]

Normal form (`blob[0]` = 4..31): `u8 pattern_length; u8 pattern[31]` (the rest
is zero padding).  The first four bytes are compared as a dword; the remainder
is compared byte-wise with `0x90` as a single-byte wildcard.

CRC form (`blob[0] == 0x20`): `u8 0x20; u8 0; u8 anchor[8]; u16
covered_length; u32 crc32; padding[15]`.  The matcher matches the 8-byte
anchor and then compares the Defender CRC-32 of `[match, match +
covered_length)`.

The type is registered by the `BootImgs` module init `FUN_180ac2ca0` (table
`DAT_181115d10`, 0x24-byte entries, template `0x180f39560`, type `0x544`).
`FUN_18015da40` is the matcher (byte-index prefilter, normal or CRC form);
`FUN_1800f95a0` scans `0x800`-aligned sectors up to `0x40000` and calls it on
the first `0xc0` bytes, `FUN_1800fb080` adds the boot memory-stealth path and
`FUN_180363558` the boot verification path (`MpInternal_bootsigoffset=%lld` /
the `bootsigoffset` report field).

Coverage: 1,217 records, 979 normal / 238 CRC form, 14 labelled / 1,203
anonymous; normal pattern length 4..31 (31: 268, 30: 112), 112 patterns with
wildcards; CRC covered length 14..300 (median 56).  Examples:
`Virus:DOS/Half` (30-byte literal), `Virus:DOS/MpTestBoot` (wildcards),
`Virus:DOS/3nop` (anchor `909090fa33c08ed8`, length 42, crc32 `63fd44a8`),
`!#TEL:Ransom:DOS/Petya.A` (31-byte pattern).

### Coverage

| type | records | decoded | named | notes |
|------|--------:|--------:|------:|-------|
| `NDAT` `0xa9` | 7,781 | 7,781 | 3,360 | typed data, 13 classes + NRI classes |
| `BRUTE` `0xd0` | 5,703 | 5,703 | 3,978 | generic script brute, kind "any" only |
| `BOOT` `0x44` | 1,217 | 1,217 | 14 | 979 patterns + 238 CRC regions |

Decoders: `NdatSig` in `defender2yara/defender/signature/ndat.py`, `BruteSig`
in `defender2yara/defender/signature/brute.py` (subclass of
`NscriptBruteSig`) and `BootSig` in
`defender2yara/defender/signature/boot.py`.  Wired into
`Vdm.decode_record`; tests in `tests/test_signature_ndat_boot_brute.py`.

`BRUTE` and `BOOT` contain inline patterns and are expressible in YARA
(`??` per wildcard; `[n]` skips for BRUTE).  `NDAT` is a condition string, not
a file pattern.  No YARA generator is wired up for these three types.

## Fifteenth round: ASEP paths and file-offset code patterns (FOP / FOPEX)

Full write-up: `doc/sigs/sig_decode_fop_asep.md`.  Engine notes were added to
`cache/functions_vdm.md` §23.  All 1,191 `ASEP_FILEPATH`, 790 real-threat `FOP`
and 1,189 real-threat `FOPEX` records decode with zero errors and zero warnings.

### `SIGNATURE_TYPE_ASEP_FILEPATH` (`0x71`)

This is **the same payload as `FILEPATH` (`0x5f`)**: a `u16` CSIDL/pseudo-root
id followed by a case-insensitive relative path or glob (no NUL terminator).
The resmgr plugin (`FUN_180939aa0`) registers four builders that share the
parser/commit logic in `FUN_1802b378c`:

| type | builder | meaning |
|------|---------|---------|
| `0x5f` `FILEPATH` | `FUN_1802b3690` | file path/glob condition |
| `0x71` `ASEP_FILEPATH` | `FUN_1802b3590` | same path at an ASEP (auto-start extensibility point) |
| `0x60` `FOLDERNAME` | `FUN_1802b39c0` | directory path/glob condition |
| `0x75` `ASEP_FOLDERNAME` | `FUN_18093a1a0` | same directory at an ASEP |

The builder computes `crc32(payload) | type << 32 | size << 40` and emits the
TLV with `FUN_180217edc`.  The ASEP context is therefore a type id, not extra
payload: the same `%SystemRoot%\System32\ftpudp.exe` path can be a plain file
condition or an ASEP check.  The engine's ASEP configuration strings
(`MpExtraAsepScanLocations`, `MP_EXTRA_ASEP_SCAN_LOCATIONS`) confirm the
auto-start meaning.  `ASEP_FOLDERNAME` has no shipped records.

Examples: `ASEP_FILEPATH %SystemRoot%\System32\ftpudp.exe` (Worm:Win32/Korgo.AY),
`ASEP_FILEPATH %windir%\system\eschlp.exe` (Worm:Win32/Msblast.F).  Top owners
are browser modifiers/adware (`Hotbar`, `CnsMin`, `C2Lop`) and ASP webshells.

### `SIGNATURE_TYPE_FOP` (`0x7f`) and `FOPEX` (`0x89`)

These are **file-offset code patterns** used by the emulator/code scanner, not
file hashes.  The family is registered by `FUN_180b60a70` and parsed by
`FUN_1802b10b4`; `FopScanner::x86_fop_processor` /
`x64_fop_processor` (vftables `0x180c84870` / `0x180c84860`) run the match.
`FOP` is a literal x86 fragment; `FOPEX` adds the engine wildcard language, a
name, and a signed match offset.  The same layout family also covers `FOP64`
(`0xc8`), `FOPEX64` (`0xc9`), `VB`p-code (`0xb4`/`0xc7`) and MSIL
(`0xba`/`0xc6`).

`FOP` payload::

    u8  flags            bit 0 only (0/1 observed)
    u8  name_length
    u16 pattern_length
    u8  name[name_length]      feed label, not NUL terminated
    u8  pattern[pattern_length] literal bytes (0x90 is a NOP, not a wildcard)

`FOPEX` payload::

    u8  flags            bit 0 only
    u8  name_length
    u16 prefix_length    literal code block
    u16 body_length      wildcard pattern block (always ends 90 00)
    u16 suffix_length    optional extra block (0 or 1 observed)
    i16 offset           signed match offset (-480..1064 observed)
    u8  name[name_length]
    u8  prefix[prefix_length]
    u8  body[body_length]
    u8  suffix[suffix_length]

The parser validates the exact total length and runs the wildcard validator
`FUN_1802b1974` over the FOPEX body/suffix.  The matcher
(`FUN_1801f9ec0` -> `FUN_1801fa18c`) adds the signed offset to the current scan
position and checks the literal prefix byte-wise.  The same matcher is called
from the KVIR32 page scan (`FUN_180118728`), the MSIL/VB scanners and the
generic record lookup (`FUN_180b66e50`).  Nothing here is a file-byte pattern in
the scanned file in the same sense as HSTR/KPAT: it is a code/emulation
fingerprint.

Coverage:

| type | records | real | named | notes |
|------|--------:|-----:|------:|-------|
| `ASEP_FILEPATH` `0x71` | 1,191 | 1,191 | 0 | FILEPATH payload, ASEP context |
| `FOP` `0x7f` | 1,519 | 790 | 729 (474 labels) | literal fragments, 1,476 flag 0 / 43 flag 1 |
| `FOPEX` `0x89` | 2,806 | 1,189 | 1,617 (1,096 labels) | 2,801 without suffix, 5 with 1-byte suffix |

`FOP` labels are packer/obfuscator names (`!ASprotect`, `!eXPressor`,
`!UPX_LZMA2_3.00`, `!#FOP:Win32/Nuwar.unsafe`); `FOPEX` labels are code-patch
attributes and deep-analysis handlers
(`!#attrmatch_codepatch_EIP_00000007_eb`,
`!#FOPEX:VirTool:Win32/Obfuscator.ACV!EP`, `!#LoD:...`).  Examples:

* `FOP !ASprotect` -> `bb 03 2b 83 89 0f 8d 50 ff ...` (42-byte literal fragment)
* `FOPEX !#Tracur_LoDCheck` -> prefix `b9 48 e2`, body `fd 90 00`, offset `7`
* `FOPEX` Cutwail -> `55 8b 64 8b 25 2d 66 75 a3 8d 51 50` +
  `90 02 06 "HeapAlloc" 00 90 03 02 04 ff 15 "SetT" 90 00`, offset `42`

Both FOP forms are expressible as YARA hex (`??` for literal wildcards, `[n]`
skips for FOPEX tokens), but no generator is wired up.  Decoders: `AsepFilePathSig` /
`AsepFolderNameSig` in `defender2yara/defender/signature/pathname.py` and
`FopSig` / `FopExSig` in `defender2yara/defender/signature/fop.py`; wired into
`Vdm.decode_record`; tests in `tests/test_signature_fop_asep.py`.

## Aggregate pseudo-threat records

These rows are Microsoft infrastructure buckets, not detections. They are excluded above 
because they would otherwise dominate the ranking.

| Record | Signatures | Most common types |
|--------|-----------:|-------------------|
| `!Infrastructure` | 93,294 | `SIGNATURE_TYPE_TRUSTED_PUBLISHER` 92,919, `SIGNATURE_TYPE_DEFAULTS` 356, `SIGNATURE_TYPE_CLEANSCRIPT` 10, `SIGNATURE_TYPE_VERSIONCHECK` 8, `SIGNATURE_TYPE_LATENT_THREAT` 1 |
| `!InfrastructureShared` | 911,958 | `SIGNATURE_TYPE_SNID` 447,605, `SIGNATURE_TYPE_NSCRIPT_BRUTE` 114,976, `SIGNATURE_TYPE_NID` 105,537, `SIGNATURE_TYPE_LUASTANDALONE` 66,308, `SIGNATURE_TYPE_STATIC` 35,428 |
| `FriendlyFiles` | 1,125,309 | `SIGNATURE_TYPE_FRIENDLYFILE_SHA256` 1,125,305, `SIGNATURE_TYPE_VERSIONCHECK` 4 |

`*` in the console output / "parsed" above marks types with a structural decoder in the
project; the `(YARA)` suffix means the decoder also feeds YARA rule generation. Everything
else is currently only parsed as an opaque `BaseSig` and is the low-hanging fruit for new
parsers. `SIGNATURE_TYPE_UNKNOWN` also appears (97 records) for byte values missing from
`sig_types.py`.
