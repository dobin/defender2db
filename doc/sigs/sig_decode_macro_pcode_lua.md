# Decoding MACRO_PCODE64 / MACRO_PCODE and LUASTANDALONE

Follow-up to `doc/sig_type_usage.md` and the earlier signature write-ups
(`doc/sigs/sig_decode_nscript_macro.md`, `doc/sigs/sig_decode_aggregator_paths.md`).

Build analysed: `mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`
(x64, image base `0x180000000`; Ghidra project binary `/mpengine.dll`).

| type | id | payload | records | what it is | decoder |
|------|----|---------|--------:|------------|---------|
| `SIGNATURE_TYPE_MACRO_PCODE` | `0x42` | 12 B + name | 2,434 | legacy macro p-code fingerprint (three 32-bit routine keys) | `defender/signature/macro_pcode.py` (`MacroPcodeSig`) |
| `SIGNATURE_TYPE_MACRO_PCODE64` | `0xcf` | 24 B + name | 5,978 | macro p-code fingerprint (three 64-bit routine keys) | same class |
| `SIGNATURE_TYPE_LUASTANDALONE` | `0xbd` | wrapper + Lua chunk | 66,760 | standalone MpLua script bound to an engine phase | `defender/signature/lua.py` (`LuaSig`) |

All 75,172 records decode with zero errors and zero warnings.  None of the
three is a byte pattern: `0x42`/`0xcf` are hashes of normalised VBA p-code, and
`0xbd` is a script that the engine interprets.

---

## 1. `MACRO_PCODE64` (`0xcf`) and `MACRO_PCODE` (`0x42`)

### What it is

These are the engine's **VBA macro p-code fingerprints**.  When mpengine walks
an Office document it decompresses every VBA module, parses the `dir` stream and
the compressed p-code of each module, and hashes the p-code token stream.  The
result is looked up in a sorted table of these records; a hit raises the
record's detection.  Nothing of the original macro *text* is stored in the
record, only three 64-bit routine keys.

The `macro` module (`FUN_180a50370`, module table entry `0x180e56960`) already
registers `0x43` (`MACRO_SOURCE`); the same module registers these two:

| address | type | role |
|--------:|-----:|------|
| `0x180432aa0` | `0x42` | parser: three `u32` keys, then optional name |
| `0x180432b10` | `0xcf` | parser: three `u64` keys, then optional name |
| `0x180432b78` | - | shared record builder: `{key0, key1, key2, cond_id, is_64bit}` (0x20-byte table entry) |
| `0x18057ee8c` | - | re-serialises a table entry to a `0x42`/`0xcf` TLV |
| `0x180584f50` | - | packed record id: `crc32(entry) | size << 40 | type << 32` |

`0x180432b10` refuses payloads shorter than `0x18`; `0x180432aa0` refuses
payloads shorter than `0xc`.  If there are extra bytes they must contain a NUL
terminator (the builder scans for it and returns `0xa004` otherwise).  The
`is_64bit` flag is written to in-memory offset `+0x1c` of the entry.

### Layout

`0x42`:

```
u32  key0            CRC-32 of a module hash
u32  key1            CRC-32 of the second module hash
u32  key2            third slot
u8   name[]          optional, NUL terminated, no length prefix
```

`0xcf`:

```
u64  key0            64-bit routine key
u64  key1
u64  key2
u8   name[]          optional, NUL terminated, no length prefix
```

The keys are stored **little endian**, so the CRC-32 is the first four bytes of
a 64-bit key.

### The 64-bit routine key

Every `0xcf` key is a *routine key* built by `FUN_18024d858`:

```
bits  0..31   CRC-32 of the hashed bytes (init 0xffffffff, no final xor)
bits 32..47   CRC-16 of the same bytes (reflected ARC, poly 0xa001, init 0)
bits 48..63   number of bytes hashed (incremented per byte)
```

`FUN_18024d858(state, data, length)` splits the state into those three fields,
calls `FUN_180675fec` (CRC-32, table `0x180c8b2a0`) and `FUN_180676148`
(CRC-16, table `0x180e38d20`) and adds `length` to the counter.  The CRC tables
in the binary are the standard reflected ones (`0x77073096…` and `0xc0c1…`), so
the fields are reproducible:

```python
crc32 = zlib.crc32(data) ^ 0xffffffff            # init 0xffffffff, no final xor
crc16 = crc16_arc(data, init=0)                   # poly 0xa001, reflected, init 0
key   = crc32 | crc16 << 32 | len(data) << 48
```

`defender/signature/macro_pcode.py` exposes this as `routine_key()`,
`defender_crc32()` and `defender_crc16()`.

A slot is "not used" when it is zero (64-bit form) or `0xffffffff` (32-bit
form, and the `0x00000000ffffffff` spelling that appears in some `0xcf`
records).  A key whose CRC-16 and length are zero is compared on the CRC-32
alone, which is exactly what the legacy `0x42` records are.

### Matching

The runtime side is the VBA project scanner:

| address | role |
|--------:|------|
| `0x1802f9718` | VBA project scan: decompress `VBA/dir`, iterate module streams, call `0x18024bd64`, then report the match |
| `0x1802f8288` | `VBA/dir` parser (validates the directory record tags) |
| `0x18024bd64` | one module: decompress, split p-code/source, run the three p-code dialects |
| `0x18024a444` | per module: loop over the three p-code versions and their tokens |
| `0x18024a84c` | p-code dialect 0: walk tokens, hash every opcode byte |
| `0x18024b1dc` | p-code dialect 1/2: same walk with the version-specific opcode table |
| `0x18024d118` | run the record table against the module's hash pairs |
| `0x18024d8a4` | table search + verifier for one hash pair |
| `0x18024dc64` | routine-key comparison (CRC-32, then length, then CRC-16) |
| `0x1801d3560` / `0x1801d3520` | table comparators (sort by key1, then key0) |
| `0x1803acc2c` | commit/sort of the record table, sets the "first key1 unset" index |

The scanner keeps an array of three "p-code slot" structures (one per supported
p-code dialect).  Each slot holds four 64-bit hash states plus counters and two
flag bytes:

```
+0x00 u64 hash0        rolling hash over every opcode byte
+0x08 u64 hash1        rolling hash over the "significant" opcode subset
+0x10 u64 hash2        XOR of per-statement hashes (all opcodes)
+0x18 u64 hash3        XOR of per-statement hashes (significant opcodes)
+0x20 u32 counter0     bytes hashed into hash0
+0x24 u32 counter1     bytes hashed into hash1
+0x28 u8  present
+0x29 u8  already matched
```

(`0x180c953c0` is the "counts as significant" byte table used for `hash1`/
`hash3`; `0x180f0a1d8`, `0x180f0b198` and `0x180f0c1d8` are the opcode
descriptor tables of the three dialects, indexed by `opcode & 0x3ff`.)

For each slot `0x18024d118` queries the record table with the pair
`{hash0, hash1}` and, for slots 0 and 2, again with `{hash2, hash3}`.
`0x18024d8a4` binary-searches the table (sorted by key1 then key0), walks the
group of entries with the same key1, and requires `key0` to match as well.
A record whose **key1 is unset** is found through the fallback index
(`DAT_1811069d0`, the first entry with key1 `0xffffffff`) and matches on key0
only.  On a hit `0x1802f9718` reports the entry's condition id with the packed
record id.

**The third key is not consulted by the matcher in this build.**  It is stored
and re-serialised (so the record round-trips) but neither the comparator
(`0x1801d3560`, key1 then key0) nor the verifier reads it.  The 32-bit form is
the same idea with CRC-32-only keys, which is why every MACRO_PCODE key has a
zero length/CRC-16 field.

The keys are therefore *not* file hashes and cannot be turned into YARA
strings; they are fingerprints of the engine's own p-code normalisation.

### Coverage in this DB

| metric | `0xcf` | `0x42` |
|--------|-------:|-------:|
| records | 5,978 | 2,434 |
| in real threats | 5,925 (all anonymous) | 2,432 (all anonymous) |
| in `!InfrastructureShared` | 53 (all named) | 2 (named) |
| distinct `(key0, key1)` pairs | 5,973 | - |
| key0 length range | 10 … 55,202 (2,173 distinct) | n/a |
| key1 length range | 0 … 17,767 (874 distinct) | n/a |
| unset slot pattern | `{2}` 5,225, `{}` 449, `{1,2}` 281, `{1}` 23 | `{}` 2,098, `{2}` 280, `{0,2}` 24, `{0}` 21, `{1}` 7, `{1,2}` 4 |

The only duplicate `(key0, key1)` pairs are byte-identical records shipped in
both the base and the delta VDM.

Third-slot values in `0xcf`: 5,401 zero, 105 `0x00000000ffffffff`, 471 with a
length field of 16 and one with 13 — i.e. it does not carry a module p-code
length in practice.

Names are engine feed labels, e.g.
`!#ALF:Trojan:Win32/NeoHash.macropcode`,
`!#TEL:TrojanDownloader:O97M/Emotet.ENC!MTB`, `#Virus:X97M/Laroux.ER`.

Example (`Virus:W97M/Marker.JZ`):

```
key0 = 0x040abe5934d1240b   crc32=34d1240b crc16=be59 len=1034
key1 = 0x026d08989525b2be   crc32=9525b2be crc16=0898 len=621
key2 = 0 (unset)
```

---

## 2. `LUASTANDALONE` (`0xbd`)

### What it is

`LUASTANDALONE` is a **standalone MpLua script**: a precompiled Lua 5.1 chunk
that the engine loads and runs at a specific definition/scan *phase*.  It is
not a pattern — it is executable detection logic that calls the `mp.*` API
(`mp.getfilesize`, `mp.readu_u32`, `mp.get_mpattribute`, `mp.CLEAN`,
`mp.INFECTED`, `peattributes`, …).

MpLua is Defender's Lua 5.1 interpreter (`"Lua 5.1"` at `0x180c72560`,
`AutoMPLuaState`); `0x180152790` is `mp.setattribute()`, `0x180c88288`/
`0x180c882b8` are the `MpLuaMaxAttributes*` limits.

Record creation (`FUN_180415898`) turns a "custom ASR"/definition blob into the
record: it requires `size >= 8`, takes the phase byte from `payload[1]`, checks
it against the 36-entry phase table at `0x180c6a650`, computes
`crc32(payload) | size << 40 | 0xbd << 32` as the record id and emits
`FUN_180217edc(out, 0xbd, payload, size)`.

### Layout

```
u8   name_length             including the trailing NUL
u8   phase                   index into the 36-entry table (0..0x23)
u16  attributes_length
u32  body_length
u8   name[name_length]
u8   attributes[attributes_length]   NUL-separated name / value pairs
u8   body[body_length]               Lua 5.1 chunk
```

Every record in the database satisfies `len(payload) == 8 + name + attributes +
body` exactly, with no padding.

### Phase table (`0x180c6a650`)

Entries are `{char *name, u64 flags}`.  `FUN_180494924(name, &id)` resolves a
phase name to this index, which is how the module initialisers ask for
`GenEarly`, `GenFirst`, `GenLast`, `GenFinalizer` and `GenConsolidator`.

| id | phase | records | id | phase | records |
|---:|-------|--------:|---:|-------|--------:|
| 0 | `Unknown` | 0 | 18 | `ProcessInspector` | 0 |
| 1 | `Infrastructure` | 74 | 19 | `UACTrigger` | 4 |
| 2-7 | `Deprecated` | 0 | 20 | `FFR` | 0 |
| 8 | `PEPREEMU` | 341 | 21 | `SignatureValidator` | 63,291 |
| 9 | `PEPOSTEMU` | 189 | 22 | `MacroSource` | 0 |
| 10 | `PELast` | 303 | 23 | `DynamicSignature` | 12 |
| 11 | `PEFinalizer` | 75 | 24 | `GenFinalizer` | 265 |
| 12 | `GenFirst` | 310 | 25 | `HipsRuleDefinition` | 25 |
| 13 | `GenLast` | 1,563 | 26 | `RtpSkipRule` | 5 |
| 14 | `PreRemediation` | 33 | 27 | `RtpSkipRuleEx` | 1 |
| 15 | `PostRemediation` | 120 | 28 | `OnDetection` | 12 |
| 16 | `IETrigger` | 9 | 29 | `GenConsolidator` | 2 |
| 17 | `DetectionSpecific` | 80 | 30 | `MachOGen` | 1 |
| | | | 31 | `MemScan` | 12 |
| | | | 32 | `GenEarly` | 7 |
| | | | 33 | `OnImageConfig` | 4 |
| | | | 34 | `MpDiag` | 0 |
| | | | 35 | `ELFGen` | 22 |

The phase names match the record content, which is a good sanity check:
`UACTrigger` holds `!#UACInstallerPersistence` scripts, `MachOGen` holds
`!#MacOS/...`, `ELFGen` holds `!#Lua:ARM_LE`/`Linux/...`, `HipsRuleDefinition`
holds ASR rule GUIDs, `RtpSkipRule` holds `*LogSkip` rules, `OnDetection` holds
`TerminateAmsiProcess`/`LuaReportAMSIOriginal` and `Infrastructure` holds
utility scripts (`SetAttributeFromClass`, `ConversionToBinary_f`, `CloudCallASEP`).

The phase's flag word is also read by `FUN_180415898` while it packages the
record, which is why the same table drives both the phase name and the record
layout:

| bit | meaning |
|----:|---------|
| `0x01` | selects between the plain record path and the tagged (`FUN_1801836c8` with a fixed 16-byte tag) path |
| `0x04` / `0x08` | the `TimeStamp` / `Flags` attributes are expected |
| `>> 4` | option nibble forwarded to the chunk loader (`FUN_1803e6e60`) |

Phase 21 (`SignatureValidator`, flags `0x0a`) is by far the most common one:
63,291 records, every one named with a 12-hex-digit id, and they are ordinary
detection scripts (`mp.CLEAN`/`mp.INFECTED`/`peattributes`).  They are the
engine's shared `SignatureValidator`-phase script cache, keyed by that hex id.

### Attributes

Attributes are repeated `name\0value\0` pairs (not `name=value`).  Observed
names: `Includes` (7,035), `ObMpAttributes` (2,121), `Flags` (1,188) and
`ObProcessAttributes` (3); 9,774 records carry attributes at all.  `Includes`
values are comma-separated library lists: `BMLuaLib`, `TechniqueTracker`,
`LuaFuncHelper`, `HstrLuaLib`, `BasScenarioSpecificInfra`, `ResearchData`,
`Bedep`, `LuaLib`.

`Ob`-prefixed attributes carry an **obfuscated value**: `FUN_180415898` decodes
the value with `FUN_1805afc44` and then substitutes every byte through the
256-byte table at `0x180dc18a0`, and the decoded names it looks for are
`Flags`, `TimeStamp`, `MpAttributes` and `ProcessAttributes`.  The decoder keeps
the value verbatim and flags it (`attributes[].obfuscated`), because the
substitution direction and the base encoding are not needed to interpret the
script.

### The Lua chunk

`FUN_1803e6f18` is the loader entry point: it accepts `len > 0xb`, treats a
first dword of `1` as the **headerless** variant and `0x61754c1b` (`\x1bLua`)
as the normal MpLua header, then skips 12 bytes and calls the undumper
`FUN_180a9a76c`.

Normal header (12 bytes):

```
1b 4c 75 61   "\x1bLua"
51            version 5.1
00            format
01            little endian
04 08 04 08   int, size_t, instruction, number sizes
01            "integral" numbers
```

The headerless variant replaces those 12 bytes with
`01 00 00 00 00 00 00 00 00 00 00 00`; everything after it is identical, so a
decoder can simply restore the normal header and undump the rest.  **The code
array of the shipped headerless records is nevertheless not plain Lua 5.1**:
every one of the 154 records has instruction words with opcodes in the unused
38..63 range (about a third of the words), and every function's last word is the
fixed `0x6305c366`, i.e. the encoded `RETURN`.  None of the 2.17M instructions
in normal-header records does this.  The wrapper, prototypes, constants and
debug section still decode, so `LuaSig` reports `code_encoding = "encoded"` and
the converter skips decompilation for these records instead of feeding the code
to a Lua 5.1 decompiler.

The undumper (`FUN_180a9a76c`) reads a classic Lua 5.1 `Function`:

```
u32  source length (0 = none) + bytes
u32  linedefined
u32  lastlinedefined
u8   nups, numparams, is_vararg, maxstacksize
u32  code count + code[count]          (u32 instructions)
u32  constant count
     u8 tag: 0 nil, 1 boolean, 3 number (8 bytes), 4 string (u32 len + bytes)
u32  proto count + nested Functions
u32  lineinfo count + ints             (skipped by the engine)
u32  local count  + {string, u32 startpc, u32 endpc}   (skipped)
u32  upvalue count + strings                            (skipped)
```

Two practical notes:

* the string lengths are 32-bit even though the header advertises 8-byte
  `size_t`;
* the `integral` byte is `1`, so the 8-byte number constants are **signed
  integers**, not IEEE doubles.  Reading them as doubles turns values such as
  `2700` into denormals (and produces `NaN` for some bit patterns).

The engine re-interns the code and constants (`FUN_180186df4`) and discards the
debug info, but the shipped chunks still contain it: sources are empty for
almost all records, and there are no local/upvalue names in this DB.

The instructions are ordinary Lua 5.1 bytecode (`op:6, A:8, C:9, B:9`); the
database-wide opcode histogram is dominated by `GETTABLE` (483k), `GETGLOBAL`
(453k), `JMP` (270k), `RETURN` (238k), `CALL` (174k) and `LOADK` (143k), i.e.
exactly what compiled Lua looks like.

### Coverage in this DB

| metric | value |
|--------|------:|
| records | 66,760 |
| standard header / headerless | 66,606 / 154 |
| in `!InfrastructureShared` | 66,308 (all named) |
| in real threats | 452 (all anonymous) |
| records with attributes | 9,774 |
| body size min / median / max | 87 / 228 / 717,578 |
| bodies > 4 KiB / > 16 KiB | 152 / 24 |
| function prototypes | 69,057 (max 257 in one script) |
| instructions | 2,241,907 (max 19,222 in one script) |
| string constants (sum of per-script unique) | 631,623 |

The 154 headerless records are the `AV_*`/`AVAS_*` scan-configuration scripts
(`AS_FullSystemScan`, `AV_QScan_User`, …) in `!InfrastructureShared`.

Top string constants across the corpus: `mp`, `INFECTED`, `CLEAN`,
`peattributes`, `isexe`, `ismsil`, `pairs`, `GetCertificateInfo`, `Signers`,
`get_mpattribute`, `no_security`, `isdll`, `getfilesize`, `lower`, `bm`,
`this_sigattrlog`, `set_mpattribute`, `utf8p2`, `MpCommon`, `getfilename`.

### Decoding / YARA

`LuaSig` parses the wrapper, splits the attributes into pairs and walks the
whole chunk (prototypes, instructions, constants, debug info).  The existing
pipeline additionally decompiles the chunk with the bundled Python Lua
decompiler (`defender2yara/defender/lua_backend.py`); `LuaSig` exposes
`lua_chunk_data` with the restored header, and normal-header records decompile
normally.  The 154 headerless records are reported as
`code_encoding = "encoded"` (see *The Lua chunk*) and are not sent to the
decompiler, because their instruction array is not Lua 5.1 — attempting it only
produced one decompiler and one disassembler warning per record.

A Lua record is detection *logic*, so it cannot become a byte-pattern YARA
rule.  The useful artefacts are the phase, the attribute list, the constants
(especially the `mp.*` API names and the script's own literals) and the
decompiled source.

---

## Decoders and tests

| type | class | file |
|------|-------|------|
| `MACRO_PCODE` / `MACRO_PCODE64` | `MacroPcodeSig` | `defender2yara/defender/signature/macro_pcode.py` |
| `LUASTANDALONE` | `LuaSig` | `defender2yara/defender/signature/lua.py` |

Both are wired into `Vdm.decode_record`; tests are in
`tests/test_signature_macro_pcode_lua.py` (vectors copied from the shipped
database) plus the existing `LuaSig` cases in `tests/test_signature_json.py`
and `tests/test_parser_regressions.py`.
