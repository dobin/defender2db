# LUASTANDALONE signatures: Defender's own Lua detection scripts

`SIGNATURE_TYPE_LUASTANDALONE` (`0xbd`) holds a **standalone MpLua script** — a
precompiled Lua 5.1 chunk that the engine runs at a specific phase. It is
detection *logic*, not a pattern: the script calls the `mp.*` API
(`mp.getfilesize`, `mp.readu_u32`, `mp.get_mpattribute`, `mp.CLEAN`,
`mp.INFECTED`, `peattributes`, …) and decides a verdict itself.

## Layout

```
name_len        u8
phase           u8    index into the engine's 36-entry phase table
attributes_len  u16
body_len        u32
name            attribute blob is NUL-separated name\0value\0 pairs
body            Lua 5.1 chunk
```

## Phase

The phase byte selects when the script runs and how the record was packaged.
Ids in use in this database, in table order:

| id | phase | id | phase |
|---:|-------|---:|-------|
| 0 | `Unknown` | 18 | `ProcessInspector` |
| 1 | `Infrastructure` | 19 | `UACTrigger` |
| 2-7 | `Deprecated` | 20 | `FFR` |
| 8 | `PEPREEMU` | 21 | `SignatureValidator` |
| 9 | `PEPOSTEMU` | 22 | `MacroSource` |
| 10 | `PELast` | 23 | `DynamicSignature` |
| 11 | `PEFinalizer` | 24 | `GenFinalizer` |
| 12 | `GenFirst` | 25 | `HipsRuleDefinition` |
| 13 | `GenLast` | 26 | `RtpSkipRule` |
| 14 | `PreRemediation` | 27 | `RtpSkipRuleEx` |
| 15 | `PostRemediation` | 28 | `OnDetection` |
| 16 | `IETrigger` | 29 | `GenConsolidator` |
| 17 | `DetectionSpecific` | 30 | `MachOGen` |
| | | 31 | `MemScan` |
| | | 32 | `GenEarly` |
| | | 33 | `OnImageConfig` |
| | | 34 | `MpDiag` |
| | | 35 | `ELFGen` |

The phase names line up with the scripts: `UACTrigger` holds
`!#UACInstallerPersistence`, `MachOGen` holds `!#MacOS/…`, `ELFGen` holds
`!#Lua:ARM_LE`, `HipsRuleDefinition` holds ASR rule GUIDs, and
`SignatureValidator` holds the 63,291 hex-id shared scripts.

## Attributes

| attribute | records | meaning |
|-----------|--------:|---------|
| `Includes` | 7,035 | comma-separated library list (`BMLuaLib`, `TechniqueTracker`, `LuaFuncHelper`, `HstrLuaLib`, …) |
| `ObMpAttributes` | 2,121 | obfuscated value (engine decodes it with a substitution table) |
| `Flags` | 1,188 | option flags, value `1` in this database |
| `ObProcessAttributes` | 3 | obfuscated process attribute list |

## The script body

The body is a normal Lua 5.1 chunk: a 12-byte header (`\x1bLuaQ…`) followed by a
function prototype with instructions, constants and nested functions. A second
variant replaces the header with `01 00 00 00 …` ("headerless"); the engine
accepts both, but the headerless records in this database encode the instruction
words (their opcodes are outside 0..37), so only their wrapper, function
structure and constants can be decoded.

Two quirks matter when reading chunks: string lengths are 32-bit, and the
header's `integral` byte is `1`, so number constants are signed integers, not
doubles.

## Coverage in this database

| metric | value |
|--------|------:|
| records | 66,760 (66,606 normal header, 154 headerless) |
| in `!InfrastructureShared` | 66,308 (all named) |
| in real threats | 452 (anonymous) |
| function prototypes / instructions | 69,057 / 2,241,907 |
| string constants | 631,623 |
| headerless records with encoded instructions | 154 |

The decoder is `defender2yara/defender/signature/lua.py` (`LuaSig`), which also
walks the chunk so the phase, attributes, function structure and string
constants are visible. The project additionally decompiles the chunk to Lua
source. The full engine analysis is in `doc/sigs/sig_decode_macro_pcode_lua.md`.
