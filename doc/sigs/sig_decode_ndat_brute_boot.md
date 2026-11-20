# NDAT typed strings, generic BRUTE patterns and BOOT images

Reverse-engineering notes for the three remaining "raw only" types that carry
matchable content in the shipped database:

| type | id | payload | what it is |
|------|----|--------:|------------|
| `SIGNATURE_TYPE_NDAT` | `0xa9` | `u32 len + data + u8 type` + NUL label | typed string / data condition (regex, path, API name, domain, cert subject, code bytes) |
| `SIGNATURE_TYPE_BRUTE` | `0xd0` | same as `NSCRIPT_BRUTE` | script-type-agnostic brute text pattern (the generic `BRUTE` table) |
| `SIGNATURE_TYPE_BOOT` | `0x44` | name + 32-byte blob | boot-sector / MBR / VBR byte pattern, or 8-byte anchor + covered-length + CRC-32 |

Engine build: x64 `mpengine.dll` 1.1.26100.4 (base `0x180000000`).  Function
notes were added to `cache/functions_vdm.md` section 22.

Decoders:

* `defender2yara/defender/signature/ndat.py` (`NdatSig`)
* `defender2yara/defender/signature/brute.py` (`BruteSig`, subclass of
  `NscriptBruteSig`)
* `defender2yara/defender/signature/boot.py` (`BootSig`)

Wired into `Vdm.decode_record`; tests in
`tests/test_signature_ndat_boot_brute.py`.  All 7,781 NDAT, 5,703 BRUTE and
1,217 BOOT records in `cache/threats.db` decode with zero errors and zero
warnings.

`BRUTE` and `BOOT` contain inline byte/string patterns and are therefore
expressible in YARA (wildcards as `??`, skips as `[n]`).  `NDAT` is a condition
string, not a file pattern.  No rule generator is wired up for any of the
three.

---

## 1. `SIGNATURE_TYPE_NDAT` (`0xa9`)

NDAT is Defender's **named-data table**: a typed blob that other modules use as
a condition.  It is not a fingerprint and usually not a byte pattern.

### Layout

```
u32 data_length          length of the data blob (includes the NUL for strings)
u8  data[data_length]    regex / path / API name / domain / code bytes ...
u8  type                 NDAT class (1..23 observed)
u8  label[]              optional: one-byte marker (!/#) + NUL-terminated label
```

The record is parsed by the generic template interpreter
(`FUN_180181cc4`) with the template at `0x180f073e0`:

```
(0x1000, 0x00)  read u32            -> entry+0x00
(0x100f, 0x08)  data pointer/size   -> entry+0x08
(0x1002, 0x10)  read u8 (type)      -> entry+0x10
(0x1017, 0x04)  condition + name,   -> entry+0x04
```

The 0x18-byte table entry is `{u32 data_len, u32 condition_id, ptr data,
u8 type}`.  The table (`DAT_181115c50`) is registered by the `cksig` module
init `FUN_180a1d2b0` as type `0x4a9` (`0x400 | 0xa9`, the `0x400` flag selects
the template/condition path).  Its commit callback `FUN_180280ab0` sorts the
table and dispatches on the type byte through the global per-type callback
table `DAT_181115430`.

The template's last opcode (`0x1017`) is the **NUL-terminated** name variant
(the length-prefixed variant is `0x1016`, used by KPAT/KPATEX).  It consumes a
one-byte marker and then a NUL-terminated label; every labelled NDAT record in
the database uses `!` or `#` as the marker (e.g. `!#NRI:...`, `#VFSLINK`).
`NdatSig` exposes both the raw label (with the marker) and the marker itself.

### Type enum

The first 14 names come from the `NDAT_*` string block at `0x180c77f98`; the
enum is **one-based**:

| type | name | what the shipped strings contain |
|-----:|------|----------------------------------|
| 1 | `NDAT_PROJECTPATH_REGEX` | VBA/VB6 `.vbp` project-path regex (real-threat heuristics) |
| 2 | `NDAT_PROJECTNAME_REGEX` | project-name regex (no shipped records) |
| 3 | `NDAT_DONTCOUNT_API` | `DLL!Api` names excluded from API-call counting (`#NoApiCallCounting`) |
| 4 | `NDAT_FIRE_EVENT` | `DLL!Api` + behavior event id (`#12387`, `#12425,%d1`, ...) |
| 5 | `NDAT_LOGSKIP_ENTRY` | `RtpSkipRule` path/extension skip rules (`*.VHD.|*|Microsoft-Hyper-V`) |
| 6 | `NDAT_VFS_LINK` | virtual-file-system link `old>new` (`#VFSLINK`) |
| 7 | `NDAT_API_ATTRIBUTE` | `DLL!Api:Attribute` mapping (`#AutoApiAttribute`) |
| 8 | `NDAT_RKPAT` | raw code byte pattern (Alureon/Sirefef) |
| 9 | `NDAT_EBHASHDATA` | hash data (no shipped records) |
| 10 | `NDAT_PDBPATH_REGEX` | PDB path regex (crypter/stub heuristics) |
| 11 | `NDAT_PDBNAME_REGEX` | PDB name regex (no shipped records) |
| 12 | `NDAT_INCLUDE_DNS_CACHE_INFO` | behavior/threat names that need DNS cache data (`#NeedDnsInfo`) |
| 13 | `NDAT_REGEXP_GENERIC` | binary regexp, the form used by `NdatRegExpMatch` |
| 14 | `NDAT_DBTAG` | database tag (no shipped records) |
| 15 | NRI domain regex | `slootni.com`, `ableawid.com`, ... (`!#NRI:DoplikInstallationServer`) |
| 16 | NRI HTTP-header regex | `Expires: ...`, `User-Agent: ...` |
| 17 | NRI generic regexp | one record |
| 18 | NRI certificate-subject regex | `^Subject: CN=aaatus\.com` (`!#NRI:CERT_UNC1878`) |
| 19 | NRI response/body regex | `^OK$`, `PAYLOAD_UUID`, JNDI/`\x..` patterns |
| 20 | NRI certificate/ECC byte pattern | `\x04...` ECC parameters, `Cert!AT1` ... |
| 21 | NRI audit rule | `AUDIT_M1:<guid>`, `WARN_M1:<guid>` |
| 22 | `RtpSkipRuleEx` | process/parent skip rules (`#na`) |
| 23 | NRI transport regex | `transport.*http.*<uuid>.com/...` (`Trojan:AIMCP/*`) |

Types above 14 are not in the mpengine name block; their labels are inferred
from the shipped data.  Engine registrations known in this build are type 5
(`RtpSkipRule`, `FUN_18046ae60`) and type 22 (`RtpSkipRuleEx`,
`FUN_180996df0`); `NdatRegExpMatch` accepts only type 13.

### Consumers

* `FUN_180997050(ctx, type, fn)` registers a per-type handler in
  `DAT_181115430`; `FUN_180280ab0` invokes it for every record of that type
  during commit.
* `FUN_18024ff68(entry, candidate)` compares a record's data string with a
  candidate string (`FUN_1800d0abc`).  The NRI rules and the
  `MpHasValidProjPath` VBA heuristic (`FUN_18039aa2c`) use it.
* `FUN_180b1e590` implements the `NdatRegExpMatch <type=13> <regex>` definition
  command: it walks `DAT_181123f88` (a NUL-terminated string vector built by
  `FUN_1804bc780`/`FUN_1804bc80c`) and returns the matching threat record id.
* `FUN_18039aa2c`/`FUN_18039b4f0` are the "data-driven extension class"
  lookups used by the VBA/project-path heuristics.

### Coverage in `cache/threats.db`

| metric | value |
|--------|------:|
| records | 7,781 |
| labelled / anonymous | 3,360 / 4,421 |
| textual payloads | 7,663 (99.8% end in NUL) |
| data length | 1 .. 3,345 (median 39) |

Per type (records): `PROJECTPATH` 368, `DONTCOUNT_API` 969, `FIRE_EVENT` 45,
`LOGSKIP_ENTRY` 3,584, `VFS_LINK` 1,215, `API_ATTRIBUTE` 6, `RKPAT` 33,
`PDBPATH` 753, `INCLUDE_DNS_CACHE_INFO` 3, `REGEXP_GENERIC` 82, NRI domain
264, HTTP header 2, generic 1, cert subject 278, response 27, cert bytes 117,
audit 2, `RtpSkipRuleEx` 30, transport 2.

Examples:

```
NDAT_PROJECTPATH_REGEX   .+?AUTO_IP_NEW\\.*?RUS-(loader|klikker).+?\.vbp
NDAT_DONTCOUNT_API       MSVCRT.DLL!cos          label #NoApiCallCounting
NDAT_FIRE_EVENT          KERNEL32.DLL!GetVersionExA   label #12385
NDAT_LOGSKIP_ENTRY       *.VHDX.|*|Microsoft-Hyper-V
NDAT_VFS_LINK            C:\WINDOWS\SYSTEM32\MFC71.DLL>C:\WINDOWS\SYSTEM32\MFC42.DLL
NDAT_API_ATTRIBUTE       KERNEL32.DLL!ResumeThread:CallsResumeThread
NDAT_RKPAT               \x01\x55\x8b\xec...        (binary, Alureon)
NDAT_PDBPATH_REGEX       \\(Desktop|Sepa|Surse)\\(NEW )?N0\$crypter...
NDAT_REGEXP_GENERIC      \x04\x4a\x34\xc6... label !#Bootloader
NRI domain               slootni.com
NRI cert subject         ^Subject: CN=aaatus\.com
NRI audit rule           AUDIT_M1:9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
RtpSkipRuleEx            *|%systemroot%\system32\smss.exe.<0x10000>
```

---

## 2. `SIGNATURE_TYPE_BRUTE` (`0xd0`)

`BRUTE` is a **script-text brute pattern**, the same wildcard language as
`NSCRIPT_BRUTE` (`0x29`), but stored in a separate, script-type-agnostic table.
There is no overlap with `0x29`: the two record sets are disjoint.

### Layout

Identical to `NSCRIPT_BRUTE` (see `doc/sigs/sig_decode_nscript_macro.md`):

```
u8  name_length       0..0x3f (0 = anonymous)
u8  name[name_length] feed label (no NUL), e.g. !#BRUTE:... / !#SCPT:...
u8  kind_and_flag     low 7 bits script kind, bit 7 = extra flag
u8  mode              0 anywhere, 1 forward, 2 backward
u32 any_length        low 16 bits; 0xffffffff = unset
u32 pattern_length
u8  pattern[pattern_length]  normalised script text + 90xx wildcards,
                             always ends 90 00
```

The only structural difference from `NSCRIPT_BRUTE` in the shipped data is the
script kind: **all 5,703 records use kind 0 ("any")**.  52 records set the
kind byte's high bit (`kind_and_flag == 0x80`), which becomes internal flag
`0x0400`.

### Engine registration and matching

`0xd0` is registered by the **kcrce module**, not by `nscript`:

| address | role |
|--------:|------|
| `0x180927150` | kcrce module init (calls `FUN_180927754`) |
| `0x180927754` | additional kcrce setup: allocates the table `DAT_1811152c0` (0x18-byte entries, tag `brut` = `0x62727574`) and registers `0xd0` -> `FUN_1801828c0` with commit `FUN_180517e50` |
| `0x1801828c0` | parser: name, kind, mode, any_length, pattern; builds the packed record id `crc32 | 0xd0 << 32 | size << 40` and validates the wildcard tail against `0x180c94d50` |
| `0x180517e50` | commit callback: strips `0x90` wildcard tokens to build an Aho-Corasick matcher `DAT_1811152c8`, stores the literal anchor offset/length in the entry |
| `0x180517568` | matcher driver over `DAT_1811152c0` / `DAT_1811152c8` |
| `0x18015dde0` | hit reporting (condition id -> detection/feature) |

The in-memory entry mirrors `NSCRIPT_BRUTE`:

```
+0x00 ptr  pattern
+0x08 u32  condition id
+0x0c u16  anchor offset (set by the commit callback)
+0x0e u16  anchor length
+0x10 u16  any_length
+0x12 u16  pattern_length
+0x14 u8   mode
+0x15 u8   kind (high bit stripped)
+0x16 u8   variant (5 = loose, 7 = no 90 1b token)
+0x17 u8   high-bit flag
```

The patterns are the source of the `BRUTE:JS:Feature:` / `BRUTE:VBS:Feature:` /
`BRUTE:PDF:Feature:` feature names and of the `mp.GetBruteMatchData()` /
`mp.ReadBruteMatchBuffer()` Lua API.  They match raw script text, so they can
feed YARA generation exactly like `NSCRIPT_BRUTE`.

### Coverage in `cache/threats.db`

| metric | value |
|--------|------:|
| records | 5,703 |
| labelled / anonymous | 3,978 / 1,725 |
| script kind | 5,703 "any" |
| mode | anywhere 4,405, forward 1,041, backward 257 |
| `any_length` unset | 5,649 (54 set, values 0..300) |
| pattern length | 6 .. 1,539 (median 25) |
| patterns with wildcard tokens | 2,404 |

Examples:

```
!#SCPT:AICustomDiscovery.ClaudeAgentSDKPy
  any anywhere len=20  'ClaudeAgentOptions'
!#BRUTE:SoftEtherUnderXOR.A
  any ...              (278 records: XOR/obfuscation patterns)
Backdoor:Win32/Plugx.I
  any forward len=34   \x34\x1d\x1c...<wildcards>
```

---

## 3. `SIGNATURE_TYPE_BOOT` (`0x44`)

`BOOT` is the **boot image signature**: a byte pattern or a checksummed region
used by the MBR / VBR / boot-sector scanner.

### Layout

```
u8  name_length          0..0x3f (0 = anonymous)
u8  name[name_length]    feed label (no NUL), e.g. !#BOOT:... / !#TEL:...
u8  blob[32]
```

The 32-byte blob has two forms, selected by its first byte.

**Normal pattern** (`blob[0]` = pattern length, 4..31):

```
u8  pattern_length
u8  pattern[31]          first pattern_length bytes significant, rest zero
```

The first four pattern bytes are compared as a dword; the following
`pattern_length - 4` bytes are compared byte-wise with `0x90` as a
single-byte wildcard.  A `0x90` inside the first four bytes is therefore a
literal `0x90`.

**CRC form** (`blob[0] == 0x20`):

```
u8  0x20
u8  0x00
u8  anchor[8]            literal first eight bytes at the match position
u16 covered_length       length of the covered region
u32 crc32                Defender CRC-32 of [match, match + covered_length)
u8  padding[15]
```

The matcher first matches the 8-byte anchor, then requires
`match + covered_length < buffer_size`, then compares `crc32` with
`FUN_180676c58(buffer + match, covered_length)` (init `0xffffffff`, no final
xor).  238 records (19.6%) use this form.

### Engine registration and matching

The type is registered by the `BootImgs` module init `FUN_180ac2ca0`:

| address | role |
|--------:|------|
| `0x180ac2ca0` | `BootImgs` init: allocates the byte index `DAT_181115d18` (0x800 bytes), registers table `DAT_181115d10` (0x24-byte entries, capacity 4) with template `0x180f39560`, type `0x544` (`0x400 | 0x100 | 0x44`), matcher tag `boot` |
| `0x180f39560` | template: `(0x1016, 0x00)` condition + optional `u8 name_len + name`; `(0x2020, 0x04)` copy 32 bytes |
| `0x18015da40` | matcher `(buffer, size, ctx, out)`; uses the byte index to limit candidates, then the normal or CRC form; returns the match offset and length |
| `0x1800f95a0` | MBR/VBR scan: checks the boot record header (`00 01 00 00`, size >= 0x800), walks `0x800`-aligned sectors up to `0x40000`, calls the matcher on the first `0xc0` bytes |
| `0x1800fb080` | boot memory stealth (`MpDTBoot_MemoryStealth`), calls the matcher on the read sector |
| `0x180363558` | boot verification: reports the offset as `MpInternal_bootsigoffset=%lld` / the `bootsigoffset` report field |
| `0x18015dde0` | hit reporting (condition id -> detection) |

In-memory entry (0x24 bytes):

```
+0x00 u32  condition id
+0x04 u8   blob[32]       (the on-disk blob, unchanged)
```

For the normal form the matcher reads `blob[0]` (length), `blob[1..4]`
(dword prefix), `blob[5..]` (tail); for the CRC form it reads
`blob[2..10]` (anchor), `blob[10..12]` (covered length) and `blob[12..16]`
(CRC-32).

### Coverage in `cache/threats.db`

| metric | value |
|--------|------:|
| records | 1,217 |
| normal / CRC form | 979 / 238 |
| labelled / anonymous | 14 / 1,203 |
| normal pattern length | 4 .. 31 (most common 31: 268, 30: 112) |
| normal patterns with wildcards | 112 |
| CRC covered length | 14 .. 300 (median 56) |

Examples:

```
Virus:DOS/Half
  len=30  80 2e 13 04 03 b9 06 00 d3 e0 2d 00 10 8e c0 33 c0 ...
Virus:DOS/MpTestBoot
  len=31  cd 90 cd 33 cd 14 cd 13 c7 16 7a 13 05 40 ...
Virus:DOS/3nop   (CRC form)
  anchor=909090fa33c08ed8 length=42 crc32=63fd44a8
!#TEL:Ransom:DOS/Petya.A
  len=31  e8 14 00 66 48 66 83 f8 00 75 f5 66 a1 00 80 ea ...
```

Real-threat BOOT records are anonymous; the 14 labelled records are shared
`!#BOOT:`/`!#TEL:`/`!#TELPER:` definitions (Petya, WhisperGate, BootMgrVbr,
DiskCryptor, ...).

---

## 4. YARA expressibility

| type | YARA |
|------|------|
| `BOOT` normal | straightforward hex: `4-byte-prefix` + `??` per `0x90` in the tail |
| `BOOT` CRC | the 8-byte anchor can be a string, but the CRC is over a region that starts at the match; a `hash.crc32(offset, length)` condition only works once the match offset is known, so it is not a plain string rule |
| `BRUTE` | same wildcard language as `NSCRIPT_BRUTE`; `decode_script_pattern()` renders the readable text and the `0x90` tokens |
| `NDAT` | not a file pattern (condition string) |
