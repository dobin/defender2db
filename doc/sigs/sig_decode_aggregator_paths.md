# Decoding AAGGREGATOR, FILEPATH and FOLDERNAME

Follow-up to `doc/sig_type_usage.md` and the previous signature-decoding
write-ups (`doc/sigs/sig_decode_ck_nscript_normal.md` and earlier).

Build analysed: `mpengine.dll`, engine `1.1.26100.4`, signature `1.463.330.0`
(x64, image base `0x180000000`; Ghidra project binary `/mpengine.dll`).

| type | id | payload | records | what it is | decoder |
|------|----|---------|--------:|------------|---------|
| `SIGNATURE_TYPE_AAGGREGATOR` | `0x96` | variable, text | 9,757 | plaintext boolean expression over other signatures | `defender/signature/aggregator.py` (`AaAggregatorSig`) |
| `SIGNATURE_TYPE_FILEPATH` | `0x5f` | `u16` + text | 2,479 | file path/glob relative to a known folder | `defender/signature/pathname.py` (`FilePathSig`) |
| `SIGNATURE_TYPE_FOLDERNAME` | `0x60` | `u16` + text | 6,055 | directory path/glob relative to a known folder | `defender/signature/pathname.py` (`FolderNameSig`) |

All 18,291 records decode with zero errors and zero warnings.  None of the
three types is a byte/hash signature: `0x96` is rule composition, and
`0x5f`/`0x60` are path conditions.

---

## 1. `SIGNATURE_TYPE_AAGGREGATOR` (`0x96`)

### What it is

`AAGGREGATOR` is the **legacy, plaintext form of `AAGGREGATOREX`** (`0xe7`).
Both contain a boolean expression over other signature records; the only
difference is that `0xe7` obfuscates the **body** with the 256-byte
substitution table at `0x180d9e080`, while `0x96` stores it as plain ASCII.
The optional name is plain text in both forms (the engine interns it before
substituting the body).

The `aggregator` module (`FUN_18098f6a0`, module table index 24) registers
both handlers:

| address | type | role |
|--------:|-----:|------|
| `0x18041a5d0` | `0x96` | parser: header, name, plaintext body -> `FUN_1801858a8` |
| `0x180185410` | `0xe7` | parser: header, hashes normalised copy, deobfuscates body -> `FUN_1801858a8` |
| `0x1801858a8` | - | shared aggregator expression compiler |
| `0x180156440` | - | runtime expression evaluator |

`FUN_18041a5d0` is short and confirms the layout: it requires `size >= 4`,
rejects `flags & 0xfe`, reads `name_len` and `body_len`, bounds-checks them,
calls `FUN_1801836c8(0x96, payload, size, ...)` to build the packed record id
and 20-byte content hash, interns the name, and passes the untouched body to
`FUN_1801858a8` (no substitution).

### Layout

Identical to `AAGGREGATOREX`:

```
u8   flags            observed 0x00, 0x01
u8   name_len         0..n (0 in most records)
u16  body_len
u8   name[name_len]   plain text in both forms
u8   body[body_len]   plain text (0x96) or substituted (0xe7)
```

There is no NUL terminator and no trailing data: every one of the 9,757
records satisfies `len(payload) == 4 + name_len + body_len`.  The body is pure
ASCII; the longest is 587 bytes.

> **Correction:** the optional name is **not** obfuscated in either form.  The
> `0xe7` handler interns the name at `param_2 + 4` before it substitutes the
> body, so a decoder must only run the `0x180d9e080` table over the body.  The
> earlier `0xe7` decoder deobfuscated the name too, which is why named shared
> records previously looked like binary garbage.  This write-up and the decoder
> were updated together.

### Database coverage

| metric | value |
|--------|------:|
| records | 9,757 |
| in real threats | 6,646 (all anonymous) |
| in `!InfrastructureShared` | 3,111 (2,958 distinct names) |
| flags `0x00` / `0x01` | 9,661 / 96 |
| named records | 3,111 (all shared) |

The shared names are the same `!#` feed labels used by the other types:
`!#SCRIPT:FromWebClipWriteFilter.A` (12), `!#SLF:PowerShell/BypassAMSI.B` (9),
`!#SLF:AsmblyLoadInvoke!amsi` (9), `!#TEL:AGGR:HTML/TechBrolo.*`,
`!#Exception:...`, `!#Lowfi:AGGREGATOR:...`, and so on.  They describe the
group/list the aggregator belongs to, not a detection name.

Most-used top-level reference prefixes in the 9,757 expressions:
`PUA` (6,389), `SCPT` (5,222), `SCRIPT` (4,311), `Block` (2,762), `Lua`
(2,389), `HSTR` (1,396), `IRST`/`IRSH`, `RPF`, `AGGR`, `SLF`, `MHSTR`,
`SIGATTR`, `MSIL`, and so on.  The grammar and meaning are exactly the same as
`AAGGREGATOREX` (see `app/static/sigs/SIG_AAGGREGATOREX.md`): `&` and, `|` or,
`!` not, parentheses for grouping.

### Examples

```
VirTool:Win32/Injector
  SLFPER:Win32/InjectsRundll32&(Lua:IsEnterprise|IsSeville)

Trojan:VBS/Autorun
  (Trojan:VBS/Autorun!attr01|Trojan:VBS/Autorun!attr02)
  &Trojan:VBS/Autorun!attr03&...&Trojan:VBS/Autorun!attr06

Virus:Win32/MpTestAgg.A
  MPTEST-AGG-00&(MPTEST-AGG-01&MPTEST-AGG-02)
```

`Virus:Win32/MpTestAgg.*` are Microsoft's own test records (`MPTEST-AGG-*`),
handy for validating an aggregator implementation.

### Renderability

The expression is already human-readable.  No YARA output is produced: an
aggregator references other rules by name, it does not contain a pattern.
It remains one of the most useful types for analysis because it exposes *what
must co-occur* for a detection.

---

## 2. `SIGNATURE_TYPE_FILEPATH` (`0x5f`) and `SIGNATURE_TYPE_FOLDERNAME` (`0x60`)

### What they are

Both are **path conditions**.  A record stores a 16-bit *root id* plus the
path/glob relative to that root.  `FILEPATH` matches a file path,
`FOLDERNAME` matches a directory path; the payload format is otherwise
identical.

```
u16  root_id      Windows CSIDL value, or an engine pseudo-folder id
u8   pattern[]    path relative to the root, or an absolute path
                  (no NUL terminator; length = payload_size - 2)
```

The pattern starts with `\` when it is relative to the root (`\gedzac.reg`
under `%SystemRoot%\System32`).  When `root_id == 0xffff` the pattern is
already absolute (`c:\a.bat`).

Matching is case-insensitive and uses glob wildcards: `?` matches one
character, `*` matches any run of characters.  Examples from the database
include `\msg1*.dll`, `\SOEasy.?`, `\greenav20??.exe` and
`\administrator@wmvmedialease[?].txt`.

### The root id is a CSIDL

The normal root ids `0x00`..`0x3d` are the standard Windows `CSIDL_*`
constants, and the shipped suffixes confirm the values: `0x24` behaves like
`%windir%`, `0x25` like `%windir%\System32`, `0x26` like `%ProgramFiles%`,
`0x2a` like `%ProgramFiles(x86)%`, `0x2b` like `%ProgramFiles%\Common Files`,
`0x1a` like `%appdata%`, `0x1c` like `%localappdata%`, `0x23` like
`%ProgramData%`, `0x28` like `%userprofile%`, `0x2d` like Common Templates and
`0x2e` like Common Documents.  The `PATH_ROOTS` table in
`defender/signature/pathname.py` renders these as symbolic macros.

The engine also has a path-macro table at `0x180c72c60` (stride `0x50`), with
resolver functions `0x1802911a0` (environment expansion) and `0x18028f4d0`
(shell folder + environment expansion).  It holds the macro names but its
numeric ids are not a reliable direct index (it contains duplicate/shifted
entries, e.g. two `0x23` entries), so the normal root ids are decoded as
standard CSIDL based on the suffixes.  The high pseudo-id entries corroborate
the `0xfffa`..`0xffff` meanings above.

The table also contains the engine pseudo-folder entries above the CSIDL range
and the literal-form marker:

| id | name | expansion | records use it for |
|---:|------|-----------|--------------------|
| `0xfffa` | `USERNAME` | `%username%` | (not used in the shipped DB) |
| `0xfffb` | `SYSTEMDRIVE` | `%systemdrive%` | drive-root drops (`\file.exe`, `\GeneralAntivirus.exe`) |
| `0xfffc` | `COMMONFILES` | `%CommonProgramFiles%` | `\microsoft shared\...`, `\Doobzo`, `\SpeedBit` |
| `0xfffd` | `ALLUSERSPROFILE` | `%allusersprofile%` | `C:\ProgramData\...`-style folders (`\npp`, `\Microsoft AData`) |
| `0xfffe` | `TEMP` | `%temp%` | `\GC\Profiles`, `\cff3df.tmp`, `\r` |
| `0xffff` | `ABSOLUTE` | (none) | literal `c:\...`, `C:\Recycle.Bin`, `C:\Users\...` |

The resolvers are `0x1802911a0` (environment/`%` expansion) and `0x18028f4d0`
(shell known-folder + environment expansion); `0x18028daf0` resolves user
profile folders and truncates at `\ntuser.dat`.

### Evidence from the database

Observed `FILEPATH` roots (2,479 records):

| root | id | records | typical suffixes |
|------|----:|--------:|------------------|
| `SYSTEM` | `0x25` | 537 | `\gedzac.reg`, `\registrar.bat`, `\vipym.dll` |
| `DESKTOPDIRECTORY` | `0x10` | 481 | `\autorun.ini`, `\System Care Antivirus.lnk` |
| `WINDOWS` | `0x24` | 359 | `\loadnew.exe`, `\system\test.txt` |
| `APPDATA` | `0x1a` | 255 | `\regsvr.exe`, `\adobe\update\flacor.dat` |
| `PROGRAM_FILES` | `0x26` | 254 | `\internet explorer\cfg.bin`, `\xpcode\sexgamelist.pif` |
| `COMMON_DESKTOPDIRECTORY` | `0x19` | 146 | `\SpeedItup Free.lnk`, `\CC-Cleaner.lnk` |
| `PROGRAMS` | `0x02` | 77 | `\startup\amvbak.lnk` |
| `COMMON_PROGRAMS` | `0x17` | 66 | `\SpeedItup Free.lnk`, `\startup\gstartup.lnk` |
| `STARTMENU` | `0x0b` | 62 | `\HELP_DECRYPT.LNK` |
| `ABSOLUTE` | `0xffff` | 50 | `c:\a.bat`, `C:\Users\Public\...` |
| `LOCAL_APPDATA` | `0x1c` | 20 | `\Google\Chrome\User Data\...` |
| `COMMON_APPDATA` | `0x23` | 20 | `\startup\gstartup.lnk` |
| `STARTUP` | `0x07` | 31 | `\95mtspcuxt0.lnk`, `\msconfig.lnk` |
| `TEMP` | `0xfffe` | 28 | `\s.cmd`, `\up.bak`, `\dwm.exe` |
| `COMMONFILES` | `0xfffc` | 7 | `\microsoft shared\greenav20??.exe` |
| `ALLUSERSPROFILE` | `0xfffd` | 1 | `\drm\slog.sys` |

Observed `FOLDERNAME` roots (6,055 records):

| root | id | records | typical suffixes |
|------|----:|--------:|------------------|
| `PROGRAM_FILES` | `0x26` | 3,758 | `\common files\kuum`, `\Google\Chrome\...\Extensions\...`, ` (x86)\SOEasy.?` |
| `COMMON_APPDATA` | `0x23` | 507 | `\AntiSpyware Pro`, `\flash` |
| `APPDATA` | `0x1a` | 410 | `\MicroST`, `\S-1-5-31-...\dmc` |
| `LOCAL_APPDATA` | `0x1c` | 300 | `\Google\Chrome\User Data\Default\Extensions\...` |
| `PROGRAMS` | `0x02` | 294 | `\startups`, `\Uncheckit` |
| `PROFILE` | `0x28` | 250 | `\Wins7`, `\Local Settings\Temp\...` |
| `COMMON_PROGRAMS` | `0x17` | 202 | `\AntiSpyware Pro`, `\SpeedItup Free` |
| `COMMON_STARTMENU` | `0x16` | 73 | `\programs\matemedia\g-archiver` |
| `STARTMENU` | `0x0b` | 57 | `\programs\messengerskinner` |
| `WINDOWS` | `0x24` | 49 | `\kuum` |
| `SYSTEM` | `0x25` | 42 | `\config\iconos` |
| `ABSOLUTE` | `0xffff` | 42 | `C:\Recycle.Bin`, `C:\Users\Undp` |
| `TEMP` | `0xfffe` | 6 | `\GC\Profiles`, `\r` |
| `COMMONFILES` | `0xfffc` | 7 | `\Doobzo`, `\Spigot`, `\keenvalue` |
| `ALLUSERSPROFILE` | `0xfffd` | 23 | `\_qbothome`, `\npp`, `\AVG Secure Search` |

There are 84 wildcard `FILEPATH` records and 116 wildcard `FOLDERNAME`
records.  Many threats repeat the same suffix under several roots (for
example `\SpeedItup Free.lnk` under Desktop, Start Menu, Programs, Common
Programs and Common Desktop; 170 and 597 such multi-root groups respectively),
which is exactly how a dropper is written: put the shortcut everywhere it can
be launched from.

### Examples

```
TrojanDropper:Win32/Delf.CK
  FILEPATH %SystemRoot%\System32\gedzac.reg

Worm:Win32/Renocide.gen!B
  FILEPATH %temp%\s.cmd

Rogue:Win32/FakeXPA
  FILEPATH %CommonProgramFiles%\microsoft shared\greenav20??.exe

Ransom:Win32/Loktrom.B
  FILEPATH c:\WIND\...\... .exe         (absolute, non-ASCII name)

BrowserModifier:Win32/IPlugin
  FOLDERNAME %Favorites%\-games-
  FOLDERNAME %Favorites%\-music-

Trojan:Win32/Agent
  FOLDERNAME %windir%\kuum
  FOLDERNAME %ProgramFiles%\common files\kuum
```

### Renderability

The pattern can be rendered with a symbolic root and kept as a YARA
filename/path condition, but it is not a byte pattern in the scanned file.
There is no generator wired up.  The decoded fields are still useful:

* `root_name`, `root_macro` and `rendered` show the real target folder;
* `pattern` and `is_wildcard` expose the dropped filename/glob;
* `is_absolute` distinguishes literal paths from root-relative ones.

The path can contain non-ASCII text (e.g. the Loktrom ransomware path uses
Latin-1/UTF-8 look-alike bytes).  The decoder tries UTF-8 first and falls back
to Latin-1, matching the other text decoders in the project.

### Related types

`SIGNATURE_TYPE_FILENAME` (`0x5e`), `SIGNATURE_TYPE_ASEP_FILEPATH` (`0x71`)
and `SIGNATURE_TYPE_ASEP_FOLDERNAME` (`0x75`) are in the same family.  They
are not decoded here; the `0x5e` payload is a bare filename, while
`0x71`/`0x75` add the ASEP (auto-start extension point) context.

---

## 3. Discovery notes

* The `aggregator` module entry is index 24 in the module table
  (`0x180e54e10`): name `aggregator`, init `FUN_18098f6a0`.  The init registers
  `0x96` -> `FUN_18041a5d0` and `0xe7` -> `FUN_180185410`, both with context
  `thunk_FUN_18098e390`; `0xe7` is the only type that uses the substitution
  table `0x180d9e080`.
* `FUN_1801836c8(type, payload, size, out_id, out_hash)` builds the packed
  record id and content hash for `0x96`, exactly as it does for `0xe7`.
* The known-folder table at `0x180c72c60` is not a CSIDL parser by itself:
  the resolver functions (`0x1802911a0`, `0x18028f4d0`, `0x18028daf0`) expand
  the stored `%...%` macro names.  The record's `u16` selects the id, and the
  suffixes in the shipped records confirm the CSIDL mapping.
* `SIGNATURE_TYPE_AAGGREGATOR` and `SIGNATURE_TYPE_AAGGREGATOREX` share the
  same header and grammar; do not try to deobfuscate `0x96` with the `0xe7`
  table.
