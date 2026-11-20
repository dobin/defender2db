# KVIR32 page fingerprints and REGKEY registry conditions

Reverse-engineering notes for the last two large unimplemented types in the
shipped database:

| type | id | payload | what it is |
|------|----|--------:|------------|
| `SIGNATURE_TYPE_KVIR32` | `0x20` | 16 B + name | two-window CRC page fingerprint (legacy virus / packer / entry-point code) |
| `SIGNATURE_TYPE_REGKEY` | `0x63` | 4 B + 2 strings | registry key/value condition, not a file pattern |

Engine build: x64 `mpengine.dll` 1.1.26100.4 (base `0x180000000`).  The
function notes were added to `cache/functions_vdm.md` section 21.

Decoders: `defender2yara/defender/signature/kvir32.py` (`Kvir32Sig`) and
`defender2yara/defender/signature/regkey.py` (`RegKeySig`); wired into
`Vdm.decode_record`; tests in `tests/test_signature_kvir_regkey.py`.

Unlike HSTR/KPAT, neither type contains an inline pattern, so neither feeds
YARA generation.

---

## 1. `SIGNATURE_TYPE_KVIR32` (`0x20`)

### Layout

```
u32 anchor_crc        CRC-32 of 16 bytes at page offset 16 * anchor_window
u32 body_crc          CRC-32 of body_length bytes at body_offset
u16 body_offset       offset inside the scanned page (0..768 observed)
u16 body_length       body window length (16..16384 observed)
u16 anchor_window     anchor index: 0, 1 or 2 -> offset 0, 16 or 32
i16 flags             0 = report; negative (0x8000) = do not report
u8  name_length       optional; absent means anonymous
u8  name[name_length] definition label, not NUL terminated
```

All CRCs are Defender's CRC-32 (reflected, init `0xffffffff`, no final xor;
`FUN_180676c58`).  The optional name is not part of the engine record id: the
id is built from the first 16 bytes only.

### What the engine does

* `FUN_18057b57c` re-serialises an in-memory 16-byte entry into the on-disk
  payload (four dwords / two dword+two word pairs).
* `FUN_18057f55c` builds the packed id
  `crc32(16-byte payload) | 0x20 << 32 | 0x10 << 40`.
* `FUN_180118728` is the page scan driver (`kvscanpage4sig`).  For a mapped
  page it computes the CRC of a 16-byte window at **page + 16 * i** for
  `i = 0..3` (a fourth window when a full page is available; the shipped
  records only use 0..2), and looks the value up in the record table.
* `FUN_18011804c` is the lookup + verification routine: bloom-filter precheck,
  binary search on `anchor_crc`, then `anchor_window` must equal the window
  index that matched, then the body window is verified.
* `FUN_1804a4c5c` is the per-record verifier.  For the body it maps
  `[body_offset, body_offset + body_length)` (possibly across pages) and
  compares `FUN_180676c58(data, body_length)` with `body_crc`.
* If `flags < 0` the record is matched but not reported; those records only
  feed the emulator/repair logic.

So a record means: *"at some 16-byte-aligned page offset `anchor_window * 16`
the 16 bytes have CRC `anchor_crc`, and the bytes at `body_offset` with length
`body_length` have CRC `body_crc`."*  In 6,239 of 6,595 records the body starts
exactly at the anchor (`body_offset == 16 * anchor_window`), so the common form
is "16-byte anchor + body window".

This is a hash-based signature.  The engine never compares record bytes with
file bytes, and a page-relative 16-byte CRC cannot be expressed cheaply in
YARA, so no rule generator is wired up.

### What it is used for

The name is historical.  In the shipped database `KVIR32` is dominated by
packer / entry-point fingerprints and emulator conditions rather than classic
virus detections.  Named shared records are packer labels:

```
!UPX_1_X  !ASProtect  !ASProtect_1_23_RC4  !Themida  !FSG_1_3  !PECompact
!Armadillo  !MPRESS64  !PELock  !MoleBOX  !PESpin  !Upack_033  !PIB ...
```

Emulator records use labels such as
`!#attrmatch_codepatch_EIP_00000009_909090909090` and
`!#PEEMU:Disable_APILimit`, which identify code patches at a given entry-point
offset.  Real threat owners include `Trojan:Win32/Dorv.A` (548 records),
`Trojan:Win32/Tracur`, `VirTool:Win32/CeeInject*`, `Virus:Win32/Godog`,
`Virus:Win32/Xpaj.A`, `Worm:Win32/Sality.AU` and other file infectors.

### Coverage

| metric | value |
|--------|------:|
| records | 6,595 |
| real-threat records | 5,369 (2,704 threats, excluding the shared bucket) |
| `!InfrastructureShared` | 1,226 records, 680 distinct labels |
| `anchor_window` | 0: 6,377, 1: 195, 2: 23 |
| `flags` | 0: 6,497, 0x8000: 98 |
| `body_offset == 16 * window` | 6,239 (94.6%) |
| body length (top) | 64: 3,101, 36: 1,006, 1024: 449, 48: 290, 256: 186, 32: 108 |
| offset/length range | offset 0..768, length 16..16,384, offset+length <= 16,384 |
| parse result | 6,595 decoded, 0 errors, 0 warnings |

Examples:

```
Backdoor:Win32/Berbew.I
  anchor 0x18da24ae at 0, body 0x644352a5 [0, 0x24)

Worm:Win32/Apsiv.A
  anchor 0xca5d2c1b at 16 (window 1), body 0x55c445ae [0x20, 0x90)

Virus:Win32/Heretic.1986
  anchor 0x7beebdbd at 32 (window 2), body 0xafaa0d24 [0x20, 0x400)

Trojan:Win32/Inject.F
  flags 0x8000 -> matched but not reported

!UPX_1_X
  anchor 0x884c33a5 at 0, body 0x36762d75 [0, 0x24)
```

`Kvir32Sig` exposes `anchor_crc`, `body_crc`, `body_offset`, `body_length`,
`anchor_window`, `anchor_offset`, `flags`, `reports_detection`,
`anchor_matches_body_start`, `record_name` and `packed_record_id`.

---

## 2. `SIGNATURE_TYPE_REGKEY` (`0x63`)

### Layout

```
u16 hive / root id     1 = HKEY_CLASSES_ROOT
                       2 = HKEY_CURRENT_USER
                       3 = HKEY_LOCAL_MACHINE
                       4 = HKEY_USERS (accepted, not observed)
u16 key_length
u8  key[key_length]    case-insensitive registry path
u16 value_length
u8  value[value_length] expected value data (empty = key existence only)
```

The engine requires `hive` to be 1..4; any other value makes it ignore the
record.  The key is stored relative to the hive (`SOFTWARE\...`, not
`HKLM\SOFTWARE\...`).  If the key contains the literal sequence `\\`, the text
before it is the key path and the text after it is the **value name**.  An
empty value string means "the key must exist"; a non-empty value string is
compared with the registry value data.

### What the engine does

* `FUN_1809382c0` (resmgr module init) registers the type next to FILEPATH
  (`0x5f`), ASEP_FILEPATH (`0x71`), FOLDERNAME (`0x60`) and
  ASEP_FOLDERNAME (`0x75`).
* `FUN_1802b27c0` parses the record.  It validates the hive and the two string
  lengths, computes the record id `crc32(payload) | size << 40 | 0x63 << 32`,
  splits the key at the first `\\` with `FUN_18070d75c` (a `strstr` against
  `"\\\\"`), interns the value data and registers the condition with
  `FUN_180186b84`.
* `FUN_1802b34f4` compares the key against the eleven-entry prefix table at
  `0x180d82b50` and stores only the suffix.  The table (lower case) is:

  | idx | prefix |
  |----:|--------|
  | 0 | `software\microsoft\windows\currentversion\run` |
  | 1 | `software\microsoft\windows\currentversion\explorer` |
  | 2 | `software\microsoft\windows\currentversion` |
  | 3 | `software\microsoft\` |
  | 4 | `software\classes\clsid` |
  | 5 | `software\classes\interface` |
  | 6 | `software\classes\typelib` |
  | 7 | `software\classes\software\microsoft\windows\currentversion\explorer` |
  | 8 | `software\classes` |
  | 9 | `software` |
  | 10 | `system\currentcontrolset` |

* `FUN_1803c3420` orders entries by hive, prefix id, key path and value name,
  case-insensitively.  `FUN_18041fb20` is the comparator for the second table.
* Records with **no value name but non-empty value data** go to a separate
  "value only" table (`DAT_181105bf8`).  All other records go to the key table
  (`DAT_181105bb0`).
* Runtime lookups are `FUN_1802b2d84` (key table) and `FUN_1802b31a8` (value
  table).  The value data is enumerated with `FUN_1801f6f60` and compared by
  `FUN_18093a800`; key paths are matched component-wise with `/` normalised to
  `\` and are case-insensitive.

### Hive ids

The hive ids were inferred from the stored keys (the engine does not ship a
name table for them):

* **1 = HKEY_CLASSES_ROOT**: only extension keys (`.z`, `.7z`, `.rar`, `.iso`,
  ...) and ProgIDs (`IEWarning.WarningBHO`) are stored with id 1.
* **2 = HKEY_CURRENT_USER**: per-user keys such as
  `Software\VB and VBA Program Settings\...`, `Software\AMediaView`.
* **3 = HKEY_LOCAL_MACHINE**: `SYSTEM\CurrentControlSet\...`,
  `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon...`.
* **4 = HKEY_USERS**: accepted by the parser, no records in this database.

### Coverage

| metric | value |
|--------|------:|
| records | 3,911 |
| threats using | 542 |
| hive 1 / 2 / 3 / 0xffff | 74 / 1,310 / 2,526 / 1 |
| key contains `\\` (value name) | 476 (72 with an empty name) |
| expected value data | 269 |
| prefix matched / no prefix | 3,805 / 105 |
| parse result | 3,910 decoded, 1 partial (invalid hive `0xffff`) |

The prefix distribution is `software\classes` 1,592, `software` 991,
`...\currentversion` 630, `software\microsoft\` 392,
`system\currentcontrolset` 125, no prefix 105, `...\run` 24,
`...\explorer` 44, `...\clsid` 6, `...\typelib` 1, `...\interface` 1.

Top owners are adware/browser-modifier families: `Hotbar` (167),
`BrowserModifier:Win32/Zwangi` (162), `BrowserModifier:Win32/Cometsystems`
(104), `Rogue:Win32/SpyAxe` (86), `BrowserModifier:Win32/CommonName` (79).

Examples:

```
HKCU\Software\kuum                                   (key exists)
HKLM\SYSTEM\ControlSet002\Services\GbpSv\\Start
     = "explorer.exe C:\WINDOWS\svshost.exe"
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\\ProxyServer
     = "77.78.240.167:80"
HKCR\.z\\                                            = "WinZipper.z"
```

`RegKeySig` exposes `hive_id`, `hive`, `key_path`, `value_name`,
`value_data`, `key_existence_only`, `prefix_index`, `prefix`, `key_suffix`,
`full_key` and a one-line `summary`.

A registry condition has no file-byte representation, so it does not feed YARA
generation.  It is directly usable for host/registry hunting or for explaining
why a detection fires only on an infected machine.
