# REGKEY: registry key and value conditions

`SIGNATURE_TYPE_REGKEY` (`0x63`) is a **registry condition**, not a file
signature.  It names a registry key, optionally one value below it, and
optionally the value data that must be present.

## Layout

```
u16 hive           1 HKCR, 2 HKCU, 3 HKLM, 4 HKU (accepted, unused)
u16 key_length
u8  key[key_length]
u16 value_length
u8  value[value_length]
```

The key is stored relative to the hive, e.g. `SOFTWARE\Microsoft\...` rather
than `HKLM\SOFTWARE\Microsoft\...`.  A literal `\\` inside the key separates
the key path from the **value name**.  An empty value means "the key exists";
a non-empty value is compared with the registry value data.

The engine strips one of eleven well-known path prefixes before storing the
key (`software\microsoft\windows\currentversion\run`,
`software\classes\...`, `system\currentcontrolset`, ...).  Matching is
case-insensitive and `/` is treated as `\`.

## Examples

```
HKCU\Software\kuum                                     (key exists)
HKLM\SYSTEM\ControlSet002\Services\GbpSv\\Start
     = "explorer.exe C:\WINDOWS\svshost.exe"
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\\ProxyServer
     = "77.78.240.167:80"
HKCR\.z\\                                              = "WinZipper.z"
```

## Hive ids

The ids are inferred from the stored keys:

| id | hive | typical content |
|---:|------|-----------------|
| 1 | HKEY_CLASSES_ROOT | file extensions, ProgIDs |
| 2 | HKEY_CURRENT_USER | per-user software keys |
| 3 | HKEY_LOCAL_MACHINE | services, Winlogon, machine-wide settings |
| 4 | HKEY_USERS | accepted by the parser, unused |

Records with a hive id outside 1..4 are ignored by the engine (the database
has one such `0xffff` record).

## Coverage

| metric | value |
|--------|------:|
| records | 3,911 |
| threats using | 542 |
| HKLM / HKCU / HKCR | 2,526 / 1,310 / 74 |
| value name pinned | 476 |
| expected value data | 269 |

Top owners are adware and browser-modifier families (`Hotbar`, `Zwangi`,
`Cometsystems`, `SpyAxe`, ...).  A registry condition has no file-byte form,
so it does not feed YARA output.  Full notes:
`doc/sigs/sig_decode_kvir32_regkey.md`.
