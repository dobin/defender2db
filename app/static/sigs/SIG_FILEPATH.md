# FILEPATH / FOLDERNAME — where Defender expects a file to live

## In one sentence

`FILEPATH` and `FOLDERNAME` are **path conditions**: they say "a file (or
folder) at this location, whose name looks like this, is malicious".  They
contain no file bytes and no hash.

```
STATIC        -> fingerprint of the file content
FILEPATH      -> exact location + filename/glob of the file
FOLDERNAME    -> exact location + name/glob of the directory
```

That is why the readable form looks like a path with a macro root:

```
FILEPATH   %temp%\s.cmd
FILEPATH   %CommonProgramFiles%\microsoft shared\greenav20??.exe
FOLDERNAME %ProgramFiles%\common files\kuum
FOLDERNAME %Favorites%\-games-
```

## How to read the decoded value

| field | meaning |
|-------|---------|
| `root_id` / `root_name` | the base folder: a Windows `CSIDL` (System32, Program Files, AppData, windir, Desktop, ...) or an engine pseudo-folder |
| `root_macro` | the symbolic expansion of that root: `%windir%`, `%ProgramFiles%`, `%appdata%`, ... |
| `pattern` | the stored relative path, or the full path when `is_absolute` is true |
| `is_wildcard` | the pattern uses `?` (one character) or `*` (any run) |
| `rendered` | the two combined, e.g. `%temp%\s.cmd` |

The special roots above the normal `CSIDL` range are:

| id | macro | real folder |
|---:|-------|-------------|
| `0xfffb` | `%systemdrive%` | drive root, e.g. `C:\` |
| `0xfffc` | `%CommonProgramFiles%` | `C:\Program Files\Common Files` |
| `0xfffd` | `%allusersprofile%` | `C:\ProgramData` (modern Windows) |
| `0xfffe` | `%temp%` | the user's temp directory |
| `0xffff` | (none) | the stored path is already absolute |

`?` and `*` are glob wildcards, and the comparison is case-insensitive.
A pattern like `\SOEasy.?` covers `SOEasy.1` through `SOEasy.9`; a literal
filename is just a glob with no wildcards.

## Worked example — fake antivirus

`Rogue:Win32/FakePAV` (122 path records) is a classic rogue AV installer. Its
`FILEPATH` records place shortcuts and executables in every launch location:

```
%Desktop%\System Care Antivirus.lnk
%StartMenu%\...\System Care Antivirus.lnk
%CommonPrograms%\...\System Care Antivirus.lnk
%ProgramFiles%\...\fakesecure.exe
%temp%\...\setup.exe
```

Reading it as an analyst or red teamer:

- the **roots** tell you what the installer writes and where it wants to be
  launched from (Desktop/Start Menu/Programs = persistence-by-shortcut);
- the **patterns** tell you the dropped name and its version globs;
- the **absolute** records (`c:\...`) show hard-coded paths the author uses
  when the user chooses a custom install location;
- `FOLDERNAME` records are often the parent directory the installer creates
  before dropping the files.

The same malware family usually repeats one suffix under several roots.  That
repetition is the persistence strategy: break one location and another still
launches.

## Practical notes

- These records fire on the **path**, not on the bytes.  Renaming or moving
  the dropped file to a different folder/name no longer matches that record.
  Other signature types (STATIC, PEHSTR, sig trees, aggregators) may still
  detect the file, so the path change is only one layer.
- `FOLDERNAME` matches the directory itself; a file inside it is not
  automatically matched by that record.  Check for a paired `FILEPATH` record.
- Paths can contain non-ASCII characters; do not assume pure ASCII when
  comparing or searching.
- The same id/layout is used by the `SIGNATURE_TYPE_ASEP_FILEPATH` (`0x71`)
  and `SIGNATURE_TYPE_ASEP_FOLDERNAME` (`0x75`) variants, which add auto-start
  extension point context.

## TL;DR for the report reader

> `SIGNATURE_TYPE_FILEPATH` / `SIGNATURE_TYPE_FOLDERNAME` = "malware is
> expected at this location with this name/glob".  The decoded value combines
> a known-folder root (`%temp%`, `%ProgramFiles%`, `%SystemRoot%\System32`,
> ...) with the relative path.  `?` and `*` are wildcards, matching is
> case-insensitive, and `is_absolute` records carry the full path.  They are
> location indicators, not content fingerprints.
