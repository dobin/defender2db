# NDAT: typed named data

`SIGNATURE_TYPE_NDAT` (`0xa9`) is Defender's **named-data table**: a typed
string or data blob that other modules use as a condition.  It is not a file
fingerprint and usually not a byte pattern.

```
u32 data_length
u8  data[data_length]    regex / path / API name / domain / code bytes
u8  type                 NDAT class (1..23 observed)
u8  label[]              optional feed label, NUL terminated
```

The `type` byte chooses the consumer:

| type | class | example |
|-----:|-------|---------|
| 1 | project-path regex | `.+?AUTO_IP_NEW\\.*?RUS-(loader|klikker).+?\.vbp` |
| 3 | API call not counted | `MSVCRT.DLL!cos` |
| 4 | API -> behavior event | `KERNEL32.DLL!GetVersionExA` |
| 5 | log-skip rule (`RtpSkipRule`) | `*.VHDX.|*|Microsoft-Hyper-V` |
| 6 | VFS link | `MFC71.DLL>MFC42.DLL` |
| 7 | API attribute | `KERNEL32.DLL!ResumeThread:CallsResumeThread` |
| 8 | raw code pattern (`RKPAT`) | Alureon/Sirefef code bytes |
| 10 | PDB path regex | `\\ValhallaCrypter\\ValhallaStub` |
| 12 | needs DNS-cache info | `Behavior:Win32/Mamadut.*` |
| 13 | generic binary regexp (`NdatRegExpMatch`) | `!#Bootloader` |
| 15-20 | NRI strings | domain, HTTP header, certificate subject, response, cert bytes |
| 21 | audit rule | `AUDIT_M1:<guid>` |
| 22 | `RtpSkipRuleEx` | `*|%systemroot%\system32\smss.exe.<0x10000>` |
| 23 | transport regex | `transport.*http.*<uuid>.com/...` |

Labels in the shared bucket look like `!#NRI:...`, `!#SCPT:...`,
`#NoApiCallCounting` or `#VFSLINK`; real-threat records are anonymous.

## Coverage

| metric | value |
|--------|------:|
| records | 7,781 |
| labelled / anonymous | 3,360 / 4,421 |
| textual payloads | 7,663 |

The type is a condition string, so it does not become a YARA byte pattern.
Full reverse-engineering notes: `doc/sigs/sig_decode_ndat_brute_boot.md`.
