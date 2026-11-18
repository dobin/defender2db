# VERSIONCHECK signatures

`SIGNATURE_TYPE_VERSIONCHECK` (`0x7a`) is a **gate**, not a detection. The
engine evaluates it while loading a definition database and keeps the result in
a single "records enabled" flag. While that flag is false, every following
record in the same threat is skipped.

```
u32 check_id
u32 value
```

The predicate is `target <relation> value`; the record passes when the
predicate is true. A threat can contain several gates, so a later gate
re-enables or disables loading for everything after it. The loader has one
subtlety: while loading is off, only a record with check ID 0 is evaluated, and
that is what turns loading back on. A later conditional gate cannot re-enable
records by itself.

```
threat begin
  VERSIONCHECK  check_id=0x34 value=1      ; PUA protection must be on
  NID64         ...                         ; only loaded when PUA is on
  VERSIONCHECK  check_id=0      value=0     ; always true: re-enable loading
  ...                                       ; these records always load
threat end
```

## Common check IDs

| ID | Meaning |
|---:|---------|
| `0x00` | Always true. Does not test anything; used to re-enable record loading (a reset point). |
| `0x01`-`0x03` | Engine build compared with `26100` (the engine build this decoder was analysed against): newer / older / equal. |
| `0x04`, `0x1b`-`0x1e`, `0x2b`, `0x2e`, `0x2f`-`0x35`, `0x3a`, `0x40`, `0x43`, `0x44`, `0x47`, `0x4d`, `0x59`, `0x60`, `0x73`, `0x74`, `0x78`, `0x89`, `0x8a`, `0xbc`, `0xbd` | Engine feature flags (see below). |
| `0x05`, `0x22`, `0x2c`, `0x2d`, `0x36`-`0x39` | Definition-version timestamp comparisons. |
| `0x26`-`0x28`, `0xa3` | Windows build number (`<`, `>`, `==`, `!=`). |
| `0x3c`-`0x3f` | The four dwords of the 16-byte definition-set digest. Pins a block to one exact definition release. |
| `0x63`-`0x66` | The engine-version digest / engine version id. |
| `0x75`-`0x77` | Engine product/kind gate. `0x77` with value `1` is the modern unconditional form. |
| `0x4b` | Always false (kill switch). |

The full mapping is in `defender2yara/defender/signature/versioncheck.py`.

## Decoded engine feature flags

The engine environment block is `DAT_18111e110`; the flags are the bytes at
`+0xbNN`. The assignments are in `FUN_18058f8b4`. The meanings below were
confirmed from the policy/value each flag is read from and, where noted, from
the engine heartbeat (`FUN_1804fe53c`).

| Flag | Meaning | Source / evidence |
|-----:|---------|-------------------|
| `+0xb42` | Microsoft-internal build | `SQMClient\MSFTInternal` policy |
| `+0xb43` | Defender for Endpoint (codename "Seville") | `MpSevilleEnable` policy |
| `+0xb44` | Sense/EDR sensor installed | `SYSTEM\CurrentControlSet\Services\Sense` → `MsSense.exe` |
| `+0xb46` | MBA policy | `MpEnableMBA` policy |
| `+0xb47` | **PUA protection** | `MpEnablePUS` policy / engine `puamode` value 1 or 2 |
| `+0xb49` | Automatic sample submission | engine `autosampleoptinvalue`; heartbeat `"autosubmit"` |
| `+0xb4a` | PUA removal | `MpEnablePUSRemoval` policy |
| `+0xb50` | Test signing | code-integrity option bit |
| `+0xb51` | Windows Lockdown Mode | `WldpQueryWindowsLockdownMode` |
| `+0xb52` | Developer Mode | `AppModelUnlock\AllowDevelopmentWithoutDevLicense` |
| `+0xb54` | Inside a container | heartbeat `"isincontaineros"` |

Unknown flag numbers are reported as an internal engine feature flag instead of
being given a guessed meaning.

## Worked example: PUA:Win32/Puwaders.C!ml

This threat contains:

```
SIGNATURE_TYPE_VERSIONCHECK  local ID 3723431  check 0x34 value 1
SIGNATURE_TYPE_NID64         local ID 3723432
SIGNATURE_TYPE_VERSIONCHECK  local ID 3723433  check 0x00 value 0
```

Interpretation:

* `3723431` requires `+0xb47` (PUA protection) to be **enabled**. If PUA
  protection is off, the NID64 record below it is not loaded and this PUA
  detection cannot fire.
* `3723433` is not another detection. Check ID 0 returns true immediately; it
  only switches record loading back on after the conditional gate. That is why
  it says "always true": the *gate* always passes, not the threat.

This is why detections whose names start with `PUA:` are only seen on machines
where PUA protection is turned on.
