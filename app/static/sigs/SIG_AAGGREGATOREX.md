# AAGGREGATOREX — how Defender combines detections

## In one sentence

An `AAGGREGATOREX` is **not a file hash and not a byte pattern**: it is a small
boolean formula that says "this detection fires only when these *other*
Defender signatures all agree".

If a `STATIC` signature is "a fingerprint of the file bytes", an aggregator is
"a fingerprint of the *verdicts*".

```
STATIC              -> looks at the file itself (hash / CRC of parts of it)
AAGGREGATOREX       -> looks at other signatures and combines them
```

That is why the value you see in a threat record is readable text like:

```
SCPT:PSDllImportKernel32 & SCPT:PSImportVirtualAlloc & SCPT:PSImportCreateThread
& SCPT:PSCallWindowsAPI & SCPT:PSCopyShellCodeToMem & SCPT:PSStagerPayloadHead
& SCPT:PSStagerPayloadTail & PowerShell:Start-Sleep
```

Every `&`-separated piece is the **name of a separate detection rule**.
Defender only raises this threat if **all** of them matched. The console just
shows you the formula; the real work is done by the referenced rules.

---

## How to read the expression

| token | meaning |
|-------|---------|
| `A & B` | both must match |
| `A \| B` | either one may match |
| `!A` | must **not** match (typically an exclusion / false-positive guard) |
| `(...)` | grouping, same as normal boolean logic |

Atoms look like `KIND:Threat:Platform/Family` or `KIND:Name`. The `KIND` prefix
tells you what sort of rule is being referenced:

| prefix | what the referenced rule checks |
|--------|----------------------------------|
| `HSTR`, `MHSTR` | strings/byte sequences (PE, macro, script text, ...) |
| `SCPT`, `SCRIPT`, `SCRPT` | script-engine behaviours and script content (PowerShell, VBS, JS) |
| `SIGATTR` | Defender's attribute records (classification / metadata) |
| `Lua` | Lua predicates, e.g. "object has 39 methods" |
| `PEPCODE`, `FOP` | PE code / file-offset patterns |
| `KCRC`, `SNID` | other internal signature records |
| `RPF` | resource / file pattern |
| `AGG`, `AGGR` | another aggregator, i.e. a reusable compound rule |

Names are internal, but surprisingly descriptive: `PSImportVirtualAlloc`,
`VBSScriptingFSO`, `AppDataTemp`, `Base64Drop`. They leak *what behaviour*
Defender needs to see.

> Note: `!` at the **start** of a term is negation. A `!` **inside** a name
> (e.g. `SCPT:AppDataTemp!Base64Drop`) is part of the referenced definition
> name — Defender uses `A!B` for sub-rules. Split terms at `&`, `|`, spaces and
> parentheses, not at every `!`.

---

## Worked example 1 — PowerShell Metasploit stager

`Backdoor:PowerShell/MetasploitWinRMScriptExecPayload`

```
SCPT:PSDllImportKernel32 & SCPT:PSImportVirtualAlloc & SCPT:PSImportCreateThread
& SCPT:PSCallWindowsAPI & SCPT:PSCopyShellCodeToMem & SCPT:PSStagerPayloadHead
& SCPT:PSStagerPayloadTail & PowerShell:Start-Sleep
```

Reading it as a red teamer:

- The target is a **PowerShell script** that is doing classic shellcode
  injection: it P/Invokes `kernel32`, imports `VirtualAlloc` and
  `CreateThread`, copies shellcode into the allocation and calls a Windows API.
- `PSStagerPayloadHead` / `PSStagerPayloadTail` mean Defender also recognises
  the **shape of the stager payload** (its head and tail), not just the API
  calls.
- `PowerShell:Start-Sleep` is a literal script-content rule for a sleep call,
  typical of a staged beacon.

Because it is a pure `&` chain, **breaking any single term breaks the whole
aggregator**. Practical angles:

- use a different allocation/injection path (e.g. `NtAllocateVirtualMemory` +
  APC / thread-pool / callback instead of `VirtualAlloc` + `CreateThread`), so
  the `VirtualAlloc`/`CreateThread` SCPT rules stay unmatched;
- drop the sleep (or replace it with a different delay mechanism) so the
  `Start-Sleep` content rule does not fire;
- change the stager payload/loader so the head/tail patterns no longer occur;
- remove the `DllImport`/`CallWindowsAPI` pattern, e.g. go through
  `Add-Type`/reflection or a compiled loader instead of an inline signature.

Caveat: each of those changes removes one *aggregator* term. The individual
script signatures may still be strong enough to detect on their own, and other
aggregators/behaviour rules may cover the same payload.

## Worked example 2 — VBS Metasploit stager

`Trojan:VBS/MetasploitVBSCmdStager`

```
SCPT:VBSCreateObject & SCPT:VBSScriptingFSO & SCPT:VBSGetFile & SCPT:VBSOpenTextFile
& SCPT:VBSSleep & SCPT:VBSBase64 & SCPT:VBSExe & SCPT:VBSRun
& SCPT:Base64FileExtension & SCPT:AppDataTemp & SCPT:AppDataTemp!Base64Drop
```

This is the VBScript version of the same idea: `CreateObject` + `Scripting.FileSystemObject`
+ `GetFile` + `OpenTextFile` (read a payload), `Base64` decode, write something
with a base64-ish extension into `%AppData%\Temp`, then `Run`/`Exec` it, with a
sleep in the middle.

Evasion levers, same logic:

- avoid `Scripting.FileSystemObject` for reading (e.g. `ADODB.Stream`, WMI,
  `Shell.Application`), which kills several SCPT terms at once;
- do not write to `%AppData%\Temp`, and do not use a base64-looking extension;
- drop the sleep or replace it;
- do not use `WScript.Shell.Run`/`Exec` to launch the result — use a different
  execution primitive.

`Base64FileExtension`, `AppDataTemp` and `AppDataTemp!Base64Drop` are a great
example of behavioural chaining: Defender does not just look for "base64"; it
looks for **base64 file dropped into AppData\Temp**.

---

## What it means for detection (red-team view)

- **It is the composition layer.** Microsoft writes small, reusable rules
  (`SCPT:*`, `HSTR:*`, `Lua:*`, ...) and then glues them into one threat name
  with an aggregator. One rule can be reused by many threats.
- **The threat name/severity/platform in the console come from the aggregator
  record**, not from any single term. The formula itself is generic; the same
  terms may appear in several families.
- **The expression is the minimum bar, not the whole detection.** A file can be
  detected by the referenced rules alone, by another aggregator, by a signature
  tree, by cloud/ML, or by a completely different signature type. Clearing one
  aggregator does not mean "clean".
- **Exclusions are visible.** A term like `!HSTR:VB.SuspiciousCrypter.Exclusion.A`
  or a `...Exclusion...` name literally tells you there is a string/marker that
  suppresses the rule. Sometimes adding that marker is a shortcut — but it is
  itself a known indicator and may trip other rules, so treat it as a last
  resort, not a plan.
- **Aggregators can chain.** `AGG:`/`AGGR:` atoms reference other aggregators,
  so a single family can be a tree of expressions. Break the leaf that all paths
  need.
- **Definitions change.** These formulas are refreshed with every definition
  update. A bypass verified against one signature version must be re-checked
  after updating.

## Bypass playbook (generic recipe)

1. **Split the expression into its top-level structure.** Ignore names for a
   moment and look at `&`, `|`, `!`.
2. **Pure `&`: find the cheapest term to remove.** Prefer terms that represent a
   replaceable technique (API, file path, extension, sleep, launch method) over
   terms that represent "the payload exists".
3. **`|`: every branch must be broken.** Enumerate all alternatives—missing one
   leaves the rule alive.
4. **`!`: this is an exclusion.** The aggregator *needs* the negated thing to be
   absent. Find out what the negated rule matches; if it is an FP/exclusion
   marker, that is the intended suppressor.
5. **Group terms by technique.** One change (`FSO` -> `ADODB.Stream`,
   `VirtualAlloc` -> `NtAllocateVirtualMemory`, `AppData\Temp` -> elsewhere) can
   remove three or four terms at once.
6. **Re-check the individual terms.** Even with the aggregator broken, the
   referenced `SCPT`/`HSTR` rules may detect the component on their own. The real
   goal is not "silence this one record" but "no rule in the chain fires".
7. **Assume siblings.** Search for other threats that reference the same terms
   (or the same family) — the same behaviour often has a second aggregator or a
   `SIGTREE`/behaviour counterpart.

## Gotchas

- The text shown is **decoded**; the raw database stores these bytes obfuscated.
  Searching the binary VDM for `SCPT:` as plaintext will not find it.
- `VERSIONCHECK` records can gate whether the aggregator (and the rest of the
  threat's records) is loaded at all, depending on engine/OS/definition
  version. An expression that "does not fire" on your build may simply be gated
  off—or gated on—for that environment.
- Some atoms are deliberately non-ASCII look-alikes (e.g. Cyrillic characters in
  `Lua:PeCompanyName!...`). Do not assume every name is pure ASCII when
  comparing or searching.
- The expression tells you what must **co-occur**, not the order, the process, or
  the file type. Correlate with the referenced rules to get the real picture.

## TL;DR for the report reader

> `SIGNATURE_TYPE_AAGGREGATOREX` = Defender's rule-combining formula.
> The line under it is a boolean expression over other signature names
> (`&` and, `|` or, `!` not). It never reads the file directly. Read it as a
> checklist of behaviours/strings that must all be present; a pure `&` chain is
> only as strong as its easiest term to remove, while `|` requires breaking every
> branch. Detection is still backed by the individual rules and other signature
> types, so breaking one aggregator is necessary but not always sufficient.
