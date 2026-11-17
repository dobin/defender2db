# NID signatures: what that number is

This is the short, no-reversing-needed explanation of a Defender `SIGNATURE_TYPE_NID`
record. Read this if you are looking at a NID and wondering what `key` and `kind` mean, and
whether it matters for detection or evasion.

## The one-sentence version

A NID is a **bookmark, not a detector**. It is a numeric reference into Defender's own
internal definition table — it describes no file, no byte pattern, no hash and no
behaviour. On its own it catches nothing.

## What you are looking at

A NID is a pair of numbers:

| Field | What it is |
|-------|------------|
| **key** | An internal id (a "name slot") assigned by Microsoft when the definition database was built. It is not an address, not a hash, and it has nothing to do with your file. |
| **kind** | A small number that says which family/namespace the id belongs to. |
| **name** (rare, mostly in the internal/shared buckets) | The name of the definition *group* the reference sits in — not the name of what it points to. |

There is nothing else in the record. There is no string to match, no offset to patch, and
no way to turn it into a YARA or Lua rule.

`kind` is undocumented but it visibly groups ids by object family, for example:

| kind (observed) | Family |
|---|---|
| `0x03`–`0x21` | legacy per-format name tables (DOS, Win16, Win95, BAT, IRC, SWF, HTML, Word/Access/Excel macros, Java, …) |
| `0x11` | name slots: legacy names, packer names, group/tag names |
| `0x3a`, `0x4e`, `0x5d`, `0x5f` | LowFi / behaviour-monitoring names |
| `0x59` | persistence names |
| `0x1b`, `0x16`, `0x07` | Java / JS / HTML script objects |
| `0x1e`, `0x1f`, `0x20` | O97M macro objects |
| `0xd2`, `0xdc` | "clean" lists (folders, domains) |
| `0xdf`, `0x4d` | shared "ALF" reference groups |
| `0x2b`–`0x3c` | engine attributes (analysis flags, not name slots) |

The exact numbers are Microsoft-internal; treat them as labels, not as anything you can
act on.

## Why a whole threat can be just a NID

About **13%** of all threat definitions in the shipped database contain nothing but NID
records. They are the **naming layer**, not the detection layer:

* legacy names (`Virus:DOS/Nutcracker.6727`, `Virus:DOS/Gullich`),
* aliases/placeholders for a family name,
* packer names (`!Momma`, `!VMProtect`, `!ExeCryptor`),
* tags and allow/clean-list entries (`#Tag`, `#CleanFolder`, `#CleanDomain`, `#TEL`),
* membership of shared groups (e.g. a signer allow-list holding tens of thousands of ids).

So a NID-only entry means *"this name exists in Defender's database"* — not *"this is how
we catch it"*. The signatures that actually inspect a file for the same family are the
sibling entries, typically the ones with suffixes like `!MTB`, `!MSR`, `!rfn`, `!sms` or
the shared group definitions. Those carry the STATIC hashes, PE/script strings, behaviour
trees or aggregator expressions.

Example, current database: the bare `Trojan:Linux/Metasploit` and `Trojan:Win64/Metasploit`
names are single NIDs with no other signature. The Metasploit entries that really match
something are `Trojan:Win64/Metasploit!MTB` (STATIC hashes), `HackTool:Win32/Metasploit`
(STATIC) and the shared `!#ALF:.../Metasploit` group (SNID + KCRCE references).

## What it means for detection

* **It cannot match anything you send.** There is no data to compare against. Nothing you
  change in a binary, script or document affects a NID.
* **It cannot be resolved.** The object the id points to is not shipped in the signature
  database (only the reference is). Measured on the full DB: only 4 out of ~192,000
  references have any companion name record, and none of the ids in the `0x77d1…` range
  used by the Metasploit names have one.
* **It tells you nothing about the trigger.** Seeing `key`/`kind` in a verdict does not
  tell you which file property or behaviour caused it.
* **Some NIDs influence analysis rather than detection.** A few ids are attributes that
  tell the engine to enable deeper analysis (emulation, re-scan, higher limits) for that
  object. That changes how hard the sample gets looked at, not whether it matches.

## What to do with it

* **Do not try to "bypass the NID".** There is nothing there to bypass. Time spent on the
  number is wasted.
* If a NID-only name is what flagged you, the real detection came from somewhere else:
  usually a sibling definition with actual content, a shared behaviour group, or a
  cloud/ML verdict that is not in the local database at all. Pivot to the other signature
  types on the same family.
* The number is still useful intel: the name tells you Defender has a name slot for that
  family, and the `kind` hints at which object family the entry belongs to (script, macro,
  installer, persistence, clean list, packer, …).

## Practical summary

* A NID is **a reference, not a detection**: "this id exists / this name is registered".
* `key` = an internal id, `kind` = which family of objects that id lives in.
* Nothing to match, nothing to patch, nothing to resolve locally.
* A threat that is only a NID is a **name/alias entry**; the actual detection logic for
  that family lives in other records.
* When you see one, ignore the NID and look at what else is attached to the threat.

One caveat: the NID tells you nothing about how the family is *actually* detected. Do not
read "NID only, no logic" as "this family is not detected" — the detection may simply live
elsewhere (another definition, the shared groups, or the cloud).
