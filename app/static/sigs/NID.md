# NID and NID64 signatures: what that number is

This is the short, no-reversing-needed explanation of Defender's
`SIGNATURE_TYPE_NID` and `SIGNATURE_TYPE_NID64` records. Read this if you are looking
at a NID and wondering what `key` and `kind` mean, and whether it matters for detection
or evasion.

## The one-sentence version

A NID is a **bookmark, not a detector**. It is a numeric reference into Defender's own
internal name/object table — it describes no file, no byte pattern, no hash and no
behaviour. On its own it catches nothing.

NID64 is the same idea with a 64-bit id. The table format and the meaning of `kind` are
the same; only the id width differs.

## What you are looking at

A NID is a pair of numbers:

| Field | What it is |
|-------|------------|
| **key** | An internal id (a "name slot") assigned by Microsoft when the definition database was built. In NID64 it is a 64-bit id. It is not an address, not a hash, and it has nothing to do with your file. |
| **kind** | A small number that says which namespace/table the id belongs to. |
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

## What the NID64 key really is

NID64 is not a different concept; it is the 64-bit form of the same table entry. In the
shipped database the 64-bit key is usually a **packed record id** in the engine's own
format:

```
bits  0..31   crc32 of the referenced record payload  (Defender CRC-32)
bits 32..39   the referenced record's signature type
bits 40..63   the referenced record's payload size
```

The engine uses the same packing everywhere (`crc32 | type << 32 | size << 40`, for
example when it builds a NID record id or a STATIC record id). Of the 12,109 NID64
records in the current database, 5,141 keys resolve exactly to a record shipped in the
VDM stream — mostly other NID64, STATIC, revoked-certificate, aggregator, SNID and NID
records. The rest point at records that are not shipped (runtime/cloud records) or use a
non-record id namespace.

That does **not** make NID64 a detector. It is still a membership/reference entry:
"id X belongs to namespace K" (plus an optional name). The fact that the id can be
parsed as a record id just tells you which record the entry is about.

Observed NID64 namespaces in the current database:

| kind | records | what the entries look like |
|------|--------:|----------------------------|
| `0x67` | 8,982 | STATIC-table members: ids of NID64/STATIC/SNID/NID/sig-tree records |
| `0x50` | 2,879 | CKSIMPLEREC-table members: STATIC, revoked-certificate and aggregator ids |
| `0x84` | 97 | high-trust publisher names, e.g. `#HighTrustPublisher_VLC` |
| `0xe4` | 80 | `MDBHSTR_EXT` names; the GoLang allow-list uses these for standard functions |
| `0x5c` | 37 | threat-name ids |
| others | 34 | sample-request, filename, removal-policy, KCRCE, UNPLIB ids |

Only 102 of the 12,109 NID64 records carry an inline name, and only 17 distinct names
occur. They are group/list names (`#HighTrustPublisher_*`, `#TEL:...`), not target names.

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

## NID vs SNID vs NID64

| | NID (`0x55`) | NID64 (`0xce`) | SNID (`0x7e`) |
|---|---|---|---|
| Payload | `u32 id`, `u8 kind`, optional name | `u64 id`, `u8 kind`, optional name | `u8 key[20]`, `u8 type`, optional group name |
| What the key is | internal 32-bit id | internal 64-bit id (often a packed record id) | key of a record in the signature record store |
| What it points at | a name slot / namespace entry | a name slot / namespace entry | a whole shared signature record of the given type |
| Detection content | none | none | none inside the SNID; the referenced record has it |

An SNID is the more interesting of the three: its **type byte tells you what the shared
record actually is** (KCRCEX, STATIC-family, trusted publisher, HSTR, aggregator, …), and
its optional name is the group/list the record belongs to (e.g. `#TopPkg:Prevalent` for
IL2 patterns, `!#OrgSignerRmmNormal` for aggregator records). See
[SNID.md](SNID.md).

## What it means for detection

* **It cannot match anything you send.** There is no data to compare against. Nothing you
  change in a binary, script or document affects a NID.
* **It cannot be resolved.** The object the id points to is usually not shipped in the
  signature database (only the reference is). Measured on the full DB: only 4 out of
  ~192,000 NID references have any companion name record, and none of the ids in the
  `0x77d1…` range used by the Metasploit names have one.
* **It tells you nothing about the trigger.** Seeing `key`/`kind` in a verdict does not
  tell you which file property or behaviour caused it.
* **Some NIDs influence analysis rather than detection.** A few ids are attributes that
  tell the engine to enable deeper analysis (emulation, re-scan, higher limits) for that
  object. That changes how hard the sample gets looked at, not whether it matches.
* **A NID64 can be resolved further than a NID** when its key is a packed record id, but
  the result is still just "this record/object exists in namespace K" — not a match rule.

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
* NID64 = the same thing with a 64-bit id; that id is often a packed record id.
* Nothing to match, nothing to patch, nothing to resolve locally.
* A threat that is only a NID is a **name/alias entry**; the actual detection logic for
  that family lives in other records.
* When you see one, ignore the NID and look at what else is attached to the threat. If the
  threat also has SNIDs, follow those: the SNID type tells you what shared record was
  reused.

One caveat: the NID tells you nothing about how the family is *actually* detected. Do not
read "NID only, no logic" as "this family is not detected" — the detection may simply live
elsewhere (another definition, the shared groups, or the cloud).
