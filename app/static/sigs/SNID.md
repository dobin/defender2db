# SNID signatures: what that reference is

This is the short explanation of a Defender `SIGNATURE_TYPE_SNID` record. Read this if
you are looking at an SNID and wondering what the key and type byte mean, and whether it
matters for detection or evasion.

## The one-sentence version

An SNID is a **pointer to a shared signature record**, not a detector. It says *"reuse the
record with this 20-byte key and this signature type"*. The record body lives elsewhere
(usually in a shared group), so the SNID itself contains no pattern and catches nothing.

## What you are looking at

An SNID is normally 21 bytes:

| Field | Size | What it is |
|-------|-----:|------------|
| **key** | 20 | The key of the referenced record in Defender's signature record store. |
| **type** | 1 | The `SIGNATURE_TYPE_*` of the referenced record. |
| **group** (optional) | .. | A NUL-terminated group/definition name; present only in the internal `!InfrastructureShared` bucket. |

There is no second body and no payload copy. mpengine looks the pair `(key, type)` up in
its record store and resolves it to a record id; that is the whole mechanism.

The 20-byte key is **not necessarily a SHA-1 of the shipped record bytes**. Hashing the
payload or TLV of every record in the current VDM (6.1 million records) reproduces only two
SNID keys, and those are accidental matches against a 4-byte `THREAT_END` payload. The key
is the record store's own key (a definition-identity hash). Some record families use a
16-byte, MD5/GUID-sized key zero-padded into the 20-byte field:

| referenced type | effective key | padding |
|---|---:|---|
| `SIGNATURE_TYPE_LOCALHASH` (`0x62`) | 16 bytes | 4 zero bytes at the end |
| `SIGNATURE_TYPE_FTRIE_POS` (`0xcd`) | 16 bytes | 4 zero bytes at the end |
| `SIGNATURE_TYPE_GENSFX` (`0x56`) | 16 bytes | 4 zero bytes at the end |
| `SIGNATURE_TYPE_MACHOHSTR_EXT` (`0x8d`) | 16 bytes | 4 zero bytes at the front |
| `SIGNATURE_TYPE_ELFHSTR_EXT` (`0x8c`) | 16 bytes | 4 zero bytes at the front |
| most others, e.g. KCRCEX (`0xcc`) | 20 bytes | none |

So when you see `…00000000` at the end of the printed key, four of the twenty bytes are
just padding, not part of the hash.

## The type byte is the useful part

The one-byte type tells you what kind of record was reused. Current database, by number of
SNID references:

| referenced type | id | references | what it means |
|---|---:|---:|---|
| `SIGNATURE_TYPE_KCRCEX` | `0xcc` | 422,922 | extended keyed-CRC record (runtime/file-derived) |
| `SIGNATURE_TYPE_IL2_PATTERN` | `0xa6` | 317,749 | .NET IL pattern |
| `SIGNATURE_TYPE_TRUSTED_PUBLISHER` | `0x70` | 258,943 | signer/publisher allow entries |
| `SIGNATURE_TYPE_AUTOITHSTR_EXT` | `0xd3` | 236,753 | AutoIt string pattern |
| `SIGNATURE_TYPE_MDBHSTR_EXT` | `0xe4` | 142,695 | managed/MDB string pattern |
| `SIGNATURE_TYPE_PESTATICEX` | `0xcb` | 132,413 | extended PE static record |
| `SIGNATURE_TYPE_FASTPATH_TDN` | `0xd8` | 128,975 | cloud/fastpath record |
| `SIGNATURE_TYPE_LOCALHASH` | `0x62` | 113,525 | locally generated file hash record |
| `SIGNATURE_TYPE_EXPLICITRESOURCEHASH` | `0xd9` | 73,143 | resource hash record |
| `SIGNATURE_TYPE_AAGGREGATOREX` | `0xe7` | 55,275 | boolean expression over other records |
| `SIGNATURE_TYPE_NID64` | `0xce` | 20,635 | 64-bit id table entries |

A large part of these records are **generated at scan time** (`KCRCEX`, `LOCALHASH`,
`FASTPATH_*`, `EXPLICITRESOURCEHASH`, …) or are cloud data, so the referenced body is often
not present in the local VDM at all. The SNID in the database is a precompiled form of the
lookup the engine will perform later.

## What the optional group name means

Only 436,206 of the 2.48 million SNID records carry a name, and **all** of them are in
`!InfrastructureShared`. The name is the **group/list the referenced records belong to**,
not the name of the target. It is also not the owner threat's name (0 of 436,206 match).
Examples from the current database:

| group name | entries | referenced type |
|---|---:|---|
| `#TopPkg:Prevalent` | 317,749 | `IL2_PATTERN` (`0xa6`) |
| `!#OrgSignerRmmNormal` | 55,275 | `AAGGREGATOREX` (`0xe7`) |
| `!#ALF:Trojan:PDF/Phish.1111!atmn` | 1,074 | `DELTA_BLOB` (`0x73`) |
| `!#AGGR:VibrantGondala` | 69 | `EXPLICITRESOURCE` (`0xd6`) |
| `!#NID:DLLHijack.DSK5` | 44 | `LOCALHASH` (`0x62`) |

This is a strong hint for triage: an SNID tells you *which shared list a threat pulls its
real signature from* even when the body is not shipped.

## Why a threat can be mostly SNIDs

The big `!#ALF:...` groups (for example `!#ALF:INTL:Trojan:Win32/Multiverze`) contain
hundreds of thousands of SNID references each. Those threats are **group containers**: they
collect references to shared records so that one definition can cover a large family. The
detection logic is in the referenced records (or in the cloud), not in the SNID lines.

## What it means for detection

* **An SNID cannot match anything by itself.** There is no data in it. Change the file and
  the key is unchanged.
* **The referenced record may be resolvable elsewhere.** If the type is a definition type
  (HSTR, aggregator, trusted publisher, sig tree), that record may exist in the same VDM;
  if it is a runtime type (KCRCEX, LOCALHASH, FASTPATH_*), it is produced during scanning
  and is not shipped.
* **The type byte is actionable intel**, the key usually is not. Use the type to pivot to
  the sibling definitions for that family; the group name, when present, tells you which
  shared list was reused.
* **Do not try to "bypass the SNID".** There is nothing there to bypass. Harden the code
  path the referenced record checks, or look at the family's other signatures.

## SNID vs NID

| | SNID (`0x7e`) | NID / NID64 (`0x55` / `0xce`) |
|---|---|---|
| Points at | a whole shared signature record | a name slot / namespace id |
| Key | 20-byte record-store key | 32-/64-bit internal id |
| Type byte | type of the referenced record | namespace of the id |
| Contains detection content | no (the target does) | no |
| Optional name | group/list that reused the record | definition group that registered the id |

See [NID.md](NID.md) for the numeric-id flavour.
