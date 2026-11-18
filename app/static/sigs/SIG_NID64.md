# NID64 signatures: what that 64-bit number is

This is the short explanation of a Defender `SIGNATURE_TYPE_NID64` record. Read this if
you are looking at an NID64 and wondering what the 64-bit key and `kind` byte mean, and
whether it matters for detection or evasion.

## The one-sentence version

A NID64 is a **bookmark, not a detector**. It is a numeric reference into Defender's own
internal id/name table, using a 64-bit id instead of the 32-bit id that NID uses. On its
own it matches nothing.

## What you are looking at

A NID64 is normally 9 bytes:

| Field | Size | What it is |
|-------|-----:|------------|
| **key** | 8 | A 64-bit internal id. For record-backed namespaces it is usually a packed record id (see below). |
| **kind** | 1 | A namespace/table id that says which family the key belongs to. |
| **name** (optional) | .. | A NUL-terminated group/list name; only 102 records in the shipped database carry one. |

There is no pattern, hash or behaviour in the record. mpengine stores NID64 entries in a
table keyed by `(key, kind)` and uses them for name lookups and membership tests (for
example "is this record id a revoked certificate?").

## The key is often a packed record id

For record-backed namespaces, the 64-bit key uses the engine's packed record-id layout:

```
bits  0..31   crc32 of the referenced record payload  (Defender CRC-32)
bits 32..39   the referenced record's signature type
bits 40..63   the referenced record's payload size
```

The engine uses the same packing for NID record ids and STATIC record ids. In the current
database **5,141 of 12,109** NID64 keys resolve exactly to a record shipped in the VDM
stream:

| target type | resolved keys |
|---|---:|
| other NID64 records | 4,077 |
| STATIC | 531 |
| aggregator (`AAGGREGATOREX`) | 312 |
| SNID | 123 |
| trusted publisher | 90 |
| revoked certificate | 4 |
| `AAGGREGATOR` (0x96) | 2 |
| `NSCRIPT_BRUTE` / NID | 1 each |

The remaining keys point at records that are not shipped (runtime/cloud data) or use a
namespace whose ids are not record ids.

**Not every key is a packed record id.** Some are plain hashes or numeric ids. For example
the GoLang allow-list keys decode to an implausible `0xea` "type" and a 4.7 MB "size"; the
`kind` byte, not the key layout, is the reliable part. Treat the packed-id reading as a
strong hint, not a guarantee.

## Following the reference in this UI

When the key has the packed record-id layout, the NID64 card shows a **Referenced record**
line linking to the record it points at. The database stores each signature's record id
(`crc32(payload) | type << 32 | size << 40`), so the crc, type and size in the key must all
match a shipped record. The link goes to that record's card and names its owning threat.

If no shipped record matches, the key is a reference to runtime/cloud data; the card says
so instead of inventing a target. Resolving a NID64 only tells you *which record the entry
is about* - the referenced record is where any usable content lives. A database built
before record ids were stored can still be browsed, but its NID64 cards report that
resolution is unavailable until it is rebuilt with `--convert`.

## What `kind` means

`kind` is an undocumented namespace/table id. Observed values in the current database:

| kind | records | what the entries look like |
|------|--------:|----------------------------|
| `0x67` | 8,982 | STATIC-table members: ids of NID64/STATIC/SNID/NID/sig-tree records |
| `0x50` | 2,879 | CKSIMPLEREC-table members: STATIC, revoked-certificate and aggregator ids |
| `0x84` | 97 | high-trust publisher names, e.g. `#HighTrustPublisher_VLC` |
| `0xe4` | 80 | `MDBHSTR_EXT` names; the GoLang allow-list uses these |
| `0x5c` | 37 | threat-name ids |
| `0x6e` | 10 | script-brute HSTR names |
| `0x57` | 10 | `UNPLIB` ids |
| `0x6a` | 7 | removal-policy ids |
| `0x7b` | 4 | sample-request names |
| others | 3 | filename, telemetry and KCRCE ids |

Only 102 of the 12,109 NID64 records carry an inline name (17 distinct names), and 97 of
those are the high-trust publisher list. As with NID, the name is the **group/list name**,
not the name of the referenced record.

## Examples

```
# !#Allow:GoLang/StandardFunc
# 80 NID64 records, kind 0xe4, no other signature in the threat.
key=0x478d41ea53957601 kind=0xe4   -> MDBHSTR_EXT function-name record
key=0x106d99db6eece403 kind=0xe4   -> MDBHSTR_EXT function-name record

# !InfrastructureShared
key=0x00001770da1e201c kind=0x84   "#HighTrustPublisher_VLC"
      -> crc 0xda1e201c, type 0x70 (TRUSTED_PUBLISHER), size 0x17 (23)
```

The first threat is an allow-list: it contains only references to function-name records.
The second is a naming/allow layer for trusted publishers.

## What it means for detection

* **A NID64 cannot match anything by itself.** There is no data to compare against.
* **It can often be resolved further than a NID** because its key is frequently the packed
  id of a real record. That still only tells you *which record the entry is about*; it does
  not create a detection rule from the NID64 line itself.
* **`kind` is the useful part.** It tells you which namespace/table the id belongs to:
  static-match members, trusted publisher names, Go function names, and so on.
* **Do not try to "bypass the NID64".** There is nothing there to bypass. Look at the
  referenced record or the family's other signatures (STATIC, HSTR, SNID, aggregators).

## NID64 vs NID vs SNID

| | NID (`0x55`) | NID64 (`0xce`) | SNID (`0x7e`) |
|---|---|---|---|
| Payload | `u32 id`, `u8 kind`, optional name | `u64 id`, `u8 kind`, optional name | `u8 key[20]`, `u8 type`, optional group name |
| Key | 32-bit internal id | 64-bit internal id, often a packed record id | record-store key |
| Points at | a name slot / namespace entry | a name slot / namespace entry | a whole shared signature record |
| Detection content | none | none | none inside the SNID; the target has it |

See [SIG_NID.md](SIG_NID.md) for the 32-bit NID explanation and
[SIG_SNID.md](SIG_SNID.md) for the shared-record reference.
