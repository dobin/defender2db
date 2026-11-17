# defender2db basics

## What this project does

Microsoft Defender definitions are distributed as packed `.vdm` files. After unpacking, a VDM database is a stream of binary records. Some records start or end a threat; others contain a signature, a reference to shared definition data, or information the current decoder does not yet interpret.

A **threat** is a named Defender entry. It can have multiple **signatures**, and a signature can be a detection rule, metadata, or a reference to another definition. Not every signature is a file-matching rule. For example, a static signature stores file fingerprints, while NID records are references into Defender's internal tables.

`defender2db` converts the slow-to-inspect VDM data into a searchable, read-only SQLite snapshot. It also runs supported Lua/YARA generation during conversion so that normal browsing does not repeat that work.

## Big picture

```text
 Packed .vdm files
 (compressed base + optional delta)
             |
             v
   extract and patch streams
             |
             v
    parse ordered TLV records
             |
      +------+------+
      |             |
      v             v
 group records   decode supported
 into threats    signature types
      |             |
      +------v------+
        generate Lua/YARA
        and JSON details
             |
             v
     bulk-write SQLite snapshot
       /                  \
 decoded rows          optional raw TLVs
       \                  /
        searchable UI / API
```

A TLV record is a **type, length, value** structure: the type identifies the record kind, the length describes its payload, and the value holds the packed data. Records are kept in source order because order can matter—for example, an environment/version check may affect following signatures.

## Database layout

Each database represents one conversion/import. That import normally contains two effective streams: antivirus (`mpav`) and antispyware (`mpas`). The delta is applied to its matching base before parsing; source offsets refer to the resulting decompressed stream, not offsets in the packed `.vdm` container.

```text
import_info (one import)
     |
     +---- source: antivirus stream
     |        |
     |        +---- threat A ---- ordered signature rows
     |        +---- threat B ---- ordered signature rows
     |        +---- global/shared signature rows
     |
     +---- source: antispyware stream
              |
              +---- threat C ---- ordered signature rows
              +---- global/shared signature rows

signature row ---- optional raw_record row
```

There are five tables:

| Table | What it stores |
|---|---|
| `import_info` | Schema/decoder and definition versions, conversion time, and whether raw records were captured. |
| `source` | Stream kind, base/delta names, effective version, size, and hash. |
| `threat` | Searchable threat name and Defender metadata, source occurrence, signature count, and generated output. |
| `signature` | One row per parsed record, in source order, with local ID, source offset, optional owning threat, type/size/status, and JSON details. Shared/global records can have no threat owner. |
| `raw_record` | Optional exact bytes of the corresponding complete TLV record, including its header. |

The layout deliberately avoids a SQL table for each signature type or for nested pieces such as string patterns and behavior-tree edges. Common searchable facts are columns; type-specific interpretations are JSON. This keeps schema evolution simple as more VDM formats are understood.

## What is stored for a signature

Parser objects exist temporarily while converting the VDM, but **Python objects are not saved in the database**. Each supported signature parser explicitly converts its interpretation into ordinary JSON values. For example, a STATIC fingerprint might be stored as:

```json
{
  "partial_crc1": 4160239032,
  "partial_crc2": 1451528285,
  "partial_crc3": 400282949,
  "file_size": 607744,
  "flags": 8192,
  "hash_type": "crc32",
  "file_hash_hex": "282ac51f",
  "prefix_match": false
}
```

Useful interpreted byte values (such as hashes, keys, or pattern bytes) are represented as lowercase hex strings. The complete original record bytes are separate and optional. Thus raw capture can be disabled without hiding interpreted fields, but unsupported or opaque payload bytes are then not recoverable from this database.

Every signature row also records its source offset, type ID, record/payload sizes, role (such as signature, threat boundary, or global record), decode status (`decoded`, `partial`, `unsupported`, or `error`) and details format version. Duplicate records are retained as distinct occurrences; local IDs identify rows in this snapshot, not Defender-wide permanent IDs.

Generated Lua and YARA text is stored with each threat as JSON, alongside a status and optional diagnostics. It is generated once while converting; browsing the database does not rerun the parser or generators.

## Signature references

Some signatures point to other data instead of containing the referenced signature body. For example, SNID identifies a shared record by an opaque key and type, and NID/NID64 identify entries in Defender's internal tables. Aggregator expressions can also mention named signatures.

```text
Threat
  |
  +-- embedded signature details (interpreted JSON)
  |
  +-- reference { key, kind/type, optional group/name }
                           |
                           +-- shared, external, or unresolved definition
```

The database preserves the reference and its interpreted key/type, but does not assume the referenced record is present, that keys are hashes of the payload, or that names always identify the target. Some referenced records exist only outside the VDM stream or inside Defender's engine. References are displayed as references; automatic resolution is not performed.

## Conversion steps

1. Choose the installed VDM signature and engine versions.
2. Read the base `.vdm` and apply the matching delta when available.
3. Decompress the effective stream and parse its ordered records.
4. Group records between threat-begin and threat-end markers; retain standalone and shared/global records too.
5. Decode supported signature types into versioned JSON details. Unsupported types remain visible with their common metadata; safely framed decoder errors are recorded as errors. Malformed framing aborts conversion because the next record boundary cannot be trusted.
6. Generate YARA and Lua output for each threat where applicable.
7. Batch-insert source, threat, and signature rows. If `--include-raw` is enabled, also store each exact TLV record as a BLOB.
8. Build read indexes and check SQLite integrity, foreign keys, and record coverage.
9. Publish the newly built database only after the checks pass, preserving the prior database if conversion fails.

Run a normal decoded-data conversion with:

```powershell
uv run defender2db --convert
```

To retain every scanned record's exact TLV bytes for later reverse engineering, use:

```powershell
uv run defender2db --convert --include-raw
```

Raw capture is off by default to keep the database smaller. It captures record bytes from the effective patched/decompressed streams, **not** the packed VDM files or Defender engine tables.

## Reading the database

Readers use the stored JSON and explicit columns directly. They do not deserialize a Python object graph or rerun conversion. Threat names and Defender IDs can repeat, so the web/API uses local database IDs to select an exact occurrence. The raw-record endpoint is explicit and reads only the requested BLOB; regular search and threat detail views do not load raw BLOB data.

A new decoder or revised interpretation requires rebuilding from VDM input. In raw-free mode, omitted bytes cannot be recovered by re-decoding the database; the source VDM must be available again.
