# defender2db

Download and parse Microsoft Defender Antivirus signatures into a searchable SQLite database. The project includes Lua parsing and a web interface for searching threats. It was originally based on [defender2yara](https://github.com/t-tani/defender2yara/).

Live at [defendersearch.r00ted.ch](https://defendersearch.r00ted.ch)

Microsoft ASR rules are in [result/asr_rules](https://github.com/dobin/defender2db_data/tree/main/asr_lua).

Data available at [defender2db_data](https://github.com/dobin/defender2db_data)


## Installation using `uv`

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if it is not already installed.

2. Create the project environment and install dependencies:

```sh
uv sync
```

On Debian/Ubuntu, `libarchive-dev` may also be required:
```sh
sudo apt install libarchive-dev
```

### Download / Update virus definition

Download current Defender Signatures (VDM) into `cache/engine` and `cache/vdm`:

```sh
uv run defender2db --download
```

Build a new `cache/threats.db` SQLite snapshot (published only after successful
conversion; updates replace the previous database):

```sh
uv run defender2db --convert
```

Conversion uses one transaction with 5,000-record `executemany` batches and builds
read indexes after loading. Progress separately shows threat-output generation
and signature insertion; final integrity checks run before publication. Parsing
throughput (MB/s) is not database conversion throughput: JSON expansion and
Lua/YARA generation add work and storage beyond the original VDM stream.

Raw capture defaults **off**. To retain every scanned TLV record, including
threat boundaries, zero-length and global records, rebuild with:

```sh
uv run defender2db --convert --include-raw
```

This captures the effective patched/decompressed signature streams, not the
original packed VDM containers or engine tables. Close readers before replacing
an open database on Windows.

Display first few entries of the sqlite db:

```sh
uv run python tools/dbtest.py
```

Browse stored YARA rules with `tools/yaraview.py`. It opens the database read-only
and displays up to five rules by default. Options include `--name Banload`
(case-insensitive substring), `--row-id 12` (SQLite row ID, not Defender ID),
`--limit 10`, `--list` (list threats with rules), `--check` (compile displayed
rules), and `--db cache\threats.db`. Both inspection tools open an existing
database read-only, validate its schema version, and read stored JSON/text without
unpickling objects or loading raw BLOBs. `tools/dbtest.py` also accepts `--db`.

Lua warnings include the threat name/ID, zero-based signature index, signature
type, decompressed VDM record offset, payload size, and first 48 payload bytes in
hex. Offsets refer to the patched/decompressed stream, not the compressed VDM
file. Decoded record metadata and generation diagnostics remain available when
Lua conversion fails; exact raw bytes are retained only with `--include-raw`.


### Structured threat data

A database is one import, with SQLAlchemy 2.x mappings for five tables:
`import_info` (schema/decoder/signature/engine versions, conversion time and raw
capture flag), `source` (effective stream identity), `threat`, `signature`, and
`raw_record`. It is a parsed snapshot, not a serialized Python object graph.
Legacy pickle databases and unsupported schema versions require rebuilding with
`--convert`; there is no migration or automatic re-decoding on read.

Threats contain explicit identity/name/category/severity fields, suffixes and
`generated` JSON. Each `generated.lua` / `generated.yara` object has a `status`,
`items` (text strings), and optional diagnostics. Empty/not-applicable output and
failed generation remain distinct. Readers never rerun parsers or generators.

Every scanned record has a local ID, source ID/offset, role, type ID, sizes,
`decode_status` (`decoded`, `partial`, `unsupported`, `error`),
`details_version`, and an explicit JSON `details` object. It also stores the
engine record id (`crc32(payload) | type << 32 | size << 40`) so references can
be resolved. Meaningful binary fields use lowercase
`*_hex` strings; 64-bit keys/packed IDs use fixed-width hex strings rather than
precision-losing JSON numbers. Unknown fields remain visible in the generic JSON
view. Unsupported records have no decoded payload; raw omission does not imply
that decoding failed.

The threat page retains static fingerprints, weighted DEX/PE patterns,
aggregator expressions/references, environment gates, behavior-tree
edges/conditions and NID/SNID references. It also shows decode/generation statuses,
source offsets, original record order, generic JSON and lazy raw downloads.
Version gates affect subsequent source-order records, even when displayed in
separate groups.

NID64 references are resolved when the key has the engine's packed record-id
layout (`crc32(payload) | type << 32 | size << 40`). Conversion stores that id on
every signature, so a NID64 card links to the referenced record and its owning
threat. This is a pointer, not a detection rule. Keys that are plain hashes or
point at runtime/cloud records show no target. SNID keys are not payload hashes
and stay unresolved, and group names describe lists, not the referenced record.

Databases built before record ids were stored remain readable; their NID64 cards
say that resolution is unavailable until rebuilt with `--convert`.

Names and Defender IDs are **not unique**. Local threat/signature IDs identify
occurrences only within the current snapshot. Offsets identify records within
the effective patched/decompressed `source` stream. Ordinary reads exclude raw
BLOBs; `raw_record` is empty unless conversion used `--include-raw`.

### Web Application

Copy `.env.example` to `.env` and set `DOMAIN` to the public base URL for the REST
API and remote MCP endpoint.

Start web server to search and browse the definitions: 

```sh
$ uv run python web.py
defender2db web interface
Listen on: 0.0.0.0 5002
 * Serving Flask app 'web'
 * Debug mode: off
```

REST search API (returns matching threat summaries):

```text
GET /api/threats?threat_name=metasploit
```

Search summaries contain `id` (local threat ID), `name`, `source_id`,
`defender_id` and `signature_count`. Use the returned local ID to retrieve a
specific occurrence, even when multiple sources contain the same name:

```text
GET /api/threats/12
GET /api/signatures/34
GET /api/signatures/34/raw
```

Threat details contain scalar threat fields, severity display, `generated`,
`raw_available`, ordered `signatures` (excluding framing), and `boundary_ids`.
Signature details contain `id`, `source_id`, `threat_id`, `type_id`, `type`,
`offset`, `size` (payload bytes), `header_size`, `record_size`, `role`,
`decode_status`, `details_version`, `details`, and `raw_available`. The raw route
alone downloads exact header-plus-payload bytes as `application/octet-stream`.

Search without `threat_name` returns `400`; unknown local IDs return `404`.
Raw bytes omitted at conversion return `409` with a rebuild instruction, not an
empty download. The HTML threat route is `/threat/12`. Name-only detail routes
are removed. The web server accepts `--db cache\threats.db`; Flask's
`DATABASE` configuration (including `FLASK_DATABASE`) selects the reader database.

### MCP Server

The MCP server exposes `search_threats` (name substring search), `get_threat`
(local threat ID), `get_signature` (local signature ID), and `get_raw_signature`
(explicit raw access as `data_hex`). Copy `.env.example` to `.env` and set `DOMAIN`
to the public base URL. The web page shows the Streamable HTTP endpoint as
`DOMAIN/mcp`.

For a local MCP client, start the stdio server with:

```sh
uv run defender2db-mcp
```

For a remote MCP client, start the Streamable HTTP server with:

```sh
uv run defender2db-mcp-http
```

It listens on `127.0.0.1:8000` by default. Configure the TLS reverse proxy for
`DOMAIN` to forward `/mcp` to this server. The HTTP server also reads `MCP_HOST`
and `MCP_PORT` from `.env` if its bind address or port needs to change. Search
results and threat details use the same fields and serialization as the REST API;
missing input or an unknown local ID is returned as a tool error. Raw-unavailable
errors explain how to rebuild with raw capture. Python readers expose
`search_threats`, `get_threat_details`, `get_signature_details`, and `get_raw_record`,
each accepting an optional `database` path. Missing rows raise `LookupError`; omitted
raw capture raises `RawUnavailableError`.

### ASR rules

Get the ASR rules into `rules/`:

```sh
uv run defender2db --asr
```


## Usage

### Python Lua backend (Windows and Linux)

Lua conversion uses the pure-Python decompiler bundled in this repository at
`defender_explorer/defender_sig_extractor/lua_decompiler`. It is included in package
builds; no separate checkout, path configuration, C compiler, `luadec` executable,
or Docker is required on Windows or Linux.

Only the Lua package is loaded, not Explorer's downloader, signature type table,
or heuristic YARA generators. The copied Explorer source has no license file;
its licensing still needs clarification before redistribution.
The existing root `luadec` binary is unused and retained only as a legacy artifact.

Original MpLua is passed directly to the Python backend, avoiding the old
integer-to-double fixup and shared temporary file. Failed decompilation falls back
to bytecode disassembly when possible. Re-run conversion to populate Lua scripts
in databases previously built on Windows. Decompiled source is best-effort, not
guaranteed equivalent to the original program; Lua constants are not automatically
promoted into YARA detections.

YARA rules now use signed, presence-based weighted scoring (`math.to_number`,
available in the required YARA version), rather than subset enumeration or
negative-weight vetoes. This preserves the project's scoring model, not the full
Defender engine semantics. Unknown extended-pattern operations remain approximate
and are marked low accuracy; malformed/unconvertible patterns are not emitted as
partial signatures. File-size and optional header restrictions still limit scope.


