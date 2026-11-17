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
```
sudo apt install libarchive-dev
```

### Download / Update virus definition

Download current Defender Signatures (VDM) into `cache/engine` and `cache/vdm`:

```sh
uv run defender2db --download
```

Convert to `./cache/threats.db` SQLite DB. File will be overwritten. 
```sh
uv run defender2db --convert
```

Display first few entries of the sqlite db:

```sh
uv run python tools/dbtest.py
```

Browse stored YARA rules with `tools/yaraview.py`. It opens the database read-only
and displays up to five rules by default. Options include `--name Banload`
(case-insensitive substring), `--row-id 12` (SQLite row ID, not Defender ID),
`--limit 10`, `--list` (list threats with rules), `--check` (compile displayed
rules), and `--db path/to/threats.db`. Only open trusted databases: stored objects
are deserialized using Python pickle.

Lua warnings include the threat name/ID, zero-based signature index, signature
type, decompressed VDM record offset, payload size, and first 48 payload bytes in
hex. Offsets refer to the patched/decompressed stream, not the compressed VDM
file. Raw signatures remain stored in the database even when Lua conversion fails.


### Structured threat data

Stored `NiceThreat` objects now include typed signature, Lua (`list[bytes]`), and
YARA (`list[str]`) collections, plus `dexhstr_signatures`,
`aggregator_signatures`, `version_checks`, `behavior_signatures`,
`nid_signatures`, `pehstr_signatures`, and `revoked_certs`.
The six decoded signature collections retain their parser objects and fields;
raw records remain in `signatures`, including records that cannot be decoded.

The threat page displays weighted DEX/PE patterns, aggregator expressions and
references, environment gates, behavior-tree edges/conditions, and NID keys/names
in separate sections. Undecodable records remain visible as raw signatures.
Existing databases are decoded on load without rewriting them; run `--convert`
to persist the new collections. Lua and YARA generation are unchanged.

### Web Application

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

Use the exact threat name to retrieve one full threat, including signatures and scripts:

```text
GET /api/threat?name=Win32%2FBearfoos.A
```

Both endpoints return JSON. Missing query parameters return `400`; an exact name not
found by `/api/threat` returns `404`.

### MCP Server

The stdio MCP server exposes the same two operations as tools: `search_threats`
(name substring search) and `get_threat` (exact-name details). Start it with:

```sh
uv run defender2db-mcp
```

Configure your MCP client to launch this command from the project directory so it
uses the same `cache/threats.db` database as the web application. Search results and
threat details use the same fields and serialization as the REST API; missing input
or an unknown exact name is returned as a tool error.

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


