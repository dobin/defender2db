#!/usr/bin/env python3
"""Helpers for resolving opaque sigtree value words.

Two modes:

  targets   Build the target list used by a runtime probe (0x40ff anchor ids
            plus, optionally, every value word that is not in the known table).

  parse     Parse a probe log and turn verified CRC inputs into hash -> text
            pairs.  Both the narrow and wide engine CRC are checked with
            ``sigtree_value_crc()``, so a line is only accepted when it really
            matches the engine's hash.

Runtime probes live in the companion DefenderReversingHelper checkout; see
``doc/sigs/sig_decode_pestatic_bm_sigtree_ext.md`` section 5.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from defender2yara.defender.signature.sigtree import (  # noqa: E402
    KNOWN_VALUE_STRINGS,
    sigtree_value_crc,
)

SIGTREE_BM = 0xB3
ATTR_SIGNATURE_ANCHOR = 0x40FF

CRC_LINE = re.compile(r'CRC\s+(narrow|wide)\s+result=0x([0-9a-fA-F]{8})\s+'
                      r'len=(\d+)\s+text="(.*)"\s*$')
MATCH_LINE = re.compile(r'(?:MATCH|MATCH40FF|ATTR40FF)\s+attr=0x([0-9a-fA-F]+)'
                        r'.*?v="(.*)"\s*$')


def iter_bm_edges(db: Path):
    con = sqlite3.connect(db)
    try:
        for (details,) in con.execute(
                "select details from signature where type_id=?", (SIGTREE_BM,)):
            yield json.loads(details)["edges"]
    finally:
        con.close()


def collect_targets(db: Path, all_unresolved: bool = False):
    """Return ``{value: {"length": n, "source": ...}}``."""
    targets: dict[int, dict] = {}
    for edges in iter_bm_edges(db):
        for edge in edges:
            attr = edge["attribute_id"]
            for side in ("left", "right"):
                value = edge.get("z" if side == "left" else "w") or 0
                if value == 0:
                    continue
                length = edge.get(f"{side}_length") or 0
                if attr == ATTR_SIGNATURE_ANCHOR:
                    targets[value] = {"length": length, "source": "0x40ff"}
                elif all_unresolved and (value, length) not in KNOWN_VALUE_STRINGS:
                    targets.setdefault(value, {"length": length,
                                               "source": f"0x{attr:04x}"})
    return targets


def write_targets(targets, out: Path, header: bool = False) -> None:
    if header:
        with out.open("w", encoding="ascii") as fh:
            fh.write("/* generated sigtree probe targets */\n#pragma once\n"
                     "#include <stdint.h>\n"
                     "static const uint32_t g_crc_targets[] = {\n")
            values = sorted(targets)
            for i in range(0, len(values), 8):
                fh.write("    " + ", ".join(f"0x{v:08x}u"
                                            for v in values[i:i + 8]) + ",\n")
            fh.write("};\n#define G_CRC_TARGET_COUNT %d\n" % len(values))
    else:
        out.write_text(json.dumps({f"0x{v:08x}": info
                                   for v, info in sorted(targets.items())},
                                  indent=2) + "\n", encoding="ascii")


def parse_log(path: Path, include_matches: bool = True) -> dict:
    resolved: dict[str, dict] = {}
    context: list[dict] = []
    for raw in path.read_text(encoding="latin-1").splitlines():
        match = CRC_LINE.search(raw)
        if match:
            kind, value_hex, length, text = match.groups()
            value = int(value_hex, 16)
            checks = {
                "narrow": sigtree_value_crc(text, wide=False),
                "wide": sigtree_value_crc(text, wide=True),
            }
            if checks[kind] != value:
                continue
            entry = resolved.setdefault(text, {
                "value": f"0x{value:08x}",
                "kind": kind,
                "length": int(length),
                "verified": True,
            })
            entry.setdefault("also", set()).add(kind)
            continue
        if include_matches:
            match = MATCH_LINE.search(raw)
            if match:
                context.append({"attr": f"0x{int(match.group(1), 16):04x}",
                                "value": match.group(2)})
    for text, entry in resolved.items():
        entry["also"] = sorted(entry["also"])
    return {"resolved": resolved, "matches": context[-200:]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_targets = sub.add_parser("targets", help="build a probe target list")
    p_targets.add_argument("--db", type=Path, default=Path("cache/threats.db"))
    p_targets.add_argument("--out", type=Path, required=True)
    p_targets.add_argument("--all-unresolved", action="store_true",
                           help="also include non-0x40ff words not in the "
                                "known table")
    p_targets.add_argument("--header", action="store_true",
                           help="write a C header instead of JSON")

    p_parse = sub.add_parser("parse", help="parse a runtime probe log")
    p_parse.add_argument("log", type=Path)
    p_parse.add_argument("--out", type=Path)
    p_parse.add_argument("--no-matches", action="store_true")

    args = parser.parse_args()
    if args.cmd == "targets":
        write_targets(collect_targets(args.db, args.all_unresolved),
                      args.out, args.header)
        return 0

    result = parse_log(args.log, include_matches=not args.no_matches)
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(text, encoding="ascii")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
