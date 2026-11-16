"""Read stored YARA rules from a trusted defender2db database (read-only).

Database blobs use pickle. Never open databases supplied by untrusted sources.
"""

import argparse
from contextlib import closing
from pathlib import Path
import pickle
import sqlite3
import sys


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=Path('cache/threats.db'), help='database path (default: cache/threats.db)')
    parser.add_argument('--name', default='', help='case-insensitive threat-name substring')
    parser.add_argument('--row-id', type=positive_int, help='database row ID (not Defender threat ID)')
    parser.add_argument('--limit', type=positive_int, default=5, help='maximum rules to display (default: 5)')
    parser.add_argument('--list', action='store_true', dest='list_only', help='list threats with rules instead of showing source; limit applies to threats')
    parser.add_argument('--check', action='store_true', help='compile each displayed rule to verify it')
    args = parser.parse_args(argv)
    if args.list_only and args.check:
        parser.error('--check cannot be used with --list')

    # A URI read-only connection cannot accidentally create a missing database.
    uri = args.db.resolve().as_uri() + '?mode=ro'
    clauses = ['instr(lower(name), lower(?)) > 0']
    params = [args.name]
    if args.row_id is not None:
        clauses.append('id = ?')
        params.append(args.row_id)
    query = 'SELECT id, name, threatObject FROM dbthreat WHERE ' + ' AND '.join(clauses) + ' ORDER BY id'
    shown = 0
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            for row_id, name, blob in connection.execute(query, params):
                threat = pickle.loads(blob)
                rules = threat.yara_rules
                if not rules:
                    continue
                if args.list_only:
                    print(f'row_id={row_id} threat_id={threat.id} rules={len(rules)} name={name}')
                    shown += 1
                else:
                    for index, rule in enumerate(rules):
                        if args.check:
                            import yara
                            yara.compile(source=rule)
                        print(f'// row_id={row_id} threat_id={threat.id} rule_index={index} name={name}')
                        print(rule)
                        shown += 1
                        if shown >= args.limit:
                            break
                if shown >= args.limit:
                    break
    except (OSError, sqlite3.Error) as error:
        parser.exit(1, f'Cannot read database: {error}\n')
    if not shown:
        print('No matching stored YARA rules.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())