"""Read stored YARA text from a defender2db JSON snapshot (read-only)."""

import argparse
from pathlib import Path
import sys

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from defender2yara.defender.dbthreat import DEFAULT_DATABASE, DbThreat, read_session


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=DEFAULT_DATABASE, help='database path (default: cache/threats.db)')
    parser.add_argument('--name', default='', help='case-insensitive threat-name substring')
    parser.add_argument('--row-id', type=positive_int, help='database row ID (not Defender threat ID)')
    parser.add_argument('--limit', type=positive_int, default=5, help='maximum rules to display (default: 5)')
    parser.add_argument('--list', action='store_true', dest='list_only', help='list threats with rules instead of showing source; limit applies to threats')
    parser.add_argument('--check', action='store_true', help='compile each displayed rule to verify it')
    args = parser.parse_args(argv)
    if args.list_only and args.check:
        parser.error('--check cannot be used with --list')

    query = select(DbThreat.id, DbThreat.name, DbThreat.defender_id, DbThreat.generated).where(
        func.instr(func.lower(DbThreat.name), func.lower(args.name)) > 0
    ).order_by(DbThreat.id)
    if args.row_id is not None:
        query = query.where(DbThreat.id == args.row_id)
    shown = 0
    try:
        with read_session(args.db) as session:
            for row_id, name, defender_id, generated in session.execute(query).yield_per(100):
                rules = generated.get('yara', {}).get('items', [])
                if not rules:
                    continue
                if args.list_only:
                    print(f'row_id={row_id} threat_id={defender_id} rules={len(rules)} name={name}')
                    shown += 1
                else:
                    for index, rule in enumerate(rules):
                        if args.check:
                            import yara
                            yara.compile(source=rule)
                        print(f'// row_id={row_id} threat_id={defender_id} rule_index={index} name={name}')
                        print(rule)
                        shown += 1
                        if shown >= args.limit:
                            break
                if shown >= args.limit:
                    break
    except (OSError, SQLAlchemyError, ValueError) as error:
        parser.exit(1, f'Cannot read database: {error}\n')
    if not shown:
        print('No matching stored YARA rules.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())