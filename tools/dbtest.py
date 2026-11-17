"""Inspect a few persisted threat summaries without decoding or reading raw BLOBs."""

import argparse
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from defender2yara.defender.dbthreat import DEFAULT_DATABASE, DbThreat, read_session


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=DEFAULT_DATABASE, help='existing database path')
    args = parser.parse_args(argv)
    try:
        with read_session(args.db) as session:
            query = select(DbThreat).order_by(DbThreat.id).limit(10)
            for threat in session.scalars(query):
                print(f'Threat Name: {threat.name}')
                print(f'  Local ID: {threat.id}; Source ID: {threat.source_id}; Defender ID: {threat.defender_id}')
                print(f'  Signatures: {threat.signature_count}')
                for language in ('lua', 'yara'):
                    output = threat.generated.get(language, {})
                    print(f"  {language.upper()}: {len(output.get('items', []))} items; status={output.get('status', 'unavailable')}")
    except (OSError, SQLAlchemyError, ValueError) as error:
        parser.exit(1, f'Cannot read database: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
