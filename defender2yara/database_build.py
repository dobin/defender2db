"""Publish a complete SQLite import without destroying the previous database."""

from contextlib import contextmanager
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
import os
import tempfile
import logging

from sqlalchemy import insert, text

from defender2yara.defender.dbthreat import Base, ImportInfo, SCHEMA_VERSION, database_engine


@contextmanager
def build_database(path, *, signature_version, engine_version, include_raw):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.stem + '-', suffix='.sqlite', dir=path.parent)
    os.close(fd)
    engine = database_engine(temporary)
    try:
        Base.metadata.create_all(engine)
        # Build read indexes once, after the bulk load, rather than per inserted row.
        indexes = [index for table in Base.metadata.tables.values() for index in table.indexes]
        with engine.begin() as connection:
            for index in indexes:
                index.drop(connection)
        with engine.begin() as connection:
            connection.execute(insert(ImportInfo), [{
                'id': 1, 'schema_version': SCHEMA_VERSION,
                'decoder_version': version('defender2db'),
                'signature_version': signature_version, 'engine_version': engine_version,
                'converted_at': datetime.now(timezone.utc), 'raw_included': include_raw,
            }])
            yield connection
            logger = logging.getLogger(__name__)
            logger.info('Building database read indexes')
            for index in indexes:
                index.create(connection)
            logger.info('Validating database integrity and record counts')
            if connection.scalar(text('PRAGMA integrity_check')) != 'ok':
                raise ValueError('Database integrity check failed')
            if connection.execute(text('PRAGMA foreign_key_check')).first() is not None:
                raise ValueError('Database foreign key check failed')
            records = connection.scalar(text('SELECT count(*) FROM signature'))
            raw_records = connection.scalar(text('SELECT count(*) FROM raw_record'))
            if raw_records != (records if include_raw else 0):
                raise ValueError('Incomplete raw record capture')
            incomplete_sources = connection.scalar(text('''
                SELECT count(*) FROM source s WHERE s.stream_size !=
                (SELECT coalesce(sum(record_size), 0) FROM signature WHERE source_id = s.id)
            '''))
            if incomplete_sources:
                raise ValueError('Incomplete source record coverage')
            incorrect_counts = connection.scalar(text('''
                SELECT count(*) FROM threat t WHERE t.signature_count !=
                (SELECT count(*) FROM signature WHERE threat_id = t.id AND role = 'signature')
            '''))
            if incorrect_counts:
                raise ValueError('Incorrect threat signature counts')
        engine.dispose()
        os.replace(temporary, path)
    finally:
        engine.dispose()
        for candidate in (temporary, temporary + '-journal'):
            if os.path.exists(candidate):
                os.remove(candidate)
