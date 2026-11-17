"""Explicit SQLite rows; parser objects never cross the persistence boundary."""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3
import json

_JSON_ENCODER = json.JSONEncoder(separators=(',', ':'), ensure_ascii=False)

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, LargeBinary, String, UniqueConstraint, create_engine, event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

SCHEMA_VERSION = 1
DEFAULT_DATABASE = Path('cache/threats.db')


class Base(DeclarativeBase):
    pass


class ImportInfo(Base):
    __tablename__ = 'import_info'
    id: Mapped[int] = mapped_column(primary_key=True)
    schema_version: Mapped[int]
    decoder_version: Mapped[str]
    signature_version: Mapped[str]
    engine_version: Mapped[str | None]
    converted_at: Mapped[datetime] = mapped_column(DateTime)
    raw_included: Mapped[bool] = mapped_column(Boolean)


class Source(Base):
    __tablename__ = 'source'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    base_filename: Mapped[str]
    delta_filename: Mapped[str | None]
    effective_version: Mapped[str]
    stream_size: Mapped[int]
    stream_sha256: Mapped[str]


class DbThreat(Base):
    __tablename__ = 'threat'
    __table_args__ = (UniqueConstraint('source_id', 'begin_offset'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey('source.id'))
    begin_offset: Mapped[int]
    defender_id: Mapped[int]
    name: Mapped[str] = mapped_column(String, index=True)
    category_id: Mapped[int]
    severity_id: Mapped[int | None]
    type: Mapped[str]
    platform: Mapped[str]
    family: Mapped[str]
    variant: Mapped[str]
    suffixes: Mapped[list] = mapped_column(JSON)
    signature_count: Mapped[int]
    generated: Mapped[dict] = mapped_column(JSON)


class Signature(Base):
    __tablename__ = 'signature'
    __table_args__ = (UniqueConstraint('source_id', 'offset'), Index('signature_threat_order', 'threat_id', 'offset'))
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey('source.id'))
    threat_id: Mapped[int | None] = mapped_column(ForeignKey('threat.id'))
    offset: Mapped[int]
    role: Mapped[str]
    type_id: Mapped[int]
    payload_size: Mapped[int]
    header_size: Mapped[int]
    record_size: Mapped[int]
    decode_status: Mapped[str]
    details_version: Mapped[int]
    details: Mapped[dict] = mapped_column(JSON)


class RawRecord(Base):
    __tablename__ = 'raw_record'
    signature_id: Mapped[int] = mapped_column(ForeignKey('signature.id'), primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary)


def database_engine(path=DEFAULT_DATABASE, *, readonly=False):
    path = Path(path).resolve()
    if readonly:
        uri = path.as_uri() + '?mode=ro'
        engine = create_engine('sqlite://', creator=lambda: sqlite3.connect(uri, uri=True))
    else:
        engine = create_engine('sqlite:///' + str(path),
                               json_serializer=_JSON_ENCODER.encode)

    @event.listens_for(engine, 'connect')
    def configure(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')

    return engine


@contextmanager
def read_session(path=DEFAULT_DATABASE):
    engine = database_engine(path, readonly=True)
    try:
        with Session(engine) as session:
            try:
                metadata = session.scalar(select(ImportInfo).where(ImportInfo.id == 1))
            except OperationalError as error:
                raise ValueError('Unsupported database; rebuild with --convert.') from error
            if metadata is None or metadata.schema_version != SCHEMA_VERSION:
                raise ValueError('Unsupported database schema; rebuild with --convert.')
            yield session
    finally:
        engine.dispose()
