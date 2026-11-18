"""Small read-only queries shared by HTML, REST, MCP and command-line tools."""

from sqlalchemy import select

from defender2yara.defender.constant import SIG_TYPES
from defender2yara.defender.dbthreat import DEFAULT_DATABASE, DbThreat, ImportInfo, RawRecord, Signature, read_session
from defender2yara.defender.signature.sigtree import SIGTREE_TYPE_IDS, enrich_sigtree_details
from defender2yara.defender.threat import SEVERITY_MAP


class RawUnavailableError(ValueError):
    pass


# SIGNATURE_TYPE_NID64.  Its key is often a packed engine record id, which can
# be resolved back to a shipped record through ``Signature.record_id``.
NID64_TYPE_ID = 0xCE


class RecordIdResolver:
    """Resolve packed engine record ids to the records shipped in a database.

    Old databases (built before the ``record_id`` column existed) are opened in
    degraded mode: resolution reports ``unavailable`` instead of failing.
    """

    # Keep ``IN (...)`` lists well below SQLite's bound-variable limit.
    CHUNK_SIZE = 500

    def __init__(self, session):
        self.session = session
        self._available = None
        self._cache = {}

    @property
    def available(self) -> bool:
        if self._available is None:
            columns = self.session.connection().exec_driver_sql(
                'PRAGMA table_info(signature)').all()
            self._available = any(column[1] == 'record_id' for column in columns)
        return self._available

    def prepare(self, record_keys) -> None:
        """Resolve many keys with a few indexed ``IN`` queries.

        A threat page can contain thousands of NID64 references, so resolving
        them one by one is needlessly slow.  Results are cached per key.
        """
        wanted = {key for key in record_keys if key not in self._cache}
        if not wanted:
            return
        if not self.available:
            for key in wanted:
                self._cache[key] = {'status': 'unavailable'}
            return

        keys = sorted(wanted)
        for start in range(0, len(keys), self.CHUNK_SIZE):
            chunk = keys[start:start + self.CHUNK_SIZE]
            rows = self.session.execute(
                select(Signature.record_id, Signature.id, Signature.threat_id,
                       Signature.role, Signature.type_id, Signature.payload_size,
                       DbThreat.name)
                .join(DbThreat, DbThreat.id == Signature.threat_id, isouter=True)
                .where(Signature.record_id.in_(chunk))
                .order_by(Signature.id)
            ).all()
            found = {}
            for row in rows:
                found.setdefault(row.record_id, {
                    'status': 'resolved',
                    'signature_id': row.id,
                    'threat_id': row.threat_id,
                    'threat_name': row.name,
                    'role': row.role,
                    'type_id': row.type_id,
                    'type': SIG_TYPES.get(row.type_id, f'UNKNOWN(0x{row.type_id:02x})'),
                    'payload_size': row.payload_size,
                })
            for key in chunk:
                self._cache[key] = found.get(key, {'status': 'not_shipped'})

    def resolve(self, record_key: int) -> dict:
        self.prepare((record_key,))
        return self._cache[record_key]


def search_threats(threat_name: str, database=DEFAULT_DATABASE) -> list[dict]:
    with read_session(database) as session:
        rows = session.execute(select(DbThreat.id, DbThreat.name, DbThreat.source_id,
                                      DbThreat.defender_id, DbThreat.signature_count)
                               .where(DbThreat.name.contains(threat_name, autoescape=True))
                               .order_by(DbThreat.id))
        return [dict(row._mapping) for row in rows]


def signature_details(row, raw_available, resolver=None):
    details = row.details
    if row.type_id in SIGTREE_TYPE_IDS:
        details = enrich_sigtree_details(details)
    if (row.type_id == NID64_TYPE_ID and isinstance(details, dict)
            and details.get('has_record_id_layout')
            and details.get('record_key_hex')):
        details = dict(details)
        details['referenced_record'] = (
            resolver.resolve(int(details['record_key_hex'], 16))
            if resolver is not None else {'status': 'unavailable'}
        )
    return {
        'id': row.id, 'source_id': row.source_id, 'threat_id': row.threat_id,
        'offset': row.offset, 'type_id': row.type_id, 'type': SIG_TYPES[row.type_id],
        'size': row.payload_size, 'header_size': row.header_size, 'record_size': row.record_size,
        'role': row.role, 'decode_status': row.decode_status,
        'details_version': row.details_version, 'details': details,
        'raw_available': raw_available,
    }


def get_threat_details(threat_id: int, database=DEFAULT_DATABASE) -> dict:
    with read_session(database) as session:
        row = session.get(DbThreat, threat_id)
        if row is None:
            raise LookupError('Threat not found.')
        raw_available = session.get(ImportInfo, 1).raw_included
        result = {column.name: getattr(row, column.name) for column in DbThreat.__table__.columns}
        result['severity'] = SEVERITY_MAP.get(row.severity_id, row.severity_id)
        result['raw_available'] = raw_available
        resolver = RecordIdResolver(session)
        signatures = list(session.scalars(
            select(Signature).where(Signature.threat_id == threat_id, Signature.role == 'signature')
            .order_by(Signature.offset)))
        resolver.prepare(
            int(sig.details['record_key_hex'], 16) for sig in signatures
            if sig.type_id == NID64_TYPE_ID and isinstance(sig.details, dict)
            and sig.details.get('has_record_id_layout')
            and sig.details.get('record_key_hex'))
        result['signatures'] = [signature_details(sig, raw_available, resolver)
                                for sig in signatures]
        result['boundary_ids'] = list(session.scalars(select(Signature.id).where(
            Signature.threat_id == threat_id, Signature.role.in_(['threat_begin', 'threat_end']))
            .order_by(Signature.offset)))
        return result


def get_signature_details(signature_id: int, database=DEFAULT_DATABASE) -> dict:
    with read_session(database) as session:
        row = session.get(Signature, signature_id)
        if row is None:
            raise LookupError('Signature not found.')
        return signature_details(row, session.get(ImportInfo, 1).raw_included,
                                 RecordIdResolver(session))


def get_raw_record(signature_id: int, database=DEFAULT_DATABASE) -> bytes:
    with read_session(database) as session:
        if session.get(Signature, signature_id) is None:
            raise LookupError('Signature not found.')
        if not session.get(ImportInfo, 1).raw_included:
            raise RawUnavailableError('Raw records were omitted; rebuild with --include-raw.')
        data = session.scalar(select(RawRecord.data).where(RawRecord.signature_id == signature_id))
        if data is None:
            raise ValueError('Database has incomplete raw capture; rebuild it.')
        return data
