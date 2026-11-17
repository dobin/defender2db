"""Small read-only queries shared by HTML, REST, MCP and command-line tools."""

from sqlalchemy import select

from defender2yara.defender.constant import SIG_TYPES
from defender2yara.defender.dbthreat import DEFAULT_DATABASE, DbThreat, ImportInfo, RawRecord, Signature, read_session
from defender2yara.defender.signature.sigtree import SIGTREE_TYPE_IDS, enrich_sigtree_details
from defender2yara.defender.threat import SEVERITY_MAP


class RawUnavailableError(ValueError):
    pass


def search_threats(threat_name: str, database=DEFAULT_DATABASE) -> list[dict]:
    with read_session(database) as session:
        rows = session.execute(select(DbThreat.id, DbThreat.name, DbThreat.source_id,
                                      DbThreat.defender_id, DbThreat.signature_count)
                               .where(DbThreat.name.contains(threat_name, autoescape=True))
                               .order_by(DbThreat.id))
        return [dict(row._mapping) for row in rows]


def signature_details(row, raw_available):
    details = row.details
    if row.type_id in SIGTREE_TYPE_IDS:
        details = enrich_sigtree_details(details)
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
        result['signatures'] = [signature_details(sig, raw_available) for sig in session.scalars(
            select(Signature).where(Signature.threat_id == threat_id, Signature.role == 'signature')
            .order_by(Signature.offset))]
        result['boundary_ids'] = list(session.scalars(select(Signature.id).where(
            Signature.threat_id == threat_id, Signature.role.in_(['threat_begin', 'threat_end']))
            .order_by(Signature.offset)))
        return result


def get_signature_details(signature_id: int, database=DEFAULT_DATABASE) -> dict:
    with read_session(database) as session:
        row = session.get(Signature, signature_id)
        if row is None:
            raise LookupError('Signature not found.')
        return signature_details(row, session.get(ImportInfo, 1).raw_included)


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
