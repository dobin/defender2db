"""Bulk persistence of one parsed VDM source into an unpublished import."""

import hashlib
import logging
import time
import json
from collections import Counter
from sqlalchemy import insert, func, select
from tqdm import tqdm

BATCH_SIZE = 5000
_JSON_ENCODER = json.JSONEncoder(separators=(',', ':'), ensure_ascii=False)


def _insert_records(connection, signature_rows, raw_rows):
    # Positional executemany avoids SQLAlchemy's per-row mapping/bind processing
    # on the multi-million-record hot path, within the same managed transaction.
    connection.exec_driver_sql(
        'INSERT INTO signature (id,source_id,threat_id,offset,role,type_id,payload_size,'
        'record_id,header_size,record_size,decode_status,details_version,details) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', signature_rows)
    if raw_rows:
        connection.exec_driver_sql('INSERT INTO raw_record (signature_id,data) VALUES (?,?)', raw_rows)

from defender2yara.defender.dbthreat import DbThreat, Signature, Source
from defender2yara.defender.signature.record_id import packed_record_id


def store_source(connection, vdm, *, include_raw, generate):
    started = time.perf_counter()
    logger = logging.getLogger(__name__)
    logger.info('Converting %s: %d threats, %d records, raw=%s',
                vdm.vdm_type, len(vdm.get_threats()), len(vdm.get_signatures()), include_raw)
    source_id = (connection.scalar(select(func.max(Source.id))) or 0) + 1
    threat_id = connection.scalar(select(func.max(DbThreat.id))) or 0
    signature_id = connection.scalar(select(func.max(Signature.id))) or 0
    connection.execute(insert(Source), [{
        'id': source_id, 'name': vdm.vdm_type, 'base_filename': vdm.base_path,
        'delta_filename': vdm.delta_path or None, 'effective_version': vdm.version,
        'stream_size': len(vdm.raw_data),
        'stream_sha256': hashlib.sha256(vdm.raw_data).hexdigest(),
    }])
    # Only completed parser threats own records; incomplete/orphan groups stay global.
    ownership = []
    threat_rows = []
    for threat in tqdm(vdm.get_threats(), desc='Generating threat output', unit='threat', leave=False):
        threat_id += 1
        begin = threat.threat_begin_sig
        end = threat.threat_end_sig
        ownership.append((begin.offset, end.offset, threat_id))
        threat_rows.append({
            'id': threat_id, 'source_id': source_id, 'begin_offset': begin.offset,
            'defender_id': threat.threat_id, 'name': threat.threat_name,
            'category_id': threat.category_id, 'severity_id': begin.severity_id,
            'type': threat.threat_type, 'platform': threat.threat_platform,
            'family': threat.threat_family, 'variant': threat.threat_variant,
            'suffixes': threat.threat_suffixes, 'signature_count': len(threat.signatures),
            'generated': generate(threat),
        })
        if len(threat_rows) >= BATCH_SIZE:
            connection.execute(insert(DbThreat), threat_rows)
            threat_rows.clear()
    if threat_rows:
        connection.execute(insert(DbThreat), threat_rows)

    signature_rows, raw_rows = [], []
    decode_errors = Counter()
    intervals = iter(ownership)
    interval = next(intervals, None)
    for sig in tqdm(vdm.get_signatures(), desc='Writing signature batches', unit='record', leave=False):
        signature_id += 1
        while interval is not None and sig.offset > interval[1]:
            interval = next(intervals, None)
        owner = interval[2] if interval is not None and interval[0] <= sig.offset <= interval[1] else None
        role = {0x5c: 'threat_begin', 0x5d: 'threat_end'}.get(sig.sig_type_id, 'signature' if owner else 'global')
        details = sig.to_details()
        error = getattr(sig, 'decode_error', None)
        if error is not None:
            decode_errors[(sig.sig_type, sig.sig_type_id)] += 1
            details = {'error': error}
        signature_rows.append((
            signature_id, source_id, owner, sig.offset, role, sig.sig_type_id,
            sig.size, packed_record_id(sig.sig_data, sig.sig_type_id),
            sig.header_size, sig.record_size,
            'error' if error is not None else sig.decode_status,
            sig.details_version, _JSON_ENCODER.encode(details),
        ))
        if include_raw:
            raw_rows.append((signature_id, vdm.raw_data[sig.offset:sig.offset + sig.record_size]))
        if len(signature_rows) >= BATCH_SIZE:
            _insert_records(connection, signature_rows, raw_rows)
            signature_rows.clear()
            raw_rows.clear()
    if signature_rows:
        _insert_records(connection, signature_rows, raw_rows)
    logger.info('Stored %s in %.1f seconds', vdm.vdm_type, time.perf_counter() - started)
    return decode_errors
