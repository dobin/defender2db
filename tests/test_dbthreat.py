import hashlib
import json
from collections import Counter
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from flask import Flask
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import OperationalError

from app.views import views
from defender2yara.conversion import store_source
from defender2yara.database_build import build_database
from defender2yara.defender.dbthreat import (
    DbThreat, ImportInfo, RawRecord, Signature, Source, database_engine, read_session,
)
from defender2yara.defender.signature.aggregator import encode_aggregator
from defender2yara.defender.vdm import Vdm
from defender2yara.threat_api import (
    RawUnavailableError, get_raw_record, get_signature_details, get_threat_details,
    search_threats,
)


NAME = 'Test:Win32/Example.A!ml'
REFERENCE_KEY = 0xFEDCBA9876543210
GENERATED = {
    'yara': {'status': 'ok', 'items': ['rule example { condition: true }']},
    'lua': {'status': 'partial', 'items': ['print("<example>")'],
            'diagnostics': [{'offset': 17, 'status': 'error', 'message': 'example'}]},
}


def tlv(type_id, payload=b'', *, extended=False):
    header = bytes([type_id])
    header += b'\xff\xff\xff' + struct.pack('<I', len(payload)) if extended else len(payload).to_bytes(3, 'little')
    return header + payload


def threat_records(records, *, name=NAME, defender_id=123):
    encoded_name = name.encode()
    begin = (struct.pack('<IIHBB', defender_id, 0, 1, len(encoded_name), 0)
             + encoded_name + b'\x00' * 4 + b'\x04')
    return [tlv(0x5C, begin), *records, tlv(0x5D, struct.pack('<I', defender_id))]


def sample_records():
    expression = encode_aggregator(b'HSTR:Example&SIGATTR:Example')
    tree = (b'\x01\x00\x00\x02\x00'
            + struct.pack('<IIII', 0x1000, 3 << 24, 7, 9) + b'abc')
    return [
        tlv(0, b'global\x00\xff', extended=True),
        *threat_records([
            tlv(0xBE, bytes.fromhex('0100010001000001000401583535350000')),
            tlv(0xE7, struct.pack('<BBH', 0, 0, len(expression)) + expression),
            tlv(0x7A, struct.pack('<II', 0x26, 17763)),
            tlv(0xB3, tree),
            tlv(0xCE, struct.pack('<QB', REFERENCE_KEY, 0x84) + b'#Publisher\x00'),
            tlv(0x7E, b'\x11' * 20 + b'\xe7' + b'!#Shared\x00'),
            tlv(0, b''),
            tlv(0xBE, b'bad'),
        ]),
        tlv(0, b'global-after'),
    ]


def synthetic_vdm(records=None, *, source='anti-virus', delta=True):
    vdm = Vdm.__new__(Vdm)
    vdm.base_path = 'mpavbase.vdm' if source == 'anti-virus' else 'mpasbase.vdm'
    vdm.delta_path = 'mpavdlta.vdm' if delta else ''
    vdm.vdm_type = source
    vdm.version = '1.463.330.0'
    vdm.raw_data = b''.join(sample_records() if records is None else records)
    vdm.signatures = Vdm.parse_database(vdm.raw_data)
    vdm.threats = Vdm.parse_threats(vdm.signatures)
    return vdm


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='dbthreat-tests-', dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'threats.sqlite'

    def publish(self, *, path=None, include_raw=False, sources=None):
        path = path or self.path
        sources = sources if sources is not None else [synthetic_vdm()]
        with build_database(path, signature_version='1.463.330.0',
                            engine_version='1.1.26100.4', include_raw=include_raw) as connection:
            for vdm in sources:
                store_source(connection, vdm, include_raw=include_raw, generate=lambda threat: GENERATED)
        return path

    def test_actual_generation_and_mcp_use_json_without_raw(self):
        from defender2yara.main import generate_output
        from defender2yara import mcp_server
        source = synthetic_vdm()
        generated = generate_output(source.threats[0])
        self.assertTrue(generated['yara']['items'])
        self.assertEqual(generated['lua']['status'], 'not_applicable')
        with build_database(self.path, signature_version=source.version,
                            engine_version=None, include_raw=False) as connection:
            store_source(connection, source, include_raw=False, generate=generate_output)
        with patch.object(mcp_server, 'get_threat_details', side_effect=lambda key: get_threat_details(key, self.path)):
            result = mcp_server.get_threat(1)
        self.assertEqual(result['generated'], generated)
        for signature in result['signatures']:
            self.assertNotIn('data_hex', signature)
            self.assertNotIn('sig_data', signature['details'])
        with patch.object(mcp_server, 'get_raw_record', side_effect=lambda key: get_raw_record(key, self.path)):
            with self.assertRaisesRegex(ValueError, '--include-raw'):
                mcp_server.get_raw_signature(1)

    def test_nid64_resolves_packed_record_id_to_shipped_record(self):
        from defender2yara.defender.signature.record_id import packed_record_id

        target = b"\x02\x00\x02\x00payload"
        key = packed_record_id(target, 0x78)
        self.publish(sources=[synthetic_vdm(threat_records([
            tlv(0x78, target),
            tlv(0xCE, key.to_bytes(8, "little") + b"\x67"),
        ]))])

        details = get_threat_details(1, self.path)
        target_row, reference = details["signatures"]
        self.assertEqual(reference["type_id"], 0xCE)
        self.assertEqual(reference["details"]["referenced_record"], {
            "status": "resolved",
            "signature_id": target_row["id"],
            "threat_id": 1,
            "threat_name": NAME,
            "role": "signature",
            "type_id": 0x78,
            "type": "SIGNATURE_TYPE_PEHSTR_EXT",
            "payload_size": len(target),
        })
        self.assertEqual(get_signature_details(reference["id"], self.path)["details"],
                         reference["details"])

        missing = packed_record_id(b"not shipped", 0x78)
        self.publish(path=self.path.with_name("missing.sqlite"), sources=[synthetic_vdm(threat_records([
            tlv(0xCE, missing.to_bytes(8, "little") + b"\x67"),
        ]))])
        unresolved = get_threat_details(1, self.path.with_name("missing.sqlite"))["signatures"][0]
        self.assertEqual(unresolved["details"]["referenced_record"], {"status": "not_shipped"})

    def test_database_without_record_ids_still_reads(self):
        from defender2yara.defender.signature.record_id import packed_record_id

        key = packed_record_id(b"target", 0x78)
        self.publish(sources=[synthetic_vdm(threat_records([
            tlv(0xCE, key.to_bytes(8, "little") + b"\x67"),
        ]))])
        engine = database_engine(self.path)
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql('DROP INDEX ix_signature_record_id')
                connection.exec_driver_sql('ALTER TABLE signature DROP COLUMN record_id')
        finally:
            engine.dispose()
        details = get_threat_details(1, self.path)["signatures"][0]["details"]
        self.assertEqual(details["referenced_record"], {"status": "unavailable"})

    def test_raw_capture_includes_every_exact_tlv_and_framing(self):
        records = sample_records()
        vdm = synthetic_vdm(records)
        self.publish(include_raw=True, sources=[vdm])
        with read_session(self.path) as session:
            rows = list(session.scalars(select(Signature).order_by(Signature.id)))
            raw = dict(session.execute(select(RawRecord.signature_id, RawRecord.data)).all())
            self.assertEqual(len(rows), len(records))
            offset = 0
            for index, (row, expected) in enumerate(zip(rows, records)):
                with self.subTest(index=index):
                    self.assertEqual(raw[row.id], expected)
                    self.assertEqual(row.offset, offset)
                    self.assertEqual(row.type_id, expected[0])
                    header_size = 8 if expected[1:4] == b'\xff\xff\xff' else 4
                    self.assertEqual(row.header_size, header_size)
                    self.assertEqual(row.payload_size, len(expected) - header_size)
                    self.assertEqual(row.record_size, len(expected))
                    offset += len(expected)
            self.assertEqual(b''.join(raw[row.id] for row in rows), vdm.raw_data)
            self.assertEqual([rows[0].role, rows[1].role, rows[-2].role, rows[-1].role],
                             ['global', 'threat_begin', 'threat_end', 'global'])
            self.assertIsNone(rows[0].threat_id)
            self.assertIsNone(rows[-1].threat_id)
            self.assertEqual({row.threat_id for row in rows[1:-1]}, {1})
            zero = next(row for row in rows if row.payload_size == 0)
            self.assertEqual(raw[zero.id], b'\0\0\0\0')
        for index, record in enumerate(records, 1):
            self.assertEqual(get_raw_record(index, self.path), record)

    def test_raw_on_off_preserves_all_interpreted_rows(self):
        raw_path = self.path.with_name('with-raw.sqlite')
        vdm = synthetic_vdm()
        self.publish(sources=[vdm])
        self.publish(path=raw_path, include_raw=True, sources=[vdm])
        snapshots = []
        for path in (self.path, raw_path):
            with read_session(path) as session:
                snapshot = {}
                for model in (Source, DbThreat, Signature):
                    snapshot[model.__tablename__] = [
                        {column.name: getattr(row, column.name) for column in model.__table__.columns}
                        for row in session.scalars(select(model).order_by(model.id))
                    ]
                snapshots.append(snapshot)
                metadata = session.get(ImportInfo, 1)
                self.assertEqual(metadata.raw_included, path == raw_path)
                self.assertEqual(metadata.signature_version, vdm.version)
                self.assertEqual(metadata.engine_version, '1.1.26100.4')
                self.assertTrue(metadata.decoder_version)
                self.assertIsNotNone(metadata.converted_at)
                self.assertEqual(session.scalar(select(func.count()).select_from(RawRecord)),
                                 len(vdm.signatures) if path == raw_path else 0)
        self.assertEqual(snapshots[0], snapshots[1])
        source = snapshots[0]['source'][0]
        self.assertEqual(source['base_filename'], vdm.base_path)
        self.assertEqual(source['delta_filename'], vdm.delta_path)
        self.assertEqual(source['effective_version'], vdm.version)
        self.assertEqual(source['stream_size'], len(vdm.raw_data))
        self.assertEqual(source['stream_sha256'], hashlib.sha256(vdm.raw_data).hexdigest())
        details = get_threat_details(1, self.path)
        self.assertEqual(details['generated'], GENERATED)
        self.assertEqual(details['suffixes'], ['ml'])
        self.assertEqual(details['severity'], 'High')
        with self.assertRaisesRegex(RawUnavailableError, '--include-raw'):
            get_raw_record(1, self.path)

    def test_nested_typed_details_and_large_reference_survive_json(self):
        self.publish()
        details = get_threat_details(1, self.path)
        signatures = {row['type_id']: row for row in details['signatures'] if row['decode_status'] == 'decoded'}
        dex = signatures[0xBE]['details']
        self.assertEqual(dex['threshold'], 1)
        self.assertEqual(dex['subrules'][0]['rule_weight'], 1)
        self.assertEqual(dex['subrules'][0]['rule_bytes_hex'], b'X555'.hex())
        tree = signatures[0xB3]['details']
        self.assertEqual(tree['edges'][0]['z'], 7)
        condition = tree['edges'][0]['conditions'][0]
        self.assertEqual(condition['side'], 'left')
        self.assertEqual(condition['text'], 'abc')
        self.assertTrue(condition['is_pattern'])
        self.assertEqual(signatures[0xE7]['details']['expression'], 'HSTR:Example&SIGATTR:Example')
        reference = signatures[0xCE]['details']
        self.assertEqual(reference['record_key_hex'], 'fedcba9876543210')
        self.assertEqual(int(reference['record_key_hex'], 16), REFERENCE_KEY)
        self.assertEqual(reference['packed_crc32'], 0x76543210)
        self.assertEqual(reference['record_name'], '#Publisher')
        self.assertEqual(signatures[0x7E]['details']['record_key_hex'], '11' * 20)
        self.assertEqual(signatures[0x7E]['details']['group_name'], '!#Shared')
        self.assertEqual(json.loads(json.dumps(details)), details)

    def test_unsupported_and_failed_decoders_stay_distinguishable(self):
        self.publish(include_raw=True)
        signatures = get_threat_details(1, self.path)['signatures']
        unsupported = next(row for row in signatures if row['type_id'] == 0)
        malformed = next(row for row in signatures if row['decode_status'] == 'error')
        self.assertEqual(unsupported['decode_status'], 'unsupported')
        self.assertEqual(unsupported['details'], {})
        self.assertEqual(malformed['type_id'], 0xBE)
        self.assertIn('error', malformed['details'])
        self.assertTrue(malformed['details']['error'])
        self.assertEqual(get_raw_record(malformed['id'], self.path), tlv(0xBE, b'bad'))
        self.assertEqual(get_signature_details(malformed['id'], self.path), malformed)

    def test_store_source_reports_unparseable_signatures(self):
        source = synthetic_vdm()
        with build_database(self.path, signature_version='1.463.330.0',
                            engine_version='1.1.26100.4', include_raw=False) as connection:
            stats = store_source(connection, source, include_raw=False,
                                 generate=lambda threat: GENERATED)
        self.assertEqual(sum(stats.values()), 1)
        (sig_type, sig_type_id), count = next(iter(stats.items()))
        self.assertEqual(sig_type_id, 0xBE)
        self.assertEqual(sig_type, 'SIGNATURE_TYPE_DEXHSTR_EXT')
        self.assertEqual(count, 1)

    def test_duplicate_names_keep_source_occurrence_and_signature_order(self):
        first = synthetic_vdm(threat_records([tlv(0, b'a'), tlv(0x7A, struct.pack('<II', 0x26, 17763)),
                                             tlv(0, b'b')])
                              + threat_records([tlv(0, b'c')], defender_id=124))
        second = synthetic_vdm(threat_records([tlv(0, b'd')]), source='anti-spyware', delta=False)
        self.publish(sources=[first, second])
        found = search_threats(NAME, self.path)
        self.assertEqual([row['name'] for row in found], [NAME] * 3)
        self.assertEqual([row['id'] for row in found], [1, 2, 3])
        self.assertEqual([row['source_id'] for row in found], [1, 1, 2])
        self.assertEqual([row['defender_id'] for row in found], [123, 124, 123])
        details = get_threat_details(1, self.path)
        self.assertEqual([row['type_id'] for row in details['signatures']], [0, 0x7A, 0])
        self.assertEqual([row['offset'] for row in details['signatures']],
                         [row.offset for row in first.threats[0].signatures])
        self.assertEqual(len(details['boundary_ids']), 2)
        self.assertEqual(details['signature_count'], 3)
        with read_session(self.path) as session:
            self.assertIsNone(session.get(Source, 2).delta_filename)
            self.assertEqual(session.scalar(select(func.count()).select_from(Signature)),
                             len(first.signatures) + len(second.signatures))

    def test_bulk_batches_preserve_ids_ownership_and_all_raw_records(self):
        records = [record for index in range(501)
                   for record in threat_records([tlv(0, struct.pack('<I', index))], defender_id=index)]
        batches = []

        def record_batch(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('INSERT INTO signature '):
                batches.append((executemany, len(parameters)))

        from sqlalchemy.engine import Engine
        event.listen(Engine, 'before_cursor_execute', record_batch)
        try:
            with patch('defender2yara.conversion.BATCH_SIZE', 500):
                self.publish(include_raw=True, sources=[synthetic_vdm(records)])
        finally:
            event.remove(Engine, 'before_cursor_execute', record_batch)
        self.assertEqual(batches, [(True, 500), (True, 500), (True, 500), (True, 3)])
        found = search_threats(NAME, self.path)
        self.assertEqual([row['defender_id'] for row in found], list(range(501)))
        with read_session(self.path) as session:
            rows = list(session.scalars(select(Signature).order_by(Signature.id)))
            captured = list(session.scalars(select(RawRecord.data).order_by(RawRecord.signature_id)))
            self.assertEqual(captured, records)
            self.assertEqual([row.id for row in rows], list(range(1, len(records) + 1)))
            self.assertEqual([row.threat_id for row in rows],
                             [local_id for local_id in range(1, 502) for _ in range(3)])
        self.assertEqual(get_threat_details(501, self.path)['defender_id'], 500)

    def test_read_indexes_built_after_loading_and_json_is_compact(self):
        source = synthetic_vdm()
        with build_database(self.path, signature_version=source.version,
                            engine_version=None, include_raw=False) as connection:
            self.assertNotIn('signature_threat_order',
                             [row[1] for row in connection.exec_driver_sql('PRAGMA index_list(signature)')])
            store_source(connection, source, include_raw=False, generate=lambda _: GENERATED)
        with read_session(self.path) as session:
            indexes = session.execute(text('PRAGMA index_list(signature)')).all()
            self.assertIn('signature_threat_order', [row[1] for row in indexes])
            self.assertIn('ix_signature_record_id', [row[1] for row in indexes])
            encoded = session.scalar(text('SELECT details FROM signature WHERE type_id=190 AND decode_status="decoded"'))
            self.assertNotIn('\": ', encoded)
            self.assertEqual(json.loads(encoded)['subrules'][0]['rule_bytes_hex'], '58353535')

    def test_search_escapes_sql_wildcards(self):
        self.publish(sources=[synthetic_vdm(threat_records([], name='Test_%:Win32/Example.A'))])
        self.assertEqual(len(search_threats('_%', self.path)), 1)
        self.assertEqual(search_threats('absent%', self.path), [])
        self.assertEqual(search_threats("' OR 1=1 --", self.path), [])

    def test_incomplete_and_orphan_records_are_retained_without_false_ownership(self):
        records = [tlv(0x5D, struct.pack('<I', 9)), *threat_records([tlv(0, b'unfinished')])[:-1],
                   *threat_records([tlv(0, b'complete')], defender_id=124),
                   *threat_records([tlv(0, b'trailing')], defender_id=125)[:-1]]
        with self.assertLogs('defender2yara.defender', level='WARNING'):
            vdm = synthetic_vdm(records)
        self.publish(include_raw=True, sources=[vdm])
        self.assertEqual([row['defender_id'] for row in search_threats(NAME, self.path)], [124])
        with read_session(self.path) as session:
            rows = list(session.scalars(select(Signature).order_by(Signature.offset)))
            self.assertEqual(len(rows), len(records))
            self.assertEqual([i for i, row in enumerate(rows) if row.threat_id is not None], [3, 4, 5])
            self.assertEqual(session.scalar(select(func.count()).select_from(RawRecord)), len(records))

    def test_failed_generation_keeps_previous_database_and_cleans_staging(self):
        self.publish(include_raw=True)
        previous = self.path.read_bytes()
        def fail(threat):
            raise RuntimeError('generation failed')
        with self.assertRaisesRegex(RuntimeError, 'generation failed'):
            with build_database(self.path, signature_version='replacement', engine_version=None,
                                include_raw=False) as connection:
                store_source(connection, synthetic_vdm(), include_raw=False, generate=fail)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(get_threat_details(1, self.path)['name'], NAME)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_failed_initial_import_does_not_publish_partial_database(self):
        with self.assertRaisesRegex(RuntimeError, 'interrupted'):
            with build_database(self.path, signature_version='new', engine_version=None,
                                include_raw=False) as connection:
                store_source(connection, synthetic_vdm(), include_raw=False, generate=lambda threat: GENERATED)
                raise RuntimeError('interrupted')
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_incomplete_raw_capture_cannot_be_published(self):
        self.publish()
        previous = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'raw record capture'):
            with build_database(self.path, signature_version='replacement', engine_version=None,
                                include_raw=True) as connection:
                store_source(connection, synthetic_vdm(), include_raw=False, generate=lambda threat: GENERATED)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_failed_replace_keeps_previous_database(self):
        self.publish()
        previous = self.path.read_bytes()
        with patch('defender2yara.database_build.os.replace', side_effect=PermissionError('busy')):
            with self.assertRaisesRegex(PermissionError, 'busy'):
                self.publish(include_raw=True)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_read_only_queries_do_not_create_missing_database(self):
        for query in (lambda: search_threats(NAME, self.path),
                      lambda: get_threat_details(1, self.path),
                      lambda: get_signature_details(1, self.path),
                      lambda: get_raw_record(1, self.path)):
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, 'rebuild'):
                query()
            self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_read_session_is_read_only_and_rejects_unknown_schema(self):
        self.publish()
        with read_session(self.path) as session:
            with self.assertRaises(OperationalError):
                session.execute(text('DELETE FROM threat'))
        engine = database_engine(self.path)
        try:
            with engine.begin() as connection:
                connection.execute(text('UPDATE import_info SET schema_version = 999'))
        finally:
            engine.dispose()
        with self.assertRaisesRegex(ValueError, 'schema.*rebuild'):
            search_threats(NAME, self.path)

    def test_index_shows_configured_rest_and_mcp_endpoints(self):
        from app.views import views
        app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'app' / 'templates'))
        app.config.update(TESTING=True, DATABASE=self.path)
        app.register_blueprint(views)
        self.publish()
        with patch.dict('os.environ', {'DOMAIN': 'https://example.test/'}):
            response = app.test_client().get('/')
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('https://example.test/api/threats?threat_name=...', page)
        self.assertIn('https://example.test/mcp', page)
        self.assertIn('class="card mt-4"', page)

    def test_flask_consumers_address_duplicate_occurrences_without_loading_raw(self):
        vdm = synthetic_vdm(threat_records([tlv(0, b'first')]) + threat_records([tlv(0, b'second')], defender_id=124))
        self.publish(include_raw=True, sources=[vdm])
        app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'app' / 'templates'))
        app.config.update(TESTING=True, DATABASE=self.path)
        app.register_blueprint(views)
        statements = []
        def record_query(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement.lower())
        from sqlalchemy.engine import Engine
        event.listen(Engine, 'before_cursor_execute', record_query)
        try:
            client = app.test_client()
            response = client.get('/api/threats', query_string={'threat_name': NAME})
            self.assertEqual(response.status_code, 200)
            self.assertEqual([row['id'] for row in response.get_json()], [1, 2])
            for local_id, defender_id in ((1, 123), (2, 124)):
                response = client.get(f'/api/threats/{local_id}')
                self.assertEqual(response.status_code, 200)
                details = response.get_json()
                self.assertEqual(details['defender_id'], defender_id)
                self.assertEqual(details['generated'], GENERATED)
                signature_id = details['signatures'][0]['id']
                response = client.get(f'/api/signatures/{signature_id}')
                self.assertEqual(response.get_json(), details['signatures'][0])
                response = client.get(f'/threat/{local_id}')
                self.assertEqual(response.status_code, 200)
                self.assertIn(NAME, response.get_data(as_text=True))
            self.assertFalse(any('raw_record' in statement for statement in statements))
            self.assertEqual(client.get('/api/threats/999').status_code, 404)
            self.assertEqual(client.get('/api/signatures/999').status_code, 404)
        finally:
            event.remove(Engine, 'before_cursor_execute', record_query)


if __name__ == '__main__':
    unittest.main()
