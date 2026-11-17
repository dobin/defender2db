from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
import io
from pathlib import Path
import shutil
import unittest
from uuid import uuid4

from sqlalchemy import insert

from defender2yara.defender.dbthreat import (
    Base, DbThreat, ImportInfo, SCHEMA_VERSION, Source, database_engine,
)
from tools.dbtest import main as dbtest_main
from tools.yaraview import main


class YaraViewTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / ('.yaraview-' + uuid4().hex)
        self.directory.mkdir()
        self.addCleanup(shutil.rmtree, self.directory)
        self.database = self.directory / 'threats.db'
        engine = database_engine(self.database)
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(insert(ImportInfo), dict(
                id=1, schema_version=SCHEMA_VERSION, decoder_version='test',
                signature_version='test', engine_version=None,
                converted_at=datetime.now(), raw_included=False,
            ))
            connection.execute(insert(Source), dict(
                id=1, name='mpav', base_filename='test.vdm', delta_filename=None,
                effective_version='test', stream_size=0, stream_sha256='0' * 64,
            ))
            for row_id, name, rules in (
                (1, 'Empty', []),
                (2, 'Trojan:Example', ['rule first { condition: true }', 'rule second { condition: false }']),
                (3, 'Other', ['rule third { condition: true }']),
            ):
                connection.execute(insert(DbThreat), dict(
                    id=row_id, source_id=1, begin_offset=row_id, defender_id=100 + row_id,
                    name=name, category_id=0, severity_id=None, type='', platform='',
                    family='', variant='', suffixes=[], signature_count=0,
                    generated={'yara': {'status': 'ok' if rules else 'empty', 'items': rules},
                               'lua': {'status': 'empty', 'items': []}},
                ))
        engine.dispose()

    def run_view(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(['--db', str(self.database), *args]), 0)
        return output.getvalue()

    def test_default_and_rule_limit(self):
        self.assertIn('rule third', self.run_view())
        output = self.run_view('--limit', '1', '--check')
        self.assertIn('rule first', output)
        self.assertNotIn('rule second', output)

    def test_filters_and_listing(self):
        output = self.run_view('--name', 'EXAMPLE', '--list')
        self.assertIn('row_id=2 threat_id=102 rules=2', output)
        self.assertNotIn('rule first', output)
        self.assertIn('rule third', self.run_view('--row-id', '3'))
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_view('--name', "' OR 1=1 --"), '')

    def test_missing_database_is_not_created(self):
        missing = self.directory / 'missing.db'
        for reader in (main, dbtest_main):
            with self.subTest(reader=reader.__module__):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    reader(['--db', str(missing)])
                self.assertEqual(error.exception.code, 1)
                self.assertFalse(missing.exists())

    def test_unsupported_schema_is_rejected(self):
        engine = database_engine(self.database)
        try:
            with engine.begin() as connection:
                connection.execute(ImportInfo.__table__.update().values(schema_version=SCHEMA_VERSION + 1))
        finally:
            engine.dispose()
        with redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit):
            main(['--db', str(self.database)])
        self.assertIn('rebuild', errors.getvalue())

    def test_dbtest_reads_json_generation_status(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(dbtest_main(['--db', str(self.database)]), 0)
        self.assertIn('Local ID: 2; Source ID: 1; Defender ID: 102', output.getvalue())
        self.assertIn('YARA: 2 items; status=ok', output.getvalue())

    def web_client(self):
        from flask import Flask
        from app.views import views

        app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'app' / 'templates'))
        app.config.update(TESTING=True, DATABASE=self.database)
        app.register_blueprint(views)
        return app.test_client()

    def add_signature(self, *, raw=False):
        from defender2yara.defender.dbthreat import RawRecord, Signature

        engine = database_engine(self.database)
        try:
            with engine.begin() as connection:
                connection.execute(insert(Signature), dict(
                    id=34, source_id=1, threat_id=2, offset=100, role='signature',
                    type_id=0x67, payload_size=4, header_size=4, record_size=8,
                    decode_status='partial', details_version=1,
                    details={'record_name': '<script>alert(1)</script>', 'file_size': 123,
                             'flags': 1, 'hash_type': 'md5', 'file_hash_hex': 'abcd',
                             'prefix_match': True, 'partial_crc1': 1, 'partial_crc2': 2,
                             'partial_crc3': 3, 'future_field': {'nested': True}},
                ))
                if raw:
                    connection.execute(ImportInfo.__table__.update().values(raw_included=True))
                    connection.execute(insert(RawRecord), dict(signature_id=34, data=b'\x00\x01raw'))
        finally:
            engine.dispose()

    def test_web_local_ids_json_sections_and_escaping(self):
        self.add_signature()
        client = self.web_client()
        self.assertEqual(client.get('/').status_code, 200)
        search = client.get('/search?threat_name=EXAMPLE')
        self.assertIn(b'/threat/2', search.data)
        response = client.get('/threat/2')
        self.assertEqual(response.status_code, 200)
        for text in (b'Static file signatures', b'future_field',
                     b'Partially decoded', b'Raw record unavailable', b'rule first'):
            self.assertIn(text, response.data)
        self.assertNotIn(b'<script>alert(1)</script>', response.data)
        self.assertNotIn(b'Offsets refer to the effective', response.data)
        self.assertNotIn(b'Rebuild using', response.data)
        self.assertIn(b'threat-heading', response.data)
        self.assertIn(b'CRC32 of the first min(N, 64 KiB) bytes', response.data)
        self.assertIn(b'prefix match (0x0001)', response.data)
        self.assertIn(b'CRC32 of the first min(N, 64 KiB) bytes', response.data)
        details = client.get('/api/threats/2').get_json()
        self.assertEqual(details['defender_id'], 102)
        self.assertEqual(details['signatures'][0]['id'], 34)
        self.assertNotIn('data_hex', details['signatures'][0])
        self.assertEqual(client.get('/api/signatures/34').get_json()['details']['file_size'], 123)
        self.assertEqual(client.get('/api/signatures/34/raw').status_code, 409)
        self.assertEqual(client.get('/api/threats').status_code, 400)
        for path in ('/threat/999', '/api/threats/999', '/api/signatures/999', '/api/signatures/999/raw'):
            self.assertEqual(client.get(path).status_code, 404)

    def test_web_type_specific_json_sections(self):
        from unittest.mock import patch
        from defender2yara.threat_api import get_threat_details

        threat = get_threat_details(2, database=self.database)
        cases = [
            ('DEXHSTR_EXT', {'threshold': 4, 'subrules': [{'rule_weight': 2, 'rule_bytes_hex': '616263', 'text': 'abc'}]}),
            ('AAGGREGATOR', {'expression': 'name1 AND name2', 'references': ['name1', 'name2']}),
            ('AAGGREGATOREX', {'expression': 'extended expression'}),
            ('VERSIONCHECK', {'check_id': 2, 'value': 3, 'description': 'test gate'}),
            ('SIGTREE', {'edges': [{'x': 1, 'conditions': [{'side': 'left', 'kind': 'pattern', 'text': 'condition text'}]}]}),
            ('SIGTREE_BM', {'edges': [{'x': 2}]}),
            ('NID64', {'record_key_hex': 'ffffffffffffffff', 'record_kind': 1, 'description': 'reference description'}),
            ('SNID', {'record_key_hex': 'aa' * 20, 'record_sig_type': 'STATIC'}),
            ('REVOKED_CERTIFICATE', {'thumbprint_hex': 'bb' * 20}),
            ('UNKNOWN', {}),
        ]
        threat['signatures'] = [dict(
            id=index, type='SIGNATURE_TYPE_' + kind, source_id=1, offset=index,
            size=0, role='signature', decode_status='decoded' if details else 'unsupported',
            details_version=1, details=details, raw_available=False,
        ) for index, (kind, details) in enumerate(cases, 1)]
        with patch('app.views.get_threat_details', return_value=threat):
            response = self.web_client().get('/threat/2')
        self.assertEqual(response.status_code, 200)
        for text in (b'DEX string signatures', b'abc', b'Aggregator expressions',
                     b'name1 AND name2', b'test gate', b'condition text',
                     b'ffffffffffffffff', b'No decoder is available'):
            self.assertIn(text, response.data)
        self.assertIn(b'A NID is a reference, not a detection', response.data)
        self.assertIn(b'What is a NID?', response.data)
        self.assertIn(b'An SNID refers to a shared signature record', response.data)
        self.assertIn(b'signature-card-dexhstr_ext', response.data)
        self.assertIn(b'Behavior signature tree (BM)', response.data)
        self.assertIn(b'Extended aggregator', response.data)

    def test_web_raw_download_is_explicit(self):
        self.add_signature(raw=True)
        client = self.web_client()
        page = client.get('/threat/2')
        self.assertIn(b'/api/signatures/34/raw', page.data)
        response = client.get('/api/signatures/34/raw')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'\x00\x01raw')
        self.assertEqual(response.mimetype, 'application/octet-stream')
        self.assertIn('attachment', response.headers['Content-Disposition'])

    def test_invalid_limit(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['--limit', '0'])

    def test_list_rejects_compile(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['--list', '--check'])
