import pickle
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from flask import Flask
from peewee import SqliteDatabase

from app.views import views
from defender2yara.defender.dbthreat import DbThreat, NiceThreat
from defender2yara.defender.signature.aggregator import encode_aggregator
from defender2yara.defender.signature.base import BaseSig
from defender2yara.defender.signature.threat import ThreatBeginSig
from defender2yara.defender.signature.static import StaticSig
from defender2yara.defender.threat import Threat
from defender2yara.defender.vdm import Vdm


def tlv(type_id, payload):
    return bytes([type_id]) + len(payload).to_bytes(3, 'little') + payload


def sample_threat(parsed=True):
    name = b'Test:Win32/Example.A'
    begin = struct.pack('<IIHBB', 123, 0, 1, len(name), 0) + name + b'\x00' * 4 + b'\x04'
    threat = Threat(ThreatBeginSig(tlv(0x5C, begin)))
    expression = encode_aggregator(b'HSTR:Example&SIGATTR:Example')
    records = [
        tlv(0xBE, bytes.fromhex('0100010001000001000401583535350000')),
        tlv(0xE7, struct.pack('<BBH', 0, 0, len(expression)) + expression),
        tlv(0x7A, struct.pack('<II', 0x26, 17763)),
        tlv(0xB3, bytes.fromhex('0200010200024102000040000d86cb0e4000000000024102000140000d86cb0e4000000000')),
        tlv(0x55, bytes.fromhex('430fd0117c') + b'<script>alert(1)</script>\x00'),
        tlv(0x78, bytes.fromhex('0100010001000001000401583535350000')),
    ]
    for data in records:
        threat.add_signature(Vdm.parse_database(data)[0] if parsed else BaseSig(data))
    return threat


class NiceThreatTests(unittest.TestCase):
    def test_persisted_collections_and_existing_data(self):
        source = sample_threat()
        threat = NiceThreat(source)
        threat.lua_scripts = [b'print("example")']
        threat.yara_rules = ['rule example { condition: true }']
        restored = pickle.loads(pickle.dumps(threat))
        for field in ('dexhstr_signatures', 'aggregator_signatures', 'version_checks',
                      'behavior_signatures', 'nid_signatures', 'pehstr_signatures'):
            self.assertEqual(len(getattr(restored, field)), 1)
        self.assertIs(threat.dexhstr_signatures[0], source.signatures[0])
        self.assertEqual(restored.aggregator_signatures[0].expression, 'HSTR:Example&SIGATTR:Example')
        self.assertEqual(restored.version_checks[0].describe(), 'os_build < 0x4563')
        self.assertEqual(restored.lua_scripts, threat.lua_scripts)
        self.assertEqual(restored.yara_rules, threat.yara_rules)
        self.assertEqual(len(restored.signatures), 6)

    def test_legacy_pickle_rebuilds_typed_collections(self):
        threat = NiceThreat(sample_threat(parsed=False))
        for field in ('dexhstr_signatures', 'aggregator_signatures', 'version_checks',
                      'behavior_signatures', 'nid_signatures', 'static_signatures',
                      'pehstr_signatures', 'revoked_certs'):
            delattr(threat, field)
        restored = pickle.loads(pickle.dumps(threat))
        self.assertEqual(restored.pehstr_signatures[0].subrules[0].rule_bytes, b'X555')
        self.assertEqual(restored.behavior_signatures[0].edge_count, 2)

    def test_legacy_parser_instances_are_refreshed(self):
        threat = NiceThreat(sample_threat())
        del threat.pehstr_signatures[0].name
        for field in ('dexhstr_signatures', 'aggregator_signatures', 'version_checks',
                      'behavior_signatures', 'nid_signatures', 'static_signatures',
                      'pehstr_signatures', 'revoked_certs'):
            delattr(threat, field)
        restored = pickle.loads(pickle.dumps(threat))
        self.assertEqual(restored.pehstr_signatures[0].name, '')

    def test_ui_and_api_preserve_data_and_escape_text(self):
        database = SqliteDatabase(':memory:')
        root = Path(__file__).resolve().parents[1]
        app = Flask(__name__, template_folder=str(root / 'app' / 'templates'))
        app.register_blueprint(views)
        with database.bind_ctx([DbThreat]):
            database.create_tables([DbThreat])
            source = sample_threat()
            static_payload = struct.pack('<IIIIH', 1, 2, 3, 4096, 1) + b'\x11' * 16 + b'\x06#Clean'
            source.add_signature(Vdm.parse_database(tlv(0x67, static_payload))[0])
            threat = NiceThreat(source)
            threat.lua_scripts = [b'print("example")']
            threat.yara_rules = ['rule example { condition: true }']
            DbThreat.create(name=threat.name, sigs='test', sigcount=7, threatObject=pickle.dumps(threat))
            response = app.test_client().get('/threat', query_string={'name': threat.name})
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            for text in ('DEX string signatures', 'PE extended string signatures',
                         'HSTR:Example&amp;SIGATTR:Example', 'os_build &lt; 0x4563',
                         'No inline conditions', 'X555', 'rule example', 'print(',
                         'Static file signatures', '#Clean', 'MD5', 'Prefix match',
                         'Partial CRC 1', '00000001'):
                self.assertIn(text, html)
            self.assertIn('&lt;script&gt;', html)
            self.assertNotIn('<script>alert(1)</script>', html)
            self.assertIn('threat-overview-grid', html)
            self.assertIn('threat-signature-summary', html)
            self.assertNotIn('threat-counts-table', html)
            self.assertIn('Signature counts', html)
            for sig_type in ('AAGGREGATOREX', 'DEXHSTR_EXT', 'VERSIONCHECK',
                             'SIGTREE_BM', 'NID', 'PEHSTR_EXT'):
                self.assertIn(sig_type, html)
            self.assertIn('Aggregator expressions', html)
            self.assertIn('<strong>ID</strong> 123', html)
            self.assertIn('Test:Win32/Example.A', html)
            self.assertIn('Severity', html)
            details = app.test_client().get('/api/threat', query_string={'name': threat.name}).get_json()
            self.assertEqual(len(details['signatures']), 7)
            self.assertEqual(details['lua_scripts'], ['print("example")'])
        database.close()

    def test_malformed_record_remains_visible_as_raw_data(self):
        source = sample_threat()
        source.add_signature(BaseSig(tlv(0xBE, b'bad')))
        with self.assertLogs('defender2yara.defender.dbthreat', level='WARNING'):
            threat = NiceThreat(source)
        self.assertEqual(len(threat.dexhstr_signatures), 1)
        app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'app' / 'templates'))
        app.register_blueprint(views)
        with patch.object(DbThreat, 'get', return_value=type('Row', (), {'threatObject': pickle.dumps(threat)})()):
            html = app.test_client().get('/threat?name=example').get_data(as_text=True)
        self.assertIn('62 61 64', html)


if __name__ == '__main__':
    unittest.main()
