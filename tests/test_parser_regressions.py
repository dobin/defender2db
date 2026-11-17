import itertools
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

import yara

from defender2yara.defender.lua_backend import load_lua_backend, decompile_data
from defender2yara.defender.luaparse import fixup_lua_data
from defender2yara.defender.signature.base import BaseSig
from defender2yara.defender.vdm import Vdm
from defender2yara.main import get_lua_from_threat
from defender2yara.main import main
from defender2yara.yara.condition import YaraCondition
from defender2yara.yara.rule import YaraRule
from defender2yara.yara.strings import YaraString


def make_threat(weights, threshold):
    subrules = [SimpleNamespace(rule_weight=w, rule_bytes=f"token{i}!".encode())
                for i, w in enumerate(weights)]
    sig = SimpleNamespace(threshold=threshold, sig_type="SIGNATURE_TYPE_PEHSTR", subrules=subrules)
    return SimpleNamespace(
        threat_type="", threat_platform="", threat_family="", threat_variant="",
        threat_name="123:test (name)", threat_id=123, severity=0,
        threat_suffixes=[], hstr_signatures=[sig], signatures=[],
    )


def mplua_chunk():
    # A stripped function returning a 64-bit integer, without a C Lua compiler.
    header = b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'
    loadk = 1  # LOADK R0, K0
    ret = 30 | (2 << 23)  # RETURN R0, 2 (one return value)
    return (header + b'\0' * 12 + bytes([0, 0, 2, 2])
            + struct.pack('<III', 2, loadk, ret)
            + struct.pack('<IBq', 1, 3, 9007199254740993)
            + struct.pack('<IIII', 0, 0, 0, 0))


class WeightedRulesTests(unittest.TestCase):
    def test_signed_presence_scoring(self):
        for weights in ([2, 3], [10, -1], [5, -8, 4], [-2, -3], [0, 4], [1, 1, 1]):
            for threshold in (0, 1, 5, 6, 15):
                source = next(YaraRule(make_threat(weights, threshold), "").generate_rules())
                compiled = yara.compile(source=source)
                for present in itertools.product((False, True), repeat=len(weights)):
                    data = b' '.join(f"token{i}!".encode() for i, flag in enumerate(present) if flag)
                    expected = sum(w for w, flag in zip(weights, present) if flag) >= threshold
                    self.assertEqual(bool(compiled.match(data=data)), expected, (weights, threshold, present))
                    self.assertEqual(bool(compiled.match(data=data * 3)), expected)

    def test_empty_signature_is_not_emitted(self):
        self.assertEqual(list(YaraRule(make_threat([], 0), "").generate_rules()), [])

    def test_large_weight_set_does_not_enumerate_subsets(self):
        sig = SimpleNamespace(threshold=500, sig_type="SIGNATURE_TYPE_PEHSTR")
        with patch.object(YaraCondition, 'generate_subsets', side_effect=AssertionError):
            cond = YaraCondition([SimpleNamespace(weight=i) for i in range(1, 1001)], sig, "")
        self.assertFalse(cond.fallback)
        self.assertLess(len(cond.statements[-1]), 60000)

    def test_invalid_subrule_does_not_weaken_rule(self):
        threat = make_threat([10, -1], 5)
        threat.hstr_signatures[0].subrules[1].rule_bytes = bytes.fromhex('aa90019000')
        self.assertEqual(list(YaraRule(threat, "").generate_rules()), [])


class PatternTests(unittest.TestCase):
    def test_nested_alternatives_preserve_all_bytes(self):
        pattern, inaccurate = YaraString.parse_ext_subrule(bytes.fromhex('aa900304041122334455667788bb9000'))
        self.assertEqual(pattern, 'aa (11 22 33 44|55 66 77 88) bb')
        self.assertFalse(inaccurate)
        compiled = yara.compile(source=f'rule check {{ strings: $a={{{pattern}}} condition: $a }}')
        self.assertTrue(compiled.match(data=bytes.fromhex('aa11223344bb')))
        self.assertFalse(compiled.match(data=bytes.fromhex('aa1122bb')))

    def test_truncated_operands(self):
        for data in ('aa90', 'aa9001', 'aa9003', 'aa9003040411', 'aa9004020341'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                YaraString.parse_ext_subrule(bytes.fromhex(data + '9000'))


class ContainerTests(unittest.TestCase):
    def test_main_parses_after_delta_patch(self):
        args = SimpleNamespace(download=False, convert=True, proxy=None, asr=False)
        calls = []
        with patch('defender2yara.main.load_lua_backend'), \
             patch('defender2yara.main.get_latest_signature_version', return_value='1.463.330.0'), \
             patch('defender2yara.main.get_latest_engine_version', return_value='1.1.26100.4'), \
             patch('defender2yara.main.os.path.exists', side_effect=lambda path: str(path).endswith('dlta.vdm')), \
             patch('defender2yara.main.db'), patch('defender2yara.main.DbMetadata'), \
             patch('defender2yara.main.convert_threats'), \
             patch('defender2yara.main.Vdm') as factory:
            factory.return_value.apply_delta_vdm.side_effect = lambda path: calls.append('delta')
            factory.return_value.parse_files.side_effect = lambda: calls.append('parse')
            with self.assertRaises(SystemExit) as exit_info:
                main(args)
            self.assertEqual(exit_info.exception.code, 0)
        self.assertEqual(calls, ['delta', 'parse', 'delta', 'parse'])

    def test_extended_record_advancement(self):
        data = bytes([0, 255, 255, 255]) + struct.pack('<I', 3) + b'abc'
        data += bytes([0, 2, 0, 0]) + b'de'
        records = Vdm.parse_database(data)
        self.assertEqual([r.sig_data for r in records], [b'abc', b'de'])
        self.assertEqual([r.offset for r in records], [0, 11])

    def test_truncated_records(self):
        for data in (b'\0', b'\0\xff\xff\xff', b'\0\x05\0\0x'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                BaseSig(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                Vdm.parse_database(data)

    def test_standalone_record_before_threat(self):
        self.assertEqual(Vdm.parse_threats([BaseSig(b'\0\x01\0\0x')]), [])

    def test_rmdx_at_zero_and_size_validation(self):
        payload = b'test VDM payload'
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(payload) + compressor.flush()
        header = b'RMDX' + b'\0' * 20 + struct.pack('<II', 24, len(payload))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.vdm'
            path.write_bytes(header + compressed)
            self.assertEqual(Vdm.extract_vdm_data(path), payload)
            path.write_bytes(header[:28] + struct.pack('<I', 999) + compressed)
            with self.assertRaises(ValueError):
                Vdm.extract_vdm_data(path)


class LuaTests(unittest.TestCase):
    def test_truncated_fixup_is_an_error_result(self):
        result, error = fixup_lua_data(mplua_chunk()[:30])
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    def test_missing_header_and_failed_decompile(self):
        sig = SimpleNamespace(sig_type='SIGNATURE_TYPE_LUASTANDALONE', sig_data=b'no Lua')
        threat = SimpleNamespace(threat_name='test', signatures=[sig])
        sig.offset = 1234
        threat.threat_id = 42
        with self.assertLogs('defender2yara', level='WARNING') as logs:
            self.assertEqual(get_lua_from_threat(threat), [])
        message = '\n'.join(logs.output)
        for detail in ('threat_id=42', 'signature_index=0', 'vdm_offset=0x4d2', 'payload_size=6', 'prefix_hex=6e6f204c7561'):
            self.assertIn(detail, message)
        sig.sig_data = mplua_chunk()
        with patch('defender2yara.main.lua_decompile_data', side_effect=[None, b'listing']):
            self.assertIn(b'listing', get_lua_from_threat(threat)[0])

    def test_missing_backend_has_actionable_error(self):
        load_lua_backend.cache_clear()
        try:
            with patch('defender2yara.defender.lua_backend.Path.is_file', return_value=False):
                with self.assertRaisesRegex(RuntimeError, 'bundled Python Lua backend'):
                    load_lua_backend()
        finally:
            load_lua_backend.cache_clear()

    def test_python_backend_without_native_luadec(self):
        backend = load_lua_backend()
        expected = Path(__file__).resolve().parents[1] / 'defender_explorer' / 'defender_sig_extractor' / 'lua_decompiler' / '__init__.py'
        self.assertEqual(Path(backend.__file__).resolve(), expected)
        with patch('subprocess.run', side_effect=AssertionError('native executable used')):
            output = decompile_data(mplua_chunk())
            listing = decompile_data(mplua_chunk(), disassemble=True)
        self.assertIn(b'9007199254740993', output)
        self.assertIn(b'RETURN', listing)

    def test_standard_lua_backend(self):
        load_lua_backend()
        fixed, error = fixup_lua_data(mplua_chunk())
        self.assertIsNone(error)
        self.assertIn(b'return', decompile_data(fixed))
        self.assertIn(b'RETURN', decompile_data(fixed, disassemble=True))

    def test_truncated_mplua_string(self):
        # One declared string with a length longer than the entire chunk.
        data = (mplua_chunk()[:40] + struct.pack('<IBI', 1, 4, 99999) + b'x')
        result, error = fixup_lua_data(data)
        self.assertIsNone(result)
        self.assertIn('Truncated Lua string', error)


if __name__ == '__main__':
    unittest.main()