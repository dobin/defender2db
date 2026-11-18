"""Version-one parser snapshots retain interpretation, never opaque payloads."""

import json
import struct
import unittest

from defender2yara.defender.signature import (
    AaAggregatorExSig, BaseSig, DexHStrExtSig, HStrExtSig, HStrSig,
    KcrceSig, LuaSig, Nid64Sig, NidSig, SigTreeSig, SnidSig, StaticSig,
    ThreatBeginSig, ThreatEndSig, VersionCheckSig,
)
from defender2yara.defender.signature.aggregator import encode_aggregator
from defender2yara.defender.subrule.hstr import HStrExtSubRule, HStrSubRule


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureJsonTests(unittest.TestCase):
    def snapshot(self, sig):
        sig.unrelated_future_attribute = b"must not leak"
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        self.assertEqual(sig.details_version, 1)
        self.assertEqual(sig.decode_status, "decoded")

        def check(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    self.assertNotIn(key, {
                        "sig_data", "tail", "extra_bytes", "trailing", "name_raw",
                        "record_name_raw", "raw_threat_name", "unrelated_future_attribute",
                    })
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)
            else:
                self.assertIsInstance(value, (str, int, float, bool, type(None)))

        check(details)
        return details

    def test_unsupported_and_error_override(self):
        sig = BaseSig(tlv(0x00, b"opaque body"))
        self.assertEqual(sig.to_details(), {})
        self.assertEqual(sig.decode_status, "unsupported")
        sig.decode_status = "error"
        self.assertEqual(sig.decode_status, "error")
        self.assertEqual(sig.to_details(), {})
        typed = VersionCheckSig(tlv(0x7A, struct.pack("<II", 0, 0)))
        typed.decode_status = "error"
        self.assertEqual(typed.decode_status, "error")

    def test_revoked_certificate_uses_only_existing_thumbprint_slice(self):
        thumbprint = bytes(range(20))
        sig = BaseSig(tlv(0x6C, b"hdr" + thumbprint + b"opaque tail"))
        self.assertEqual(self.snapshot(sig), {"thumbprint_hex": thumbprint.hex()})
        for size in (0, 20, 22):
            with self.subTest(size=size):
                short = BaseSig(tlv(0x6C, b"x" * size))
                self.assertEqual(short.to_details(), {})
                self.assertEqual(short.decode_status, "unsupported")

    def test_static_has_canonical_crcs_and_computed_flag_interpretation(self):
        payload = struct.pack("<IIIIH", 1, 3, 2, 4096, 0x2003)
        sig = StaticSig(tlv(0x67, payload + bytes.fromhex("aabbccdd") + b"\x06#Clean"))
        d = self.snapshot(sig)
        self.assertEqual([d[f"partial_crc{i}"] for i in (1, 2, 3)], [1, 2, 3])
        self.assertEqual(d["file_hash_hex"], "aabbccdd")
        self.assertEqual(d["hash_type"], "crc32")
        self.assertTrue(d["prefix_match"])
        self.assertEqual(d["record_name"], "#Clean")
        self.assertEqual(d["unknown_flag_bits"], 2)
        self.assertEqual(d["flag_summary"], sig.flag_summary)
        self.assertEqual(d["match_mode_note"], sig.match_mode_note)
        self.assertNotIn("hash1", d)
        self.assertNotIn("crc32", d)

    def test_hstr_nested_patterns_keep_signed_weight_and_rendering(self):
        pattern = b"ab\x90\x01\x02cd"
        payload = struct.pack("<HHHB", 5, 4, 1, 0)
        payload += struct.pack("<hB", -2, len(pattern)) + pattern + b"\0\0"
        d = self.snapshot(HStrSig(tlv(0x61, payload)))
        self.assertEqual(d["threshold"], 4)
        self.assertEqual(d["subrules"], [{
            "rule_weight": -2, "rule_size": len(pattern),
            "rule_bytes_hex": pattern.hex(), "text": "ab<skip 2>cd",
        }])

    def test_extended_hstr_flags_and_dex_name_references(self):
        payload = struct.pack("<HHH", 2, 2, 1) + b"label\0"
        payload += struct.pack("<hBB", 2, 3, 0) + b"abc" + struct.pack("<HH", 0, 3)
        d = self.snapshot(HStrExtSig(tlv(0x78, payload + b"opaque tail")))
        self.assertEqual(d["name"], "label")
        self.assertTrue(d["name_present"])
        self.assertEqual(d["flags"], 3)
        self.assertTrue(d["flags_present"])
        self.assertEqual(d["end_marker"], 0)
        self.assertEqual(d["subrules"][0]["unknown_u8_1"], 0)
        self.assertEqual(d["subrules"][0]["rule_bytes_hex"], "616263")
        reference = struct.pack("<HHH", 2, 2, 0) + b"!#Tel:Example\0\0\0"
        dex = self.snapshot(DexHStrExtSig(tlv(0xBE, reference)))
        self.assertTrue(dex["is_name_reference"])
        self.assertEqual(dex["name_reference"], "#Tel:Example")
        self.assertEqual(dex["subrules"], [])

    def test_pehstr_ext_bytes_are_not_rendered_as_text(self):
        pattern = b"\xe8\x00\x00\x00\x00\x5b\x52\x45\x55\x90\x01\x04"
        payload = struct.pack("<HHH", 1, 1, 1) + b"\0"
        payload += struct.pack("<hBB", 1, len(pattern), 3) + pattern + b"\0\0"
        d = self.snapshot(HStrExtSig(tlv(0x78, payload)))
        self.assertNotIn("text", d["subrules"][0])

        dex_payload = struct.pack("<HHH", 1, 1, 1) + b"\0"
        dex_payload += struct.pack("<hBB", 1, 3, 1) + b"abc" + b"\0\0"
        dex = self.snapshot(DexHStrExtSig(tlv(0xBE, dex_payload)))
        self.assertEqual(dex["subrules"][0]["text"], "abc")

    def test_static_partial_only_for_detected_incomplete_fields(self):
        cases = [
            (struct.pack("<IIIIH", 1, 2, 3, 4096, 0x5000), "Unknown STATIC hash algorithm"),
            (struct.pack("<IIIIH", 1, 2, 3, 4096, 0) + b"short", "Truncated STATIC file hash"),
            (struct.pack("<IIIIH", 1, 2, 3, 4096, 0) + b"x" * 16 + b"\x05ab", "Truncated STATIC record name"),
        ]
        for payload, warning in cases:
            with self.subTest(warning=warning):
                sig = StaticSig(tlv(0x67, payload))
                self.assertEqual(sig.decode_status, "partial")
                self.assertIn(warning, sig.to_details()["decode_warnings"])
                json.dumps(sig.to_details())
                sig.decode_status = "error"
                self.assertEqual(sig.decode_status, "error")
        complete = StaticSig(tlv(0x67, struct.pack("<IIIIH", 1, 2, 3, 4096, 2) + b"x" * 16))
        self.assertEqual(complete.decode_status, "decoded")
        self.assertEqual(complete.to_details()["decode_warnings"], [])

    def test_hstr_partial_for_missing_counted_rules_and_short_patterns(self):
        header = struct.pack("<HHH", 2, 2, 2) + b"\0"
        for cls, kind, rule in (
            (HStrSig, 0x61, struct.pack("<hB", 1, 3)),
            (HStrExtSig, 0x78, struct.pack("<hBB", 1, 3, 0)),
        ):
            for suffix in (b"", rule + b"a", rule + b"abc" + b"\0\0\0\0"):
                with self.subTest(cls=cls, suffix=suffix):
                    sig = cls(tlv(kind, header + suffix))
                    self.assertEqual(sig.decode_status, "partial")
                    self.assertTrue(sig.to_details()["decode_warnings"])
                    json.dumps(sig.to_details())
            single = struct.pack("<HHH", 2, 2, 1) + b"\0"
            truncated = cls(tlv(kind, single + rule + b"a"))
            self.assertEqual(truncated.decode_status, "partial")
            self.assertTrue(any("pattern" in w for w in truncated.to_details()["decode_warnings"]))
            complete = cls(tlv(kind, single + rule + b"abc" + b"\0\0"))
            self.assertEqual(complete.decode_status, "decoded")

    def test_terminated_subrules_are_json_ready(self):
        for rule_type in (HStrSubRule, HStrExtSubRule):
            for payload in (b"", b"\0\0\0\0"):
                with self.subTest(rule=rule_type, payload=payload):
                    d = rule_type(payload, 0).to_details()
                    self.assertEqual(json.loads(json.dumps(d)), d)
                    self.assertEqual(d["rule_weight"], 0)
                    self.assertEqual(d["rule_bytes_hex"], "")

    def test_sigtree_nested_conditions_keep_patterns_hashes_and_words(self):
        pattern = b"A\0\x90\x01\x02B\0"
        payload = bytes([1, 1, 0, 2, 0])
        payload += struct.pack("<IIIII", 0x1000, len(pattern) << 24, 3, 4, 0x100)
        payload += pattern + b"\x02" + b"\xab" * 16 + b"opaque tail"
        d = self.snapshot(SigTreeSig(tlv(0x40, payload)))
        edge = d["edges"][0]
        self.assertEqual([edge[k] for k in ("z", "w", "extra")], [3, 4, 256])
        self.assertEqual(edge["left_flags"], 0x10)
        self.assertEqual(edge["left_length"], len(pattern))
        left, right = edge["conditions"]
        self.assertEqual(left["data_hex"], pattern.hex())
        self.assertEqual(left["text"], "A<skip 2>B")
        self.assertTrue(left["is_pattern"])
        self.assertEqual(right["kind"], "md5")
        self.assertEqual(right["data_hex"], "ab" * 16)
        self.assertTrue(right["is_hash"])
        self.assertFalse(d["is_behavior"])

    def test_nid_keys_are_canonical_without_large_json_integers(self):
        key = 0xFEDCBA9876543210
        sig = Nid64Sig(tlv(0xCE, key.to_bytes(8, "little") + b"\x67group\0opaque tail"))
        d = self.snapshot(sig)
        self.assertEqual(d["record_key_hex"], "fedcba9876543210")
        self.assertNotIn("record_key", d)
        self.assertEqual(d["record_name"], "group")
        self.assertEqual(d["packed_crc32"], 0x76543210)
        self.assertEqual(d["packed_sig_type_id"], 0x98)
        self.assertEqual(d["packed_size"], 0xFEDCBA)
        self.assertFalse(d["has_record_id_layout"])
        small = self.snapshot(NidSig(tlv(0x55, b"\x53\0\0\0\x2b")))
        self.assertEqual(small["record_key_hex"], "00000053")
        self.assertTrue(small["is_legacy_id"])
        self.assertEqual(small["likely_purpose"], "tagging")
        self.assertTrue(small["purpose_note"])

    def test_snid_retains_record_store_key_not_sha1_alias(self):
        key = b"\0" * 4 + b"\xab" * 16
        d = self.snapshot(SnidSig(tlv(0x7E, key + b"\xe7group\0opaque tail")))
        self.assertEqual(d["record_key_hex"], key.hex())
        self.assertEqual(d["record_sig_type_id"], 0xE7)
        self.assertEqual(d["group_name"], "group")
        self.assertTrue(d["key_is_padded"])
        self.assertNotIn("record_sha1", d)

    def test_aggregator_expression_and_reference_summary_exclude_tail(self):
        expression = b"HSTR:Example&HSTR:Example|Lua:Other"
        payload = struct.pack("<BBH", 1, 0, len(expression))
        payload += encode_aggregator(expression) + b"opaque tail"
        d = self.snapshot(AaAggregatorExSig(tlv(0xE7, payload)))
        self.assertEqual(d["expression"], expression.decode())
        self.assertEqual(d["references"], ["HSTR:Example", "HSTR:Example", "Lua:Other"])
        self.assertEqual(d["reference_kinds"], [{"kind": "HSTR", "count": 2}, {"kind": "Lua", "count": 1}])
        self.assertTrue(d["is_attribute"])
        self.assertNotIn("extra", d)

    def test_version_gate_known_and_unknown_interpretation(self):
        for check_id, check in ((0x26, ["os_build", "<"]), (0xFFFFFFFF, None)):
            sig = VersionCheckSig(tlv(0x7A, struct.pack("<II", check_id, 18363) + b"opaque tail"))
            d = self.snapshot(sig)
            self.assertEqual(d["check"], check)
            self.assertEqual(d["description"], sig.describe())
            self.assertEqual(d["value"], 18363)
            self.assertNotIn("extra", d)

    def test_kcrce_and_threat_lua_metadata_exclude_unknown_bytes(self):
        kcrc = self.snapshot(KcrceSig(tlv(0x80, struct.pack("<IIIHH", 1, 2, 3, 4096, 0x8000) + b"\x04name")))
        self.assertEqual(kcrc, {"crc1": 1, "crc2": 2, "crc3": 3, "region": 4096, "flags": 0x8000, "record_name": "name"})
        payload = struct.pack("<I4sHBB", 42, b"xxxx", 3, 4, 1) + b"name"
        for suffix, severity in ((b"", None), (b"xxxx\x05xxxx", 5)):
            with self.subTest(cls=ThreatBeginSig, severity=severity):
                d = self.snapshot(ThreatBeginSig(tlv(0x5C, payload + suffix)))
                self.assertEqual(d, {"threat_id": 42, "category_id": 3, "type_id": 1, "threat_name": "name", "severity_id": severity})
        self.assertEqual(self.snapshot(ThreatEndSig(tlv(0x5D, struct.pack("<I", 42)))), {"threat_id": 42})

    def test_lua_standalone_wrapper_is_decoded(self):
        name = b"!#Lua:Test\0"
        attributes = b"Includes\0BMLuaLib\0"
        code = struct.pack("<II", 1, 30 | (2 << 23))  # LOADK R0 K0; RETURN R0, 2
        function = (struct.pack("<III", 0, 0, 0) + bytes([0, 0, 0, 2])
                    + struct.pack("<I", 2) + code
                    + struct.pack("<I", 1) + b"\x04"
                    + struct.pack("<I", len("BMLuaLib") + 1) + b"BMLuaLib\0"
                    + struct.pack("<IIII", 0, 0, 0, 0))
        body = b"\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01" + function
        payload = bytes([len(name), 0x15]) + struct.pack("<HI", len(attributes), len(body))
        payload += name + attributes + body
        sig = LuaSig(tlv(0xBD, payload))
        self.assertEqual(sig.lua_bytecode, body)
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#Lua:Test")
        self.assertTrue(d["has_name"])
        self.assertEqual(d["script_type"], 0x15)
        self.assertEqual(d["phase_name"], "SignatureValidator")
        self.assertEqual(d["attributes"], [
            {"name": "Includes", "value": "BMLuaLib", "obfuscated": False},
        ])
        self.assertEqual(d["attribute_strings"], ["Includes", "BMLuaLib"])
        self.assertIsNone(d["attribute_data_hex"])
        self.assertEqual(d["body_size"], len(body))
        self.assertEqual(d["body_format"], "lua")
        self.assertTrue(d["has_lua_bytecode"])
        self.assertEqual(d["decode_warnings"], [])
        self.assertEqual(d["summary"], sig.describe())
        chunk = d["chunk"]
        self.assertTrue(chunk["has_header"])
        self.assertEqual((chunk["version"], chunk["functions"], chunk["instructions"]), ("5.1", 1, 2))
        self.assertEqual(chunk["string_constants"], ["BMLuaLib"])
        self.assertEqual(chunk["number_encoding"], "integer")
        self.assertEqual(chunk["opcodes"][0], {"name": "LOADK", "count": 1})


if __name__ == "__main__":
    unittest.main()
