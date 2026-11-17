"""Vectors from the shipped database for PESTATIC, PESTATICEX and BM_INFO."""

import json
import struct
import unittest

from defender2yara.defender.signature import BmInfoSig, PestaticSig, SigTreeSig
from defender2yara.defender.signature.bm_info import bits_to_names
from defender2yara.defender.signature.pestatic import defender_crc32


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        self.assertEqual(sig.decode_status, "decoded")
        return details


class PestaticSigTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_section_fingerprint(self):
        sig = PestaticSig(tlv(0x87, bytes.fromhex("a411d72f3421dfb88b3e351f3fe60100")))
        self.assertEqual(sig.crc_head, 0x2FD711A4)
        self.assertEqual(sig.crc_prefix, 0xB8DF2134)
        self.assertEqual(sig.crc_section, 0x1F353E8B)
        self.assertEqual(sig.hashed_length, 124479)
        self.assertIsNone(sig.record_name)
        self.assertFalse(sig.section_crc_equals_prefix)
        d = self.snapshot(sig)
        self.assertEqual(d["crc_head"], 0x2FD711A4)
        self.assertEqual(d["hashed_offset"], None)
        self.assertEqual(d["md5_hex"], None)

    def test_window_order_from_database(self):
        # 83,105 records use hashed_length == 0x200 and every one of them has
        # crc_section == crc_prefix.
        sig = PestaticSig(tlv(0x87, bytes.fromhex("11223344556677885566778800020000")))
        self.assertEqual(sig.hashed_length, 0x200)
        self.assertTrue(sig.section_crc_equals_prefix)
        self.assertNotIn("prefix_window_matches_head", sig.to_details())

    def test_named_infrastructure_record(self):
        base = bytes.fromhex("b14afa5a48f703a230de2c7307180000")
        name = b"!#ESRP:PEStatic:iobios64.sys"
        sig = PestaticSig(tlv(0x87, base + bytes([len(name)]) + name))
        self.assertEqual(sig.record_name, "!#ESRP:PEStatic:iobios64.sys")
        self.assertEqual(sig.packed_record_id & 0xFFFFFFFF, defender_crc32(base))
        self.assertEqual((sig.packed_record_id >> 32) & 0xFF, 0x87)
        self.assertEqual((sig.packed_record_id >> 40) & 0xFFFFFF, 16)
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#ESRP:PEStatic:iobios64.sys")
        self.assertEqual(d["packed_record_id_hex"], f"{sig.packed_record_id:016x}")

    def test_pestaticex_md5_region(self):
        md5 = bytes(range(16))
        payload = struct.pack("<II", 0x11223344, 0x55667788) + md5
        payload += struct.pack("<II", 0x1000, 0x40)
        sig = PestaticSig(tlv(0xCB, payload))
        self.assertEqual(sig.crc_head, 0x11223344)
        self.assertEqual(sig.crc_prefix, 0x55667788)
        self.assertEqual(sig.md5, md5)
        self.assertEqual(sig.md5_hex, md5.hex())
        self.assertEqual(sig.hashed_length, 0x1000)
        self.assertEqual(sig.hashed_offset, 0x40)
        self.assertIsNone(sig.crc_section)
        d = self.snapshot(sig)
        self.assertTrue(d["is_extended_form"])
        self.assertEqual(d["md5_hex"], md5.hex())

    def test_truncated_and_short_window_warnings(self):
        with self.assertRaises(ValueError):
            PestaticSig(tlv(0x87, b"\0" * 4))
        sig = PestaticSig(tlv(0x87, bytes.fromhex("112233445566778899aabbcc20000000")))
        self.assertEqual(sig.decode_status, "partial")
        self.assertTrue(sig.decode_warnings)


class BmInfoSigTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_minimal_telemetry_record(self):
        sig = BmInfoSig(tlv(0xA8, bytes.fromhex(
            "0000010003003333000e004c6f773a54656c656d6574727900"
        )))
        self.assertEqual(sig.group, "")
        self.assertEqual(sig.flags, 1)
        self.assertEqual(sig.default_signature_id, 33)
        self.assertEqual(sig.scope_ids, {})
        self.assertEqual(sig.levels["Low"]["tags"], ["Telemetry"])
        self.assertEqual(sig.action_mask, 0x2)
        d = self.snapshot(sig)
        self.assertIsNone(d["group"])
        self.assertEqual(d["levels"], [{"level": "Low", "tags": ["Telemetry"], "mask": 2}])
        self.assertEqual(d["action_names"], ["Telemetry"])

    def test_scoped_ids_and_all_levels(self):
        payload = bytes.fromhex(
            "00000400190033332c33332b5061636b65642c33332b53797374656d333200"
            "2e004c6f773a54656c656d657472792c4d656469756d3a54656c656d65747279"
            "2c486967683a54656c656d6574727900"
        )
        sig = BmInfoSig(tlv(0xA8, payload))
        self.assertEqual(sig.flags, 4)
        self.assertEqual(sig.default_signature_id, 33)
        self.assertEqual(sig.scope_ids, {"packed": 33, "system32": 33})
        self.assertEqual(sorted(sig.levels), ["High", "Low", "Medium"])
        self.assertEqual(sig.level_masks, {"Low": 2, "Medium": 2, "High": 2})
        d = self.snapshot(sig)
        self.assertEqual(d["scope_ids"], {"packed": 33, "system32": 33})
        self.assertEqual([entry["level"] for entry in d["levels"]], ["Low", "Medium", "High"])

    def test_grouped_record_and_case_insensitive_tags(self):
        group = b"grp\0"
        id_spec = b"50,33+System32\0"
        tags = b"Low:Telemetry+SMSScan,High:UI+PurgeClipboardContent\0"
        payload = struct.pack("<H", len(group)) + group
        payload += struct.pack("<H", 0x0005)
        payload += struct.pack("<H", len(id_spec)) + id_spec
        payload += struct.pack("<H", len(tags)) + tags
        sig = BmInfoSig(tlv(0xA8, payload))
        self.assertEqual(sig.group, "grp")
        self.assertEqual(sig.default_signature_id, 50)
        self.assertEqual(sig.scope_ids, {"system32": 33})
        self.assertEqual(sig.decode_warnings, [])
        # The engine compares names case-insensitively (FUN_180719580), so
        # "SMSScan" folds into the SmsScan bit.
        self.assertEqual(sig.levels["Low"]["mask"], 0x2 | 0x08000000)
        self.assertEqual(sig.levels["High"]["mask"], 0x4 | 0x2000000000)
        d = self.snapshot(sig)
        self.assertEqual(d["group"], "grp")
        self.assertIn("SmsScan", d["action_names"])
        self.assertNotIn("SMSScan", d["action_names"])

    def test_unknown_tag_and_bad_scope_are_warnings(self):
        id_spec = b"33,33+Wrong\0"
        tags = b"Low:NotAThing,Urgent:Telemetry\0"
        payload = struct.pack("<HH", 0, 0)
        payload += struct.pack("<H", len(id_spec)) + id_spec
        payload += struct.pack("<H", len(tags)) + tags
        sig = BmInfoSig(tlv(0xA8, payload))
        self.assertEqual(sig.decode_status, "partial")
        self.assertEqual(sig.default_signature_id, 33)
        self.assertEqual(sig.scope_ids, {})
        self.assertEqual(list(sig.levels), ["Low"])
        self.assertEqual(sig.levels["Low"]["mask"], 0)
        details = sig.to_details()
        self.assertTrue(any("scope" in w for w in details["decode_warnings"]))
        self.assertTrue(any("action" in w for w in details["decode_warnings"]))
        self.assertTrue(any("level" in w for w in details["decode_warnings"]))

    def test_bit_helpers(self):
        self.assertEqual(bits_to_names(0x2 | 0x40000000), ["Telemetry", "ParentInfo"])


class SigTreeAttributeTests(unittest.TestCase):
    def test_edge_attribute_id_and_values(self):
        # Real 0x41 record: y = 0x11003008, z = 0xb0f4fd76, w = 0, flags 0/2.
        payload = bytes([1, 0, 0, 3, 0])
        payload += struct.pack("<IIII", 0x00000002, 0x11003008, 0x296929f7, 0)
        sig = SigTreeSig(tlv(0x41, payload))
        edge = sig.edges[0]
        self.assertEqual(edge.attribute_id, 0x3008)
        self.assertEqual(edge.left_length, 0x11)
        self.assertEqual(edge.right_length, 0)
        self.assertEqual(edge.left_value, 0x296929F7)
        self.assertEqual(edge.right_value, 0)
        self.assertEqual(edge.left_flags_text, "0x00")
        self.assertEqual(edge.right_flags_text, "any")
        self.assertEqual(sig.attribute_ids, [0x3008])
        self.assertEqual(sig.attribute_namespace, "0x30xx (file/PE metadata)")
        self.assertFalse(sig.has_inline_conditions)

    def test_inline_condition_overrides_value_word(self):
        pattern = b"A\0B\0"
        payload = bytes([1, 0, 0, 2, 0])
        # Only the left side is inline (x high byte = 0x10), y byte3 = length.
        payload += struct.pack("<IIII", 0x00001000, len(pattern) << 24, 0x12345678, 0x87654321)
        payload += pattern
        sig = SigTreeSig(tlv(0x41, payload))
        edge = sig.edges[0]
        self.assertEqual(edge.attribute_id, 0)
        self.assertIsNone(edge.left_value)
        self.assertEqual(edge.right_value, 0x87654321)
        self.assertTrue(sig.has_inline_conditions)
        self.assertEqual(sig.patterns[0].text, "AB")
        self.assertEqual(edge.left_flags_text, "inline pattern")

    def test_bm_event_names_and_known_values(self):
        # Real Behavior:Win32/CobaltStrike.J!sms record, local id 2465931.
        raw = bytes.fromhex(
            "b34500000400010200024104001140001a802720f400000000"
            "404002001740210a24d7e998ad190406"
            "404002001740210a24d7e99828e5311b"
            "02400200ff4000241eac621700000000"
        )
        sig = SigTreeSig(raw)
        self.assertTrue(sig.is_behavior)
        self.assertEqual([edge.attribute_name for edge in sig.edges], [
            "BM_ProcessStart",
            "BM_EngineInternal",
            "BM_EngineInternal",
            "BM_SignatureAnchor (rule/group identity, not a live event)",
        ])
        self.assertEqual(sig.edges[0].value_hint, "process command line")
        self.assertEqual(sig.edges[0].left_flags_text, "suffix|wide")
        self.assertEqual(sig.edges[0].left_predicate,
                         "ends with crc32=0xf4202780 (26 wide chars)")
        self.assertEqual(sig.edges[0].right_predicate, "any")
        self.assertEqual(sig.edges[1].left_value_text, "SMS_THREAT")
        self.assertEqual(sig.edges[1].right_value_text,
                         "HackTool:Win32/CobaltStrike.I!sms")
        self.assertEqual(sig.edges[2].right_value_text,
                         "HackTool:Win64/CobaltStrike.I!sms")
        self.assertIn("SMS_THREAT", sig.to_details()["decoded_summary"])

    def test_value_crc_matches_engine_values(self):
        from defender2yara.defender.signature.sigtree import sigtree_value_crc

        self.assertEqual(sigtree_value_crc("SMS_THREAT"), 0x98E9D724)
        self.assertEqual(sigtree_value_crc("mshta.exe"), 0xDE038D24)
        self.assertEqual(sigtree_value_crc("\\powershell.exe"), 0xC7F18C20)

    def test_enrich_legacy_details(self):
        from defender2yara.defender.signature.sigtree import enrich_sigtree_details

        legacy = {
            "tree_kind": 2,
            "edges": [{
                "x": 0x00024040, "y": 0x0A214017, "z": 0x98E9D724, "w": 0x060419AD,
                "left_flags": 0x40, "right_flags": 0x40,
                "left_length": 10, "right_length": 33,
                "left_value": 0x98E9D724, "right_value": 0x060419AD,
                "attribute_id": 0x4017, "conditions": [],
            }],
        }
        enriched = enrich_sigtree_details(legacy)
        edge = enriched["edges"][0]
        self.assertEqual(edge["attribute_name"], "BM_EngineInternal")
        self.assertEqual(edge["left_value_text"], "SMS_THREAT")
        self.assertEqual(edge["right_value_text"], "HackTool:Win32/CobaltStrike.I!sms")
        self.assertIn("starts with", edge["left_predicate"])


if __name__ == "__main__":
    unittest.main()
