import unittest

from defender2yara.defender.signature.hstr import HStrExtSig
from defender2yara.defender.signature.nid import Nid64Sig, NidSig
from defender2yara.defender.signature.sigtree import (
    SigTreeSig,
    decode_tree_pattern,
)
from defender2yara.defender.vdm import Vdm


def tlv(sig_type: int, payload: bytes) -> bytes:
    size = len(payload)
    return bytes([sig_type, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF]) + payload


class NidTests(unittest.TestCase):
    def test_reference_record(self):
        # Backdoor:Win32/Hupigon - attribute id 0x11 attached to object 0x77d15d90
        sig = NidSig(tlv(0x55, bytes.fromhex("905dd17711")))
        self.assertEqual(sig.record_key, 0x77D15D90)
        self.assertEqual(sig.record_kind, 0x11)
        self.assertFalse(sig.has_name)
        self.assertEqual(sig.describe(), "key=0x77d15d90 kind=0x11")

    def test_named_record(self):
        # !InfrastructureShared - (key, kind) maps to a telemetry name
        sig = NidSig(tlv(0x55, bytes.fromhex("430fd0117c2354454c00")))
        self.assertEqual(sig.record_key, 0x11D00F43)
        self.assertEqual(sig.record_kind, 0x7C)
        self.assertTrue(sig.has_name)
        self.assertEqual(sig.record_name, "#TEL")
        self.assertEqual(sig.trailing, b"")

    def test_nid64(self):
        # HackTool:Win32/Mikatz
        sig = Nid64Sig(tlv(0xCE, bytes.fromhex("1f7698f378b500007b")))
        self.assertEqual(sig.record_key, 0x0000B578F398761F)
        self.assertEqual(sig.record_kind, 0x7B)
        self.assertFalse(sig.has_name)

    def test_nid64_named_record(self):
        sig = Nid64Sig(tlv(0xCE, bytes.fromhex(
            "1c201eda7017000084234869676854727573745075626c69736865725f564c4300")))
        self.assertEqual(sig.record_key, 0x00001770DA1E201C)
        self.assertEqual(sig.record_kind, 0x84)
        self.assertEqual(sig.record_name, "#HighTrustPublisher_VLC")

    def test_kind_label_and_purpose(self):
        # Trojan:Linux/Metasploit - reference-only record in the 0x77d1 id block
        sig = NidSig(tlv(0x55, bytes.fromhex("af7fd17711")))
        self.assertEqual(sig.key_text, "0x77d17faf")
        self.assertEqual(sig.kind_text, "0x11")
        self.assertEqual(sig.id_block, 0x77D1)
        self.assertEqual(sig.kind_label, "name slots (packers, tags)")
        self.assertFalse(sig.is_legacy_id)
        self.assertEqual(sig.purpose_label, "naming")
        self.assertEqual(sig.likely_purpose, "naming")
        self.assertIn("name slot", sig.purpose_note)

    def test_group_membership_purpose(self):
        payload = (0x000092B9).to_bytes(4, "little") + b"\xe7" + b"!#OrgSignerRmmNormal\x00"
        sig = NidSig(tlv(0x55, payload))
        self.assertEqual(sig.record_name, "!#OrgSignerRmmNormal")
        self.assertEqual(sig.likely_purpose, "group membership")

    def test_tagging_purpose(self):
        # kind 0x2b is an engine attribute (deep analysis / VMM grow family)
        sig = NidSig(tlv(0x55, bytes.fromhex("905dd1772b")))
        self.assertEqual(sig.likely_purpose, "tagging")

    def test_unknown_kind_has_no_label(self):
        sig = NidSig(tlv(0x55, bytes.fromhex("905dd177ff")))
        self.assertEqual(sig.kind_label, "")
        self.assertEqual(sig.likely_purpose, "naming")

    def test_legacy_small_id(self):
        # Virus:DOS/Nutcracker.6727 - id from one of the old flat name tables
        sig = NidSig(tlv(0x55, bytes.fromhex("5300000011")))
        self.assertEqual(sig.record_key, 0x53)
        self.assertTrue(sig.is_legacy_id)
        self.assertEqual(sig.id_block, 0)


class SigTreeTests(unittest.TestCase):
    def test_behavior_tree_without_conditions(self):
        # Behavior:Win32/ModifiedAutoRunInf - variant 0, no condition blobs
        sig = SigTreeSig(tlv(0xB3, bytes.fromhex(
            "0200010200024102000040000d86cb0e4000000000024102000140000d86cb0e"
            "4000000000")))
        self.assertTrue(sig.is_behavior)
        self.assertEqual(sig.edge_count, 2)
        self.assertEqual(sig.variant, 0)
        self.assertEqual(sig.tree_kind, 2)
        self.assertEqual(sig.name, "")
        self.assertEqual(sig.edges[0].x, 0x00024102)
        self.assertEqual(sig.edges[0].y, 0x0D004000)
        self.assertEqual(sig.edges[0].conditions, [])
        self.assertEqual(sig.trailing, b"")

    def test_behavior_tree_with_utf16_pattern(self):
        # Behavior:Win32/Renos217 - variant 1, one UTF-16 path pattern
        sig = SigTreeSig(tlv(0xB3, bytes.fromhex(
            "02010202000000000000f00015d9d1251f00000000000000000250000100400021"
            "0000000000000000000002002500770069006e0064006f007700730025005c0090"
            "02122e006500780065009000")))
        self.assertEqual(sig.variant, 1)
        self.assertEqual(len(sig.edges), 2)
        self.assertEqual(sig.edges[0].extra, 0)
        self.assertEqual(sig.edges[1].extra, 0x00020000)
        patterns = sig.patterns
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].side, "left")
        self.assertEqual(patterns[0].flags, 0x50)
        self.assertEqual(patterns[0].data.hex(), (
            "2500770069006e0064006f007700730025005c009002122e006500780065009000"))
        self.assertEqual(decode_tree_pattern(patterns[0].data),
                         "%windows%\\<skip 0..18>.exe")

    def test_sigtree_with_patterns(self):
        # Trojan:Win32/Startpage.AR (SIGTREE_EXT) - system32 path patterns
        sig = SigTreeSig(tlv(0x41, bytes.fromhex(
            "050001030000000000203000126cf4c23800000000000000000c300018c1e39a8c"
            "00000000000000001030140be1ee542212b606911401000010301d041ae7a105"
            "00000000633a5c77696e646f77735c73797374656d33325c9002082e646c6c"
            "9000001400000330001d0000000000000000633a5c77696e646f77735c737973"
            "74656d33325c9002102e6578659000")))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_SIGTREE_EXT")
        self.assertFalse(sig.is_behavior)
        self.assertEqual(sig.tree_kind, 3)
        self.assertEqual(sig.edge_count, 5)
        texts = [c.text for c in sig.patterns]
        self.assertTrue(any("system32" in t and ".dll" in t for t in texts), texts)
        self.assertTrue(any("system32" in t and ".exe" in t for t in texts), texts)

    def test_plain_sigtree(self):
        # TrojanDropper:Win32/Agent (SIGTREE) - five edges, no conditions
        sig = SigTreeSig(tlv(0x40, bytes.fromhex(
            "050001030002000000083000059f7ebfbd00000000020220000a3000000000000000000000000020000b3000000000000000000000000000000330001275ff8fd900000000000000001f30000bd23bda4600000000")))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_SIGTREE")
        self.assertEqual(sig.edge_count, 5)
        self.assertEqual(sig.tree_kind, 3)
        self.assertEqual(sig.patterns, [])
        self.assertEqual(sig.trailing, b"")


class HStrExtNameAndTailTests(unittest.TestCase):
    def test_name_field_is_empty_for_compiled_records(self):
        # TrojanDropper:Win32/Agent (0x78)
        sig = HStrExtSig(tlv(0x78, bytes.fromhex(
            "0100010002000001005a03e835000000eb08c680900104004080b89001040075"
            "ef68900104ff35900104ff3590010468900104e89001010000006a00e89001"
            "01000000558bec50ff7508ff7514e89001010000006a006a006a026a006a0068"
            "000000c09000010048038b4e088b5604518bc8e8900101ffffff50ff15900104"
            "8b3590010457ffd653ffd633c0b9110000008d7c241cf3ab8d54240c528d4424"
            "20506a006a006a006a006a006a006a0090000000")))
        self.assertEqual(sig.threshold, 1)
        self.assertEqual(sig.rule_numbers, 2)
        self.assertEqual(sig.name, "")
        self.assertFalse(sig.name_present)
        self.assertEqual(len(sig.subrules), 2)
        self.assertEqual(sig.tail, b"\x00\x00")
        self.assertEqual(sig.end_marker, 0)
        self.assertFalse(sig.flags_present)

    def test_definition_name_and_subrules(self):
        # !InfrastructureShared: definition form keeps the name and the rules
        sig = HStrExtSig(tlv(0x78, bytes.fromhex(
            "0100010001002123485354523a537472696e67436f6465466f724d736874612e"
            "4121706c690001000580016d736874610000")))
        self.assertEqual(sig.name, "!#HSTR:StringCodeForMshta.A!pli")
        self.assertTrue(sig.name_present)
        self.assertEqual(sig.rule_numbers, 1)
        self.assertEqual(len(sig.subrules), 1)
        self.assertEqual(sig.subrules[0].rule_bytes, b"mshta")
        self.assertEqual(len(sig.tail), 2)

    def test_trailing_flags_word(self):
        # TrojanSpy:Win32/Keylogger - end marker + flags word
        sig = HStrExtSig(tlv(0x78, bytes.fromhex(
            "05000500050000010015015c52454359434c45525c74656d7030312e74787400"
            "01000e015b0045004e005400450052005d0001000c015b0042004b0053005000"
            "5d00010010015b0049004e0053004500520054005d0001001101e95202000083"
            "ff40761b83ff5b73166a1400000400")))
        self.assertEqual(sig.rule_numbers, 5)
        self.assertEqual(len(sig.subrules), 5)
        self.assertTrue(sig.flags_present)
        self.assertEqual(sig.flags, 4)
        self.assertEqual(sig.end_marker, 0)

    def test_rule_count_bounds_subrules(self):
        # VirTool:Win32/CeeInject.gen!HP: the terminator scan overruns here.
        sig = HStrExtSig(tlv(0x78, bytes.fromhex(
            "030003000400000100160333ff576800300000ff7650ff7634ff35900104e890"
            "00010013030fb74e063bc17290090b00a190010440a3900001001e038b462803"
            "463489900305048424900104459001018d9003020144244590000100190333db"
            "536800300000ff7650e890010453ff765457ff7634900001000200")))
        self.assertEqual(sig.rule_numbers, 4)
        self.assertEqual(len(sig.subrules), 4)
        self.assertEqual(sig.tail, b"\x01\x00\x02\x00")
        self.assertEqual(sig.end_marker, 1)
        self.assertEqual(sig.flags, 2)


class DispatchTests(unittest.TestCase):
    def test_parse_database_wires_the_new_types(self):
        data = (
            tlv(0x55, bytes.fromhex("905dd17711"))
            + tlv(0xCE, bytes.fromhex("1f7698f378b500007b"))
            + tlv(0xB3, bytes.fromhex(
                "0200010200024102000040000d86cb0e4000000000024102000140000d86cb0e"
                "4000000000"))
            + tlv(0x78, bytes.fromhex("0100010001000001000401583535350000"))
        )
        records = Vdm.parse_database(data)
        self.assertIsInstance(records[0], NidSig)
        self.assertIsInstance(records[1], Nid64Sig)
        self.assertIsInstance(records[2], SigTreeSig)
        self.assertIsInstance(records[3], HStrExtSig)
        self.assertEqual(records[2].sig_type, "SIGNATURE_TYPE_SIGTREE_BM")


if __name__ == "__main__":
    unittest.main()

