import unittest

from defender2yara.defender.signature.aggregator import (
    AaAggregatorExSig,
    decode_aggregator,
    encode_aggregator,
)
from defender2yara.defender.signature.hstr import DexHStrExtSig
from defender2yara.defender.signature.versioncheck import VersionCheckSig


def tlv(sig_type: int, payload: bytes) -> bytes:
    size = len(payload)
    return bytes([sig_type, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF]) + payload


class AggregatorTests(unittest.TestCase):
    def test_expression_decode(self):
        # PWS:Win32/Gina
        sig = AaAggregatorExSig(tlv(0xE7, bytes.fromhex(
            "00003200a3c70f93ec67edc7ecedf23f88747877f23fbcfe13eaea8f"
            "c71777e30f0f93ec67edc7ecedf23f88747877f23fbcfe13eaea")))
        self.assertEqual(sig.flags, 0x00)
        self.assertEqual(sig.name_length, 0)
        self.assertEqual(
            sig.expression,
            "HSTR:PWS:Win32/Gina.dll&SIGATTR:PWS:Win32/Gina.dll",
        )
        self.assertEqual(
            sig.references,
            ["HSTR:PWS:Win32/Gina.dll", "SIGATTR:PWS:Win32/Gina.dll"],
        )

    def test_attribute_flag(self):
        # TrojanClicker:Win32/VB.H
        sig = AaAggregatorExSig(tlv(0xE7, bytes.fromhex(
            "01002b00936704ecd76ad777de67e305008fa3c70f93ec0f0baccebc3f05eaf231e48"
            "00becedf23f8874784414fea3")))
        self.assertEqual(sig.flags, 0x01)
        self.assertTrue(sig.is_attribute)
        self.assertEqual(
            sig.expression, "RPF:DODGYPACK&HSTR:TrojanClicker:Win32/VB.H"
        )

    def test_long_expression(self):
        # VirTool:Win32/Injector - mixed Lua/HSTR atoms with negation
        sig = AaAggregatorExSig(tlv(0xE7, bytes.fromhex(
            "0000d200e7dabcec4414fe6a99ce80311eedf21e18f8acad801e18ac13d18fe7dabcec4414fec7da99adbcf23fd7f2d11ebc3f3180770fc233d0d8333333338fc0e7dabcec4414fe0fac1ebceaad801e18ac13d1ec884a36e7dabcec4414fe0fac1ebceaad801e18ac13d1ece588e08fe7dabcec4414fe0fac1ebcea6a99ce80311ed1ec9a338fa3c70f93ec4414fec7dad1e6f231f2acdad1050ba7e61e800bfe05bceaea99bc31e41773e6ac0b1e8f12a3c70f93ec4414fec7dad1e6f231f2acdad1050ba7e61e800bfefcd031eadad1f2ac3ffee3")))
        self.assertIn("Lua:VB.ObjectWithNoMethods", sig.expression)
        self.assertIn("!HSTR:VB.SuspiciousCrypter.Exclusion.A", sig.expression)
        self.assertIn("&", sig.expression)

    def test_table_is_a_permutation(self):
        self.assertEqual(len(set(decode_aggregator(bytes(range(256))))), 256)

    def test_utf8_expression(self):
        # Backdoor:Win32/Cawkcawk.NA!dha uses non-ASCII look-alike characters
        plain = "Lua:PeCompanyName!\u03faicr\u043es\u043eft__corp\u043erati\u043en"
        encoded = plain.encode("utf-8")
        payload = b"\x00\x00" + len(encoded).to_bytes(2, "little") + encode_aggregator(encoded)
        sig = AaAggregatorExSig(tlv(0xE7, payload))
        self.assertEqual(sig.expression, plain)
        self.assertEqual(encode_aggregator(decode_aggregator(encoded)), encoded)


class DexHStrExtTests(unittest.TestCase):
    # TrojanSpy:AndroidOS/Geimini.A
    GEIMINI = bytes.fromhex(
        "0400040005000001002a0368692c7869616f6c7590010268692c6c697169616e9001"
        "02636f6d6d616e64206f6b9001026279659000010020034164416374697669747990"
        "090c00636f6d900301012e2f6765696e696d69900001001d0170726f63657373444f57"
        "4e4c4f41445f4641494c55455f416374696f6e01001a0170726f636573735041525345"
        "5f4641494c55455f416374696f6e01000f015452414e534143545f4641494c55450000"
    )

    # Trojan:AndroidOS/FakeInstSms.C - has the extra trailing flags word
    FAKEINSTSMS = bytes.fromhex(
        "050005000500000100160042696e617279534d5352656365697665722e6a61766101"
        "0038004c636f6d2f736f66742f616e64726f69642f617070696e7374616c6c65722f"
        "73657276696365732f534d5353656e6465725365727669636501000e00536f727469"
        "6e6720534d532e2e2e01000a006463536d73436f756e7401000d0066696c6c536d73"
        "496e666f28290000030000"
    )

    def test_common_header(self):
        sig = DexHStrExtSig(tlv(0xBE, self.GEIMINI))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_DEXHSTR_EXT")
        self.assertEqual(sig.threshold, 4)
        self.assertEqual(sig.rule_numbers, 5)
        self.assertEqual(len(sig.subrules), 5)
        self.assertFalse(sig.flags_present)

    def test_wildcard_bytes(self):
        sig = DexHStrExtSig(tlv(0xBE, self.GEIMINI))
        self.assertEqual(
            sig.subrules[0].rule_bytes,
            b"hi,xiaolu\x90\x01\x02hi,liqian\x90\x01\x02command ok\x90\x01\x02bye\x90\x00",
        )

    def test_trailing_flags(self):
        sig = DexHStrExtSig(tlv(0xBE, self.FAKEINSTSMS))
        self.assertTrue(sig.flags_present)
        self.assertEqual(sig.flags, 3)
        self.assertEqual(len(sig.subrules), 5)
        self.assertEqual(sig.subrules[-1].rule_bytes, b"fillSmsInfo()")

    def test_name_reference_variant(self):
        # !InfrastructureShared record: not a real DEX string signature
        sig = DexHStrExtSig(tlv(0xBE, bytes.fromhex(
            "020002000100212354656c3a54726f6a616e3a416e64726f69644f532f46616b65"
            "63616c6c732e59550002000e007c2a63616c6c456e746974792a7c0000")))
        self.assertTrue(sig.is_name_reference)
        self.assertEqual(sig.name_reference, "#Tel:Trojan:AndroidOS/Fakecalls.YU")
        self.assertEqual(sig.subrules, [])


class VersionCheckTests(unittest.TestCase):
    def test_always_true(self):
        sig = VersionCheckSig(tlv(0x7A, bytes.fromhex("0000000000000000")))
        self.assertEqual(sig.check_id, 0)
        self.assertTrue(sig.is_unconditional)
        self.assertEqual(sig.describe(), "always true")

    def test_unconditional_modern(self):
        # Backdoor:Win32/Simda
        sig = VersionCheckSig(tlv(0x7A, bytes.fromhex("7700000001000000")))
        self.assertEqual(sig.check_id, 0x77)
        self.assertEqual(sig.value, 1)
        self.assertTrue(sig.is_unconditional)

    def test_os_build(self):
        # Behavior:Win32/WPADExploitAttempt
        sig = VersionCheckSig(tlv(0x7A, bytes.fromhex("26000000bb470000")))
        self.assertEqual(sig.value, 18363)
        self.assertEqual(sig.check, ("os_build", "<"))

    def test_definition_digest(self):
        # Behavior:Win32/Mamadut.B starts with four definition-version digest checks
        sig = VersionCheckSig(tlv(0x7A, bytes.fromhex("3c000000d409da02")))
        self.assertEqual(sig.check_id, 0x3C)
        self.assertEqual(sig.value, 0x02DA09D4)
        self.assertEqual(sig.check, ("definition_set_digest[0]", "=="))

    def test_engine_build_constant(self):
        sig = VersionCheckSig(tlv(0x7A, bytes.fromhex("02000000de5d0000")))
        self.assertEqual(sig.value, 0x5DDE)
        self.assertEqual(sig.describe(), "0x65f4 > value")

    def test_engine_gate(self):
        # Behavior:Win32/Badbrute.A
        sig = VersionCheckSig(tlv(0x7A, bytes.fromhex("1300000003000600")))
        self.assertEqual(sig.check, ("engine_field_0xb60", ">"))
        self.assertFalse(sig.is_unconditional)


if __name__ == "__main__":
    unittest.main()
