import unittest

from defender2yara.defender.signature.aggregator import (
    AaAggregatorSig,
    AaAggregatorExSig,
)
from defender2yara.defender.signature.pathname import (
    FilePathSig,
    FolderNameSig,
    PATH_ROOTS,
)


def tlv(sig_type: int, payload: bytes) -> bytes:
    size = len(payload)
    return bytes([sig_type, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF]) + payload


class AaAggregatorTests(unittest.TestCase):
    # VirTool:Win32/Injector - plaintext legacy aggregator
    INJECTOR = bytes.fromhex(
        "963d000000003900534c465045523a57696e33322f496e6a6563747352756e646c6c"
        "333226284c75613a4973456e74657270726973657c4973536576696c6c6529"
    )
    # Trojan:VBS/Autorun - plaintext, no name
    AUTORUN = bytes.fromhex(
        "96a1000000009d002854726f6a616e3a5642532f4175746f72756e21617474723031"
        "7c54726f6a616e3a5642532f4175746f72756e21617474723032292654726f6a616e"
        "3a5642532f4175746f72756e216174747230332654726f6a616e3a5642532f417574"
        "6f72756e216174747230342654726f6a616e3a5642532f4175746f72756e21617474"
        "7230352654726f6a616e3a5642532f4175746f72756e21617474723036"
    )
    # Virus:Win32/MpTestAgg.A
    MPTEST = bytes.fromhex(
        "962f000000002b004d50544553542d4147472d303026284d50544553542d4147472d"
        "3031264d50544553542d4147472d303229"
    )

    def test_plaintext_expression(self):
        sig = AaAggregatorSig(self.INJECTOR)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_AAGGREGATOR")
        self.assertEqual(sig.flags, 0x00)
        self.assertEqual(sig.name_length, 0)
        self.assertEqual(
            sig.expression,
            "SLFPER:Win32/InjectsRundll32&(Lua:IsEnterprise|IsSeville)",
        )
        self.assertFalse(sig.to_details()["is_obfuscated"])

    def test_plaintext_expression_large(self):
        sig = AaAggregatorSig(self.AUTORUN)
        self.assertEqual(sig.body_length, 0x9D)
        self.assertTrue(sig.expression.startswith("(Trojan:VBS/Autorun!attr01|"))
        self.assertEqual(sig.references[0], "Trojan:VBS/Autorun")
        self.assertIn("Trojan:VBS/Autorun!attr06", sig.expression)

    def test_plaintext_named_record(self):
        sig = AaAggregatorSig(self.MPTEST)
        self.assertEqual(sig.expression, "MPTEST-AGG-00&(MPTEST-AGG-01&MPTEST-AGG-02)")

    def test_decoder_does_not_deobfuscate_plaintext(self):
        # 0x96 handler FUN_18041a5d0 does not apply the 0xe7 substitution table.
        sig = AaAggregatorSig(self.MPTEST)
        self.assertEqual(sig.expression[0], "M")

    def test_ex_sig_still_decodes(self):
        # Same layout but substituted; ensure the refactor kept 0xe7 working.
        sig = AaAggregatorExSig(tlv(0xE7, bytes.fromhex(
            "00003200a3c70f93ec67edc7ecedf23f88747877f23fbcfe13eaea8f"
            "c71777e30f0f93ec67edc7ecedf23f88747877f23fbcfe13eaea")))
        self.assertEqual(
            sig.expression,
            "HSTR:PWS:Win32/Gina.dll&SIGATTR:PWS:Win32/Gina.dll",
        )

    def test_ex_name_is_plain_text(self):
        # 0xe7 obfuscates only the body; the optional name is interned verbatim.
        sig = AaAggregatorExSig(bytes.fromhex(
            "e7360100003af8002123534c463a54726f6a616e3a507974686f6e2f5079416d"
            "7369556e736166654d6f64656c446573657269616c697a6174696f6e2e414d21"
            "6d6c936704ec67a7e3adc717ec148018bc19f2ac0beca3bcd167f231e4ea8004"
            "f23f1305eabcd1d18fc0e7dabcec67a7e3adc717ec148018bc19f2ac0becade7"
            "ec4a4a36e7dabcec67a7e3adc717ec148018bc19f2ac0becade7ec4abf36e7da"
            "bcec67a7e3adc717ec148018bc19f2ac0becade7ec4a2936e7dabcec67a7e3a"
            "dc717ec148018bc19f2ac0becade7ec4a3336e7dabcec67a7e3adc717ec1480"
            "18bc19f2ac0becade7ecbf3336e7dabcec67a7e3adc717ec148018bc19f2ac0"
            "becade7ec413336e7dabcec67a7e3adc717ec148018bc19f2ac0becade7ecd8"
            "3336e7dabcec67a7e3adc717ec148018bc19f2ac0becade7ec2933e0"))
        self.assertEqual(
            sig.name,
            "!#SLF:Trojan:Python/PyAmsiUnsafeModelDeserialization.AM!ml",
        )
        self.assertTrue(sig.expression.startswith("RPF:PyAMSI:"))

    def test_wrong_type_rejected(self):
        with self.assertRaises(AssertionError):
            AaAggregatorSig(tlv(0xE7, b"\0\0\0\0"))


class FilePathTests(unittest.TestCase):
    # Trojan:Win32/VB.HI - literal absolute path
    ABSOLUTE = bytes.fromhex("5f0a0000ffff633a5c612e626174")
    # TrojanDropper:Win32/Delf.CK - CSIDL_SYSTEM + relative path
    SYSTEM = bytes.fromhex("5f0d000025005c6765647a61632e726567")
    # Worm:Win32/Renocide.gen!B - %temp%
    TEMP = bytes.fromhex("5f080000feff5c732e636d64")
    # Rogue:Win32/FakeXPA - %CommonProgramFiles% + wildcard pattern
    COMMONFILES = bytes.fromhex(
        "5f230000fcff5c6d6963726f736f6674207368617265645c677265656e61763230"
        "3f3f2e657865"
    )

    def test_absolute_path(self):
        sig = FilePathSig(self.ABSOLUTE)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_FILEPATH")
        self.assertEqual(sig.root_id, 0xFFFF)
        self.assertEqual(sig.root_name, "ABSOLUTE")
        self.assertTrue(sig.is_absolute)
        self.assertEqual(sig.path, "c:\\a.bat")
        self.assertEqual(sig.rendering, "c:\\a.bat")

    def test_csidl_root(self):
        sig = FilePathSig(self.SYSTEM)
        self.assertEqual(sig.root_id, 0x25)
        self.assertEqual(sig.root_name, "SYSTEM")
        self.assertEqual(sig.root_macro, "%SystemRoot%\\System32")
        self.assertEqual(sig.path, "\\gedzac.reg")
        self.assertEqual(sig.rendering, "%SystemRoot%\\System32\\gedzac.reg")

    def test_temp_pseudo_root(self):
        sig = FilePathSig(self.TEMP)
        self.assertEqual(sig.root_id, 0xFFFE)
        self.assertEqual(sig.root_name, "TEMP")
        self.assertEqual(sig.rendering, "%temp%\\s.cmd")

    def test_wildcard_pattern(self):
        sig = FilePathSig(self.COMMONFILES)
        self.assertEqual(sig.root_id, 0xFFFC)
        self.assertEqual(sig.root_name, "COMMONFILES")
        self.assertEqual(sig.rendering,
                         "%CommonProgramFiles%\\microsoft shared\\greenav20??.exe")
        self.assertTrue(sig.is_wildcard)

    def test_details(self):
        details = FilePathSig(self.SYSTEM).to_details()
        self.assertEqual(details["layout"], "filepath")
        self.assertEqual(details["root_id_hex"], "0x0025")
        self.assertEqual(details["pattern"], "\\gedzac.reg")
        self.assertFalse(details["is_wildcard"])
        self.assertEqual(details["decode_warnings"], [])

    def test_unknown_root_warns(self):
        sig = FilePathSig(tlv(0x5F, b"\x77\x77\\x"))
        self.assertTrue(sig.decode_warnings)
        self.assertIn("0x7777", sig.decode_warnings[0])
        self.assertEqual(sig.root_name, "UNKNOWN(0x7777)")

    def test_truncated_payload(self):
        with self.assertRaises(ValueError):
            FilePathSig(tlv(0x5F, b"\x25"))


class FolderNameTests(unittest.TestCase):
    # Trojan:Win32/Agent - %windir% + relative directory
    WINDOWS = bytes.fromhex("6007000024005c6b75756d")
    # Trojan:Win32/Agent - %ProgramFiles% + relative directory
    PROGRAM_FILES = bytes.fromhex("6014000026005c636f6d6d6f6e2066696c65735c6b75756d")
    # SoftwareBundler:Win32/SquareNet - %temp% + numeric folder
    TEMP = bytes.fromhex("60050000feff5c3532")

    def test_relative_folder(self):
        sig = FolderNameSig(self.WINDOWS)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_FOLDERNAME")
        self.assertEqual(sig.root_name, "WINDOWS")
        self.assertEqual(sig.rendering, "%windir%\\kuum")

    def test_nested_relative_folder(self):
        sig = FolderNameSig(self.PROGRAM_FILES)
        self.assertEqual(sig.root_name, "PROGRAM_FILES")
        self.assertEqual(sig.rendering, "%ProgramFiles%\\common files\\kuum")

    def test_temp_folder(self):
        sig = FolderNameSig(self.TEMP)
        self.assertEqual(sig.rendering, "%temp%\\52")

    def test_roots_table_is_complete_for_observed_ids(self):
        for root_id in (0x02, 0x06, 0x07, 0x0B, 0x0C, 0x10, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1C, 0x20, 0x21, 0x23, 0x24, 0x25,
                        0x26, 0x28, 0x2E, 0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF):
            self.assertIn(root_id, PATH_ROOTS)


if __name__ == "__main__":
    unittest.main()
