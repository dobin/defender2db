import unittest

from defender2yara.defender.signature.kcrce import KcrceSig
from defender2yara.defender.signature.snid import SnidSig
from defender2yara.defender.signature.static import StaticSig


def tlv(sig_type: int, payload: bytes) -> bytes:
    size = len(payload)
    return bytes([sig_type, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF]) + payload


class StaticSigTests(unittest.TestCase):
    def test_crc32_variant(self):
        # Backdoor:Win32/Hupigon
        sig = StaticSig(tlv(0x67, bytes.fromhex(
            "7952f31104d126ea22390208736e0000012022390208")))
        self.assertEqual(sig.hash_type, "crc32")
        self.assertEqual(sig.file_size, 0x6E73)
        self.assertEqual(sig.flags, 0x2001)
        self.assertEqual(sig.crc32, 0x08023922)
        # CRC32 of the whole file equals the 64 KiB partial CRC for small files.
        self.assertEqual(sig.hash3, sig.crc32)

    def test_md5_variant(self):
        # Virus:Win32/MPTestFile.2004
        sig = StaticSig(tlv(0x67, bytes.fromhex(
            "1f79d57eb21ec59529d988cb0090000001009a026f3295fefe4c4647ea5ba6bd43da")))
        self.assertEqual(sig.hash_type, "md5")
        self.assertEqual(sig.file_size, 0x9000)
        self.assertEqual(sig.flags, 0x0001)
        self.assertEqual(sig.md5.hex(), "9a026f3295fefe4c4647ea5ba6bd43da")

    def test_sha1_variant(self):
        # Virus:DOS/EICAR_Test_File
        sig = StaticSig(tlv(0x67, bytes.fromhex(
            "69860403923603bcf45331916c0c00000110"
            "02a27e325ff806402628ac68780906d07f285b9a")))
        self.assertEqual(sig.hash_type, "sha1")
        self.assertEqual(sig.file_size, 0xC6C)
        self.assertEqual(sig.flags, 0x1001)
        self.assertEqual(sig.sha1.hex(), "02a27e325ff806402628ac68780906d07f285b9a")


class KcrceSigTests(unittest.TestCase):
    def test_fields(self):
        # Backdoor:Win32/Hupigon
        sig = KcrceSig(tlv(0x80, bytes.fromhex(
            "dff401000e1d51ea4158390200040000")))
        self.assertEqual(sig.crc1, 0x0001F4DF)
        self.assertEqual(sig.crc2, 0xEA511D0E)
        self.assertEqual(sig.crc3, 0x02395841)
        self.assertEqual(sig.region, 0x0400)
        self.assertEqual(sig.flags, 0x0000)

    def test_last_window_variant(self):
        # Trojan:MacOS/EICAR_Test_File.A!xp
        sig = KcrceSig(tlv(0x80, bytes.fromhex(
            "e8a5368ce231a8799de802b300040080")))
        self.assertEqual(sig.region, 0x0400)
        self.assertEqual(sig.flags, 0x8000)


class SnidSigTests(unittest.TestCase):
    def test_reference_type(self):
        # HackTool:Win32/Keygen
        sig = SnidSig(tlv(0x7E, bytes.fromhex(
            "7e7b2ea3dfc3045c124b961591b7752d7a9a563acc")))
        self.assertEqual(sig.record_sig_type_id, 0xCC)
        self.assertEqual(sig.record_sig_type, "SIGNATURE_TYPE_KCRCEX")

    def test_localhash_reference(self):
        # Backdoor:Win32/Hupigon
        sig = SnidSig(tlv(0x7E, bytes.fromhex(
            "119480bce5833ad22fb789f15497cb630000000062")))
        self.assertEqual(len(sig.record_sha1), 20)
        self.assertEqual(sig.record_sig_type_id, 0x62)
        self.assertEqual(sig.record_sig_type, "SIGNATURE_TYPE_LOCALHASH")


if __name__ == "__main__":
    unittest.main()
