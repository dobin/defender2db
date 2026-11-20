"""Vectors from the shipped database for KVIR32 (0x20) and REGKEY (0x63)."""

import json
import unittest

from defender2yara.defender.signature import Kvir32Sig, RegKeySig
from defender2yara.defender.vdm import Vdm


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        return details


class Kvir32Tests(SignatureSnapshotMixin, unittest.TestCase):
    # Backdoor:Win32/Berbew.I: body at page offset 0, 0x24 bytes.
    BERBEW = bytes.fromhex("ae24da18a55243640000240000000000")
    # Worm:Win32/Apsiv.A: anchor window 1, body at page offset 0x20.
    APSIV = bytes.fromhex("1b2c5dcaae45c4552000700001000000")
    # Virus:Win32/Heretic.1986: anchor window 2 (anchor at offset 32).
    HERETIC = bytes.fromhex("bdee7be024d0aaaf2000e00302000000")
    # Trojan:Win32/Inject.F: negative flag suppresses the detection report.
    SUPPRESSED = bytes.fromhex("1920be5ad1a80e340000e90000000080")
    # !InfrastructureShared: UPX 1.x packer fingerprint.
    UPX = bytes.fromhex("a5334c88752d7636000024000000000008215550585f315f58")

    def test_berbew(self):
        sig = Kvir32Sig(tlv(0x20, self.BERBEW))
        self.assertEqual(sig.anchor_crc, 0x18DA24AE)
        self.assertEqual(sig.body_crc, 0x644352A5)
        self.assertEqual(sig.body_offset, 0)
        self.assertEqual(sig.body_length, 0x24)
        self.assertEqual(sig.body_end, 0x24)
        self.assertEqual(sig.anchor_window, 0)
        self.assertEqual(sig.anchor_offset, 0)
        self.assertTrue(sig.reports_detection)
        self.assertIsNone(sig.record_name)
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "kvir32")
        self.assertEqual(d["anchor_crc_hex"], "18da24ae")
        self.assertEqual(d["flags"], 0)
        self.assertFalse(d["has_name"])

    def test_anchor_windows(self):
        one = Kvir32Sig(tlv(0x20, self.APSIV))
        self.assertEqual(one.anchor_window, 1)
        self.assertEqual(one.anchor_offset, 16)
        self.assertEqual(one.body_offset, 0x20)
        self.assertFalse(one.anchor_matches_body_start)
        two = Kvir32Sig(tlv(0x20, self.HERETIC))
        self.assertEqual(two.anchor_window, 2)
        self.assertEqual(two.anchor_offset, 32)
        self.assertEqual(two.body_offset, 32)
        self.assertEqual(two.body_length, 0x3E0)
        self.assertTrue(two.anchor_matches_body_start)

    def test_suppressed_flag(self):
        sig = Kvir32Sig(tlv(0x20, self.SUPPRESSED))
        self.assertEqual(sig.flags, -0x8000)
        self.assertEqual(sig.flags_unsigned, 0x8000)
        self.assertFalse(sig.reports_detection)
        d = self.snapshot(sig)
        self.assertFalse(d["reports_detection"])

    def test_named_shared_record(self):
        sig = Kvir32Sig(tlv(0x20, self.UPX))
        self.assertEqual(sig.record_name, "!UPX_1_X")
        self.assertEqual(sig.record_name_raw, b"!UPX_1_X")
        self.assertEqual(sig.body_length, 0x24)
        d = self.snapshot(sig)
        # The name is not part of the engine record id (16-byte payload + type).
        self.assertTrue(d["packed_record_id_hex"].startswith("00001020"))
        self.assertTrue(d["has_name"])

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x20, self.BERBEW), 0)
        self.assertIsInstance(sig, Kvir32Sig)

    def test_truncated_payload(self):
        with self.assertRaises(ValueError):
            Kvir32Sig(tlv(0x20, b"\x00" * 15))

    def test_truncated_name_is_partial(self):
        payload = self.BERBEW + b"\x08UPX"
        sig = Kvir32Sig(tlv(0x20, payload))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Truncated KVIR32 name", sig.decode_warnings[0])


class RegKeyTests(SignatureSnapshotMixin, unittest.TestCase):
    # Trojan:Win32/Agent: HKCU key existence, no value name/data.
    AGENT = bytes.fromhex(
        "02000d00536f6674776172655c6b75756d0000"
    )
    # TrojanSpy:Win32/Bancos.KT: HKLM service value with expected data.
    BANCOS = bytes.fromhex(
        "03002a0053595354454d5c436f6e74726f6c5365743030325c53657276696365"
        "735c47627053765c5c537461727423006578706c6f7265722e65786520433a5c"
        "57494e444f57535c737673686f73742e657865"
    )
    # !InfrastructureShared style HKCR extension record (kind 1).
    WINZIPPER = bytes.fromhex(
        "010004002e7a5c5c0b0057696e5a69707065722e7a"
    )
    # Trojan:MSIL/Toshruli.A: HKCU Internet Settings proxy server value.
    PROXY = bytes.fromhex(
        "02004800536f6674776172655c4d6963726f736f66745c57696e646f77735c43"
        "757272656e7456657273696f6e5c496e7465726e65742053657474696e6773"
        "5c5c50726f7879536572766572100037372e37382e3234302e3136373a3830"
    )
    # Invalid hive: the engine ignores this record.
    INVALID_KEY = b"\\Registry\\Machine\\Test\\\\(default)"
    INVALID = (
        (0xFFFF).to_bytes(2, "little")
        + len(INVALID_KEY).to_bytes(2, "little")
        + INVALID_KEY
        + b"\x00\x00"
    )

    def test_hkcu_key_existence(self):
        sig = RegKeySig(tlv(0x63, self.AGENT))
        self.assertEqual(sig.hive_id, 2)
        self.assertEqual(sig.hive, "HKEY_CURRENT_USER")
        self.assertEqual(sig.key_path, "Software\\kuum")
        self.assertIsNone(sig.value_name)
        self.assertEqual(sig.value_data, "")
        self.assertFalse(sig.has_value_separator)
        self.assertTrue(sig.key_existence_only)
        self.assertEqual(sig.prefix_index, 9)
        self.assertEqual(sig.prefix, "software")
        self.assertEqual(sig.key_suffix, "\\kuum")
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "regkey")
        self.assertEqual(d["full_key"], "HKEY_CURRENT_USER\\Software\\kuum")

    def test_hklm_value_data(self):
        sig = RegKeySig(tlv(0x63, self.BANCOS))
        self.assertEqual(sig.hive, "HKEY_LOCAL_MACHINE")
        self.assertEqual(
            sig.key_path, "SYSTEM\\ControlSet002\\Services\\GbpSv"
        )
        self.assertEqual(sig.value_name, "Start")
        self.assertEqual(
            sig.value_data, "explorer.exe C:\\WINDOWS\\svshost.exe"
        )
        self.assertFalse(sig.key_existence_only)
        self.assertIsNone(sig.prefix)
        self.assertEqual(sig.key_suffix, sig.key)
        self.assertIn("\\\\Start = ", sig.describe())

    def test_hkcr_extension_record(self):
        sig = RegKeySig(tlv(0x63, self.WINZIPPER))
        self.assertEqual(sig.hive, "HKEY_CLASSES_ROOT")
        self.assertEqual(sig.key_path, ".z")
        self.assertEqual(sig.value_name, "")
        self.assertEqual(sig.value_data, "WinZipper.z")

    def test_known_prefix(self):
        sig = RegKeySig(tlv(0x63, self.PROXY))
        self.assertEqual(sig.prefix_index, 2)
        self.assertEqual(
            sig.prefix, "software\\microsoft\\windows\\currentversion"
        )
        self.assertEqual(
            sig.key_suffix, "\\Internet Settings\\\\ProxyServer"
        )
        self.assertEqual(sig.value_name, "ProxyServer")
        self.assertEqual(sig.value_data, "77.78.240.167:80")

    def test_invalid_hive_is_partial(self):
        sig = RegKeySig(tlv(0x63, self.INVALID))
        self.assertIsNone(sig.hive)
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("outside 1..4", sig.decode_warnings[0])

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x63, self.AGENT), 0)
        self.assertIsInstance(sig, RegKeySig)

    def test_truncated_key(self):
        with self.assertRaises(ValueError):
            RegKeySig(tlv(0x63, b"\x02\x00\x20\x00abc"))

    def test_truncated_value(self):
        with self.assertRaises(ValueError):
            RegKeySig(tlv(0x63, b"\x02\x00\x01\x00a\x08\x00b"))


if __name__ == "__main__":
    unittest.main()
