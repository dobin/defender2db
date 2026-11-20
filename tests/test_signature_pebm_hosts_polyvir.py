"""Vectors from the shipped database for PEBMPAT, HOSTSENTRY and POLYVIR32."""

import json
import unittest

from defender2yara.defender.signature.hostsentry import HostsEntrySig
from defender2yara.defender.signature.pebmpat import PebmPatSig
from defender2yara.defender.signature.polyvir32 import Polyvir32Sig
from defender2yara.defender.vdm import Vdm


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        return details


class PebmPatTests(SignatureSnapshotMixin, unittest.TestCase):
    # Trojan:Win32/Zlob.DI: anonymous 106-byte code pattern.
    ANON = bytes.fromhex(
        "00006600558bec83c4c081e87e224000720681e38d1f400081e3581d40002bd268"
        "425142005fbeaaffffff6601376683072c81e8812e4000720681e3ee114000668b"
        "0f6683c12c66890f47685020060081ce1325400058474eb98453420039f975c481"
        "fe5c1740009000"
    )
    # Shared infrastructure label: flag 0, 41-byte name, 15-byte pattern.
    NAMED = bytes.fromhex(
        "00290f0021235045424d5041543a566972546f6f6c3a57696e33322f4f62667573"
        "6361746f722e4143562145508bff2bc981c1900104512bc0c39000"
    )

    def test_anonymous_pattern(self):
        sig = PebmPatSig(tlv(0x95, self.ANON))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_PEBMPAT")
        self.assertEqual(sig.flags, 0)
        self.assertEqual(sig.name_length, 0)
        self.assertFalse(sig.has_name)
        self.assertEqual(sig.pattern_length, 0x66)
        self.assertEqual(len(sig.pattern), 0x66)
        self.assertTrue(sig.pattern.endswith(b"\x90\x00"))
        self.assertEqual(sig.anchor.hex(), "558bec83c4c081e8")
        self.assertFalse(sig.uses_wildcards)
        self.assertEqual(sig.opcode_counts, {0x00: 1})
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "pebmpat")
        self.assertEqual(d["pattern_length"], 0x66)
        self.assertEqual(d["anchor_hex"], "55 8b ec 83 c4 c0 81 e8")
        self.assertTrue(d["pattern_hex"].startswith("55 8b ec"))

    def test_named_pattern(self):
        sig = PebmPatSig(tlv(0x95, self.NAMED))
        self.assertEqual(
            sig.name, "!#PEBMPAT:VirTool:Win32/Obfuscator.ACV!EP"
        )
        self.assertEqual(sig.name_length, 0x29)
        self.assertTrue(sig.has_name)
        self.assertEqual(sig.pattern_length, 0x0F)
        self.assertEqual(sig.pattern.hex(), "8bff2bc981c1900104512bc0c39000")
        self.assertEqual(sig.anchor.hex(), "8bff2bc981c1")
        self.assertEqual(sig.decode_warnings, [])
        d = self.snapshot(sig)
        self.assertTrue(d["has_name"])

    def test_invalid_flags_warn(self):
        sig = PebmPatSig(tlv(0x95, bytes.fromhex("0200 0400 41 42 43 44 9000")))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Unsupported flags", sig.decode_warnings[0])

    def test_short_payload(self):
        with self.assertRaises(ValueError):
            PebmPatSig(tlv(0x95, b"\x00\x00\x02"))

    def test_truncated_pattern(self):
        with self.assertRaises(ValueError):
            PebmPatSig(tlv(0x95, b"\x00\x00\x08\x00AB"))

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x95, self.ANON), 0)
        self.assertIsInstance(sig, PebmPatSig)


class HostsEntryTests(SignatureSnapshotMixin, unittest.TestCase):
    # SettingsModifier:Win32/PossibleHostsFileHijack: NULL microsoft.com
    MICROSOFT = bytes.fromhex("054e554c4c000e6d6963726f736f66742e636f6d00")
    # SettingsModifier:Win32/HostsFileHijack: 0.0.0.0 v4.windowsupdate...
    WINDOWSUPDATE = bytes.fromhex(
        "08302e302e302e30001f76342e77696e646f77737570646174652e6d6963726f"
        "736f66742e636f6d00"
    )

    def test_null_address(self):
        sig = HostsEntrySig(tlv(0x64, self.MICROSOFT))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_HOSTSENTRY")
        self.assertEqual(sig.address, "NULL")
        self.assertEqual(sig.host, "microsoft.com")
        self.assertTrue(sig.is_null_address)
        self.assertFalse(sig.host_wildcard)
        self.assertEqual(sig.host_suffix, "")
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "hostsentry")
        self.assertEqual(d["summary"], "HOSTSENTRY NULL microsoft.com")

    def test_explicit_address(self):
        sig = HostsEntrySig(tlv(0x64, self.WINDOWSUPDATE))
        self.assertEqual(sig.address, "0.0.0.0")
        self.assertEqual(sig.host, "v4.windowsupdate.microsoft.com")
        self.assertFalse(sig.is_null_address)
        self.assertEqual(sig.decode_warnings, [])

    def test_wildcard_host(self):
        payload = b"\x05NULL\x00" + b"\x0a*.foo.bar\x00"
        sig = HostsEntrySig(tlv(0x64, payload))
        self.assertTrue(sig.host_wildcard)
        self.assertEqual(sig.host_suffix, "foo.bar")

    def test_missing_nul(self):
        with self.assertRaises(ValueError):
            HostsEntrySig(tlv(0x64, b"\x05NULLx\x05hosts"))

    def test_truncated(self):
        with self.assertRaises(ValueError):
            HostsEntrySig(tlv(0x64, b"\x05NU"))

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x64, self.MICROSOFT), 0)
        self.assertIsInstance(sig, HostsEntrySig)


class Polyvir32Tests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:Win32/Bugbear.B: 16-byte anchor + windows (0, 0x20) and (0x40, 0x200).
    BUGBEAR = bytes.fromhex(
        "e803ee7ef7bf0bf7f7b8d34d6210bf3c0000200078fec34f40000002e27eedd40000"
    )
    # Virus:Win32/Bofra.A: two 0x2000 windows.
    BOFRA = bytes.fromhex(
        "e9415a0f3c55a96c126752606164466920002000a053466b00012000715a5f0f0000"
    )
    # Virus:DOS/ASK.7972: a 0x40 window and a 0x8000 window.
    ASK = bytes.fromhex(
        "e807004d532d444f53005eb88a16cd2f4000400099ef411580008000c64d2cd40000"
    )

    def test_bugbear_windows(self):
        sig = Polyvir32Sig(tlv(0x21, self.BUGBEAR))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_POLYVIR32")
        self.assertEqual(sig.anchor.hex(), "e803ee7ef7bf0bf7f7b8d34d6210bf3c")
        self.assertEqual(sig.window(1), (0x0000, 0x0020, 0x4FC3FE78))
        self.assertEqual(sig.window(2), (0x0040, 0x0200, 0xD4ED7EE2))
        self.assertEqual(sig.extra_length, 0)
        self.assertIsNone(sig.record_name)
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "polyvir32")
        self.assertEqual(d["window1_crc_hex"], "4fc3fe78")
        self.assertEqual(d["window2_end"], 0x240)

    def test_bofra_shared_anchor(self):
        sig = Polyvir32Sig(tlv(0x21, self.BOFRA))
        self.assertEqual(sig.window(1), (0x0020, 0x0020, 0x6B4653A0))
        self.assertEqual(sig.window(2), (0x0100, 0x0020, 0x0F5F5A71))
        self.assertEqual(sig.decode_warnings, [])

    def test_ask_text_anchor(self):
        sig = Polyvir32Sig(tlv(0x21, self.ASK))
        self.assertIn("MS-DOS", sig.anchor_text)
        self.assertEqual(sig.window(1), (0x0040, 0x0040, 0x1541EF99))
        self.assertEqual(sig.window(2), (0x0080, 0x0080, 0xD42C4DC6))
        self.assertEqual(sig.decode_warnings, [])

    def test_short_payload(self):
        with self.assertRaises(ValueError):
            Polyvir32Sig(tlv(0x21, b"\x00" * 33))

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x21, self.BUGBEAR), 0)
        self.assertIsInstance(sig, Polyvir32Sig)


if __name__ == "__main__":
    unittest.main()
