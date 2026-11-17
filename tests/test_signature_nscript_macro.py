"""Vectors from the shipped database for NSCRIPT_SP, NSCRIPT_BRUTE and MACRO_SOURCE."""

import json
import struct
import unittest

from defender2yara.defender.signature import (
    MacroSourceSig, NscriptBruteSig, NscriptSpSig,
)
from defender2yara.defender.signature.nscript import (
    decode_script_pattern, script_type_name,
)
from defender2yara.defender.vdm import Vdm


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        self.assertEqual(sig.decode_status, "decoded")
        return details


class NscriptSpTests(SignatureSnapshotMixin, unittest.TestCase):
    # Backdoor:Win32/Hupigon: hash1, flags, hash2, window
    BASE = bytes.fromhex("00656f27f2048c9b298dee000000")

    def test_anonymous_hash_pair(self):
        sig = NscriptSpSig(tlv(0x28, self.BASE))
        self.assertEqual(sig.name, "")
        self.assertEqual(sig.name_length, 0)
        self.assertEqual(sig.hash1, 0xF2276F65)
        self.assertEqual(sig.flags, 0x04)
        self.assertEqual(sig.hash2, 0x8D299B8C)
        self.assertEqual(sig.match_length, 238)
        self.assertFalse(sig.flag_high)
        self.assertFalse(sig.irc_special_case)
        d = self.snapshot(sig)
        self.assertEqual(d["match_length"], 238)
        self.assertEqual(d["flags_low"], 4)

    def test_named_reference_and_high_flag(self):
        name = b"!#TEL:HTML/CoinHive.C!lib"
        payload = (bytes([len(name)]) + name
                   + struct.pack("<I", 0x11223344) + b"\x82"
                   + struct.pack("<II", 0x55667788, 0x1000))
        sig = NscriptSpSig(tlv(0x28, payload))
        self.assertEqual(sig.name, "!#TEL:HTML/CoinHive.C!lib")
        self.assertTrue(sig.flag_high)
        self.assertTrue(sig.irc_special_case)
        self.assertEqual(sig.match_length, 0x1000)
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#TEL:HTML/CoinHive.C!lib")
        self.assertTrue(d["flag_0x80"])

    def test_short_and_trailing_records(self):
        with self.assertRaises(ValueError):
            NscriptSpSig(tlv(0x28, self.BASE[:8]))
        sig = NscriptSpSig(tlv(0x28, self.BASE + b"\x00"))
        self.assertEqual(sig.decode_status, "partial")
        self.assertTrue(sig.decode_warnings)

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x28, self.BASE), 0)
        self.assertIsInstance(sig, NscriptSpSig)


class NscriptBruteTests(SignatureSnapshotMixin, unittest.TestCase):
    # Backup of the real AdRotator record: name_len=0, kind=0 (any), mode=2,
    # any_length=0xffffffff, 51-byte pattern ending in 90 00.
    PATTERN = (b"thisnameisignoredsowhybother?eim01.exets_www2.exe" + b"\x90\x00")
    BASE = bytes([0, 0, 2]) + struct.pack("<II", 0xFFFFFFFF, len(PATTERN)) + PATTERN

    def test_literal_pattern(self):
        sig = NscriptBruteSig(tlv(0x29, self.BASE))
        self.assertEqual(sig.script_type, "any")
        self.assertEqual(sig.kind, 6)
        self.assertEqual(sig.mode, 2)
        self.assertEqual(sig.any_length, 0xFFFFFFFF)
        self.assertEqual(sig.pattern_length, len(self.PATTERN))
        self.assertIn("thisnameisignoredsowhybother?", sig.pattern_text)
        self.assertFalse(sig.uses_wildcards)
        self.assertTrue(sig.loose_pattern is False)
        self.assertTrue(sig.flags & 0x0800)
        d = self.snapshot(sig)
        self.assertEqual(d["mode_label"], "backward")
        self.assertFalse(d["any_length_set"])

    def test_script_types(self):
        self.assertEqual(script_type_name(1), "vbs")
        self.assertEqual(script_type_name(2), "js")
        self.assertEqual(script_type_name(3), "bat")
        self.assertEqual(script_type_name(4), "irc")
        self.assertEqual(script_type_name(5), "ps")
        self.assertEqual(script_type_name(6), "py")
        self.assertEqual(script_type_name(0), "any")
        self.assertEqual(script_type_name(7), "any")
        self.assertEqual(script_type_name(0x84), "irc")

    def test_kind_byte_and_flag_word(self):
        pattern = b"abc\x90\x00"
        payload = bytes([0]) + bytes([0x84, 1]) + struct.pack("<II", 0x80, len(pattern)) + pattern
        sig = NscriptBruteSig(tlv(0x29, payload))
        self.assertEqual(sig.script_type, "irc")
        self.assertEqual(sig.kind, 3)
        self.assertTrue(sig.kind_high_flag)
        self.assertEqual(sig.mode, 1)
        self.assertTrue(sig.flags & 0x0400)
        # mode 1 << 5 | kind 3 << 7 | 0x400 | 0x800
        self.assertEqual(sig.flags, (1 << 5) | (3 << 7) | 0x0400 | 0x0800)

    def test_wildcards_are_rendered(self):
        pattern = b"http://" + b"\x90\x02\x03" + b"." + b"\x90\x02\x03" + b":81/"
        pattern += b"\x90\x01\x07" + b".php\x90\x00"
        payload = bytes([0, 0, 0]) + struct.pack("<II", 0xFFFFFFFF, len(pattern)) + pattern
        sig = NscriptBruteSig(tlv(0x29, payload))
        self.assertTrue(sig.uses_wildcards)
        self.assertEqual(
            sig.pattern_text,
            "http://<skip 0..3>.<skip 0..3>:81/<skip 7>.php",
        )
        self.assertEqual(sig.wildcard_count, 4)
        self.assertFalse(sig.loose_pattern)

    def test_named_and_loose_pattern(self):
        name = b"!#SCPT:Trojan:JS/NPMInstall.PR!AMTB"
        pattern = b"eval(" + b"\x90\x1b\x02\xaa" + b")\x90\x00"
        payload = (bytes([len(name)]) + name + bytes([2, 0])
                   + struct.pack("<II", 0x20, len(pattern)) + pattern)
        sig = NscriptBruteSig(tlv(0x29, payload))
        self.assertEqual(sig.name, "!#SCPT:Trojan:JS/NPMInstall.PR!AMTB")
        self.assertEqual(sig.script_type, "js")
        self.assertEqual(sig.any_length, 0x20)
        self.assertTrue(sig.loose_pattern)
        self.assertNotIn(0x0800, [sig.flags & 0x0800])
        d = self.snapshot(sig)
        self.assertTrue(d["loose_pattern"])
        self.assertTrue(d["any_length_set"])

    def test_terminator_warning_and_truncation(self):
        pattern = b"abc"
        payload = bytes([0, 0, 0]) + struct.pack("<II", 0xFFFFFFFF, len(pattern)) + pattern
        sig = NscriptBruteSig(tlv(0x29, payload))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("terminator", " ".join(sig.decode_warnings))
        with self.assertRaises(ValueError):
            NscriptBruteSig(tlv(0x29, bytes([0, 0, 0]) + struct.pack("<II", 0, 100) + b"short"))

    def test_nul_escapes(self):
        self.assertEqual(decode_script_pattern(b"a\x00b\x90\x00"), "a\\x00b")

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x29, self.BASE), 0)
        self.assertIsInstance(sig, NscriptBruteSig)


class MacroSourceTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_single_routine_with_second_hash(self):
        # Real record: header 0x101 (count=1, kind=0x101>>6=4 vba_source),
        # low=0xe14561fd, high=0x2aaad95b.
        payload = bytes.fromhex("00010100" "00" "fd6145e1" "5bd9aa2a")
        sig = MacroSourceSig(tlv(0x43, payload))
        self.assertEqual(sig.routine_count, 1)
        self.assertEqual(sig.source_kind, 4)
        self.assertEqual(sig.source_kind_label, "vba_source")
        self.assertTrue(sig.has_second_hash_array)
        self.assertEqual(sig.routine_keys, [0x2AAAD95BE14561FD])
        self.assertEqual(sig.routine_keys_hex, ["2aaad95be14561fd"])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["routine_count"], 1)
        self.assertEqual(d["source_kind"], 4)
        self.assertEqual(d["routine_keys"], ["2aaad95be14561fd"])

    def test_low_array_only(self):
        name = b"!#SSF:ScanAllStreams"
        payload = (bytes([len(name)]) + name
                   + struct.pack("<I", (4 << 6) | 1)
                   + struct.pack("<I", 0x964FC617))
        sig = MacroSourceSig(tlv(0x43, payload))
        self.assertEqual(sig.name, "!#SSF:ScanAllStreams")
        self.assertFalse(sig.has_second_hash_array)
        self.assertEqual(sig.hash_high, [0])
        self.assertEqual(sig.routine_keys, [0x964FC617])
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#SSF:ScanAllStreams")
        self.assertFalse(d["has_second_hash_array"])

    def test_multiple_routines_and_kinds(self):
        for kind, label in ((0, "word6_excel5_macro_source"), (2, "excel_formula"),
                            (4, "vba_source"), (8, "excel_formula_routines")):
            payload = (bytes([0]) + struct.pack("<I", (kind << 6) | 2)
                       + struct.pack("<II", 0x11111111, 0x22222222)
                       + struct.pack("<II", 0x33333333, 0x44444444))
            sig = MacroSourceSig(tlv(0x43, payload))
            self.assertEqual(sig.source_kind_label, label)
            self.assertEqual(sig.routine_count, 2)
            self.assertEqual(sig.routine_keys,
                             [0x3333333311111111, 0x4444444422222222])

    def test_unexpected_trailing_data_is_partial(self):
        payload = bytes([0]) + struct.pack("<I", 1) + struct.pack("<I", 0x12345678) + b"zz"
        sig = MacroSourceSig(tlv(0x43, payload))
        self.assertEqual(sig.decode_status, "partial")
        self.assertTrue(sig.decode_warnings)

    def test_truncated_table(self):
        with self.assertRaises(ValueError):
            MacroSourceSig(tlv(0x43, bytes([0]) + struct.pack("<I", 3) + b"\x01\x02"))

    def test_router(self):
        payload = bytes([0]) + struct.pack("<I", 1) + struct.pack("<I", 0x12345678)
        sig = Vdm.decode_record(tlv(0x43, payload), 0)
        self.assertIsInstance(sig, MacroSourceSig)


if __name__ == "__main__":
    unittest.main()
