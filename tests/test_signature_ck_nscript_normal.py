"""Vectors from the shipped database for CKSIMPLEREC, CKOLDREC and NSCRIPT_NORMAL."""

import json
import struct
import unittest

from defender2yara.defender.signature import (
    CkOldRecSig, CkSimpleRecSig, NscriptNormalSig,
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


class CkSimpleRecTests(SignatureSnapshotMixin, unittest.TestCase):
    # Trojan:DOS/Telefoon: first four bytes + header CRC + region CRC.
    BASE = bytes.fromhex("601ee83bf7eb02431000310189e1184803000000")

    def test_anonymous_checksum_record(self):
        sig = CkSimpleRecSig(tlv(0x50, self.BASE))
        self.assertEqual(sig.file_prefix_hex, "601ee83b")
        self.assertEqual(sig.header_crc, 0x4302EBF7)
        self.assertEqual(sig.region_offset, 16)
        self.assertEqual(sig.region_length, 305)
        self.assertEqual(sig.region_crc, 0x4818E189)
        self.assertEqual(sig.flags, 3)
        self.assertEqual(sig.scan_group, 0)
        self.assertEqual(sig.flags_low, 3)
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "cksimplerec")
        self.assertEqual(d["header_length"], 0x10)
        self.assertEqual(d["file_prefix_text"], "601ee83b (`..;)")

    def test_literal_mz_prefix_and_name(self):
        # !InfrastructureShared @ 0x50 payload size 0x1d: prefix is the DOS
        # header "MZ", region = first 0x40 bytes, label "!LHASFX".
        payload = bytes.fromhex(
            "4d5a6400b30e77301000400091a972070000000008214c484153465800"
        )
        sig = CkSimpleRecSig(tlv(0x50, payload))
        self.assertEqual(sig.file_prefix_raw, b"MZ\x64\x00")
        self.assertEqual(sig.file_prefix_text, "4d5a6400 (MZd.)")
        self.assertEqual(sig.region_offset, 0x10)
        self.assertEqual(sig.region_length, 0x40)
        self.assertEqual(sig.name, "!LHASFX")
        self.assertEqual(sig.name_length, 7)
        d = self.snapshot(sig)
        self.assertTrue(d["has_name"])
        self.assertEqual(d["record_name"], "!LHASFX")

    def test_truncated_payload(self):
        with self.assertRaises(ValueError):
            CkSimpleRecSig(tlv(0x50, self.BASE[:19]))

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x50, self.BASE), 0)
        self.assertIsInstance(sig, CkSimpleRecSig)


class CkOldRecTests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:DOS/Demi: two explicit regions.
    BASE = bytes.fromhex("060010001a2fb7201600220014c4060f03000000")

    def test_two_regions(self):
        sig = CkOldRecSig(tlv(0x11, self.BASE))
        self.assertEqual(sig.region1_offset, 6)
        self.assertEqual(sig.region1_length, 0x10)
        self.assertEqual(sig.region1_crc, 0x20B72F1A)
        self.assertEqual(sig.region2_offset, 0x16)
        self.assertEqual(sig.region2_length, 0x22)
        self.assertEqual(sig.region2_crc, 0x0F06C414)
        self.assertEqual(sig.flags, 3)
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "ckoldrec")
        self.assertEqual(d["region2_offset"], 0x16)

    def test_trailing_non_nul_name(self):
        # Single shipped record: name length includes the missing NUL.
        payload = self.BASE + b"\x0a~Holupfpos"
        sig = CkOldRecSig(tlv(0x11, payload))
        self.assertEqual(sig.name, "~Holupfpos")
        self.assertEqual(sig.name_length, 10)

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x11, self.BASE), 0)
        self.assertIsInstance(sig, CkOldRecSig)


class NscriptNormalTests(SignatureSnapshotMixin, unittest.TestCase):
    # Exploit:JS/CreateText: one hash pair.
    PAIR = bytes.fromhex("0001e833e86f005416cdc1")
    # Trojan:JS/Torvil: two hash pairs (count=2, then the second hash array).
    TWO_PAIRS = bytes.fromhex("000255d8e709f36f2a18001a001e112d02d38b")
    # Virus:BAT/Ataris.A: flags=1 => window form (hash1, window length).
    WINDOW = bytes.fromhex("0001403a80960177db7b09ac000000")
    # !InfrastructureShared #fp6234: compact variant, no hash_b array.
    COMPACT = bytes.fromhex("072366703632333402b46e2766ab22b05e00")

    def test_hash_pair(self):
        sig = NscriptNormalSig(tlv(0x27, self.PAIR))
        self.assertEqual(sig.count, 1)
        self.assertEqual(sig.hash_a, [0x6FE833E8])
        self.assertEqual(sig.hash_b, [0xC1CD1654])
        self.assertEqual(sig.flags, 0)
        self.assertFalse(sig.compact_variant)
        self.assertEqual(sig.conditions, [{
            "kind": "hash_pair", "hash1": 0x6FE833E8, "hash2": 0xC1CD1654,
        }])
        d = self.snapshot(sig)
        self.assertEqual(d["condition_form"], "hash_pairs")

    def test_multiple_hash_pairs(self):
        sig = NscriptNormalSig(tlv(0x27, self.TWO_PAIRS))
        self.assertEqual(sig.count, 2)
        self.assertEqual(sig.hash_a, [0x09E7D855, 0x182A6FF3])
        self.assertEqual(sig.hash_b, [0x111E001A, 0x8BD3022D])
        self.assertEqual([c["kind"] for c in sig.conditions], ["hash_pair"] * 2)

    def test_window_form(self):
        sig = NscriptNormalSig(tlv(0x27, self.WINDOW))
        self.assertEqual(sig.count, 1)
        self.assertEqual(sig.flags, 1)
        self.assertTrue(sig.irc_special_case)
        self.assertEqual(sig.window_hash, 0x097BDB77)
        self.assertEqual(sig.window_length, 172)
        self.assertEqual(sig.hash_a, [0x96803A40])
        self.assertEqual(sig.conditions, [{
            "kind": "window",
            "hash1": 0x097BDB77,
            "hash2": 0x96803A40,
            "match_length": 172,
        }])
        d = self.snapshot(sig)
        self.assertEqual(d["condition_form"], "window")
        self.assertEqual(d["window_length"], 172)

    def test_compact_variant(self):
        sig = NscriptNormalSig(tlv(0x27, self.COMPACT))
        self.assertEqual(sig.name, "#fp6234")
        self.assertTrue(sig.compact_variant)
        self.assertEqual(sig.count, 2)
        self.assertEqual(sig.hash_b, [])
        self.assertEqual(sig.conditions, [])
        self.assertEqual(self.snapshot(sig)["compact_variant"], True)

    def test_truncated_records(self):
        with self.assertRaises(ValueError):
            NscriptNormalSig(tlv(0x27, b"\x00\x01\x00\x00\x00"))
        # flags=1 promises a window condition but value/window are missing.
        with self.assertRaises(ValueError):
            NscriptNormalSig(tlv(0x27, b"\x00\x01" + b"\x00" * 4 + b"\x01"
                                         + b"\x00" * 4))

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x27, self.WINDOW), 0)
        self.assertIsInstance(sig, NscriptNormalSig)


if __name__ == "__main__":
    unittest.main()
