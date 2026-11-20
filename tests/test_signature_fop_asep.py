"""Vectors from the shipped database for FOP/FOPEX and the ASEP path types."""

import json
import unittest

from defender2yara.defender.signature import (
    AsepFilePathSig,
    AsepFolderNameSig,
    Fop64Sig,
    FopEx64Sig,
    FopExSig,
    FopSig,
)
from defender2yara.defender.signature.pathname import PATHNAME_SIGS
from defender2yara.defender.vdm import Vdm


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        return details


class FopTests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:Win95/Sgae.631: anonymous literal x86 fragment.
    SGAE = bytes.fromhex(
        "7f25000000002100b860eb9090908a838b3c7590909090eb90909066c16657e8"
        "eb9090900f8b8356eb"
    )
    # !ASprotect: named x86 code fragment, no wildcards.
    ASPROTECT = bytes.fromhex(
        "7f380000000a2a0021415370726f74656374bb032b83890f8d50ff898b8d5350ff"
        "898d5357ff898b896a68686aff898d5053e88b8d8bf38b686a50ff"
    )

    def test_literal_anonymous_pattern(self):
        sig = FopSig(self.SGAE)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_FOP")
        self.assertEqual(sig.flags, 0)
        self.assertEqual(sig.name_length, 0)
        self.assertFalse(sig.name_present)
        self.assertEqual(sig.pattern_length, 33)
        self.assertEqual(len(sig.pattern), 33)
        self.assertEqual(sig.pattern[:4].hex(), "b860eb90")
        self.assertTrue(sig.is_literal)
        self.assertFalse(sig.text_like)
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "fop")
        self.assertTrue(d["is_literal"])
        self.assertEqual(d["pattern_length"], 33)

    def test_named_pattern(self):
        sig = FopSig(self.ASPROTECT)
        self.assertEqual(sig.name, "!ASprotect")
        self.assertEqual(sig.name_length, 10)
        self.assertTrue(sig.name_present)
        self.assertEqual(sig.pattern_length, 42)
        self.assertTrue(sig.pattern.startswith(b"\xbb\x03+"))
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!ASprotect")
        self.assertTrue(d["has_name"])

    def test_router(self):
        sig = Vdm.decode_record(self.SGAE, 0)
        self.assertIsInstance(sig, FopSig)


class FopExTests(SignatureSnapshotMixin, unittest.TestCase):
    # TrojanDropper:Win32/Cutwail.gen!C: literal prefix + wildcard body.
    CUTWAIL = bytes.fromhex(
        "892f000000000c00190000002a00558b648b252d6675a38d515090020648656170"
        "416c6c6f630090030204ff15536574549000"
    )
    # !#Tracur_LoDCheck: optional name, 3-byte prefix, 3-byte body.
    TRACUR = bytes.fromhex(
        "892100000011030003000000070021235472616375725f4c6f44436865636b"
        "b948e2fd9000"
    )
    # Anonymous variant with the optional one-byte suffix.
    SUFFIX = bytes.fromhex(
        "8952000000000500420001000000"
        "b8e8a3830fb8900104e8900104a3900104900210833d901b02000f8490010490"
        "0215ba901b00a1901b02e8900104900210a1901b02e8900104900210c7059001"
        "0401000000900089"
    )

    def test_prefix_and_wildcard_body(self):
        sig = FopExSig(self.CUTWAIL)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_FOPEX")
        self.assertEqual(sig.flags, 0)
        self.assertEqual(sig.prefix_length, 12)
        self.assertEqual(sig.body_length, 25)
        self.assertEqual(sig.suffix_length, 0)
        self.assertEqual(sig.file_offset, 42)
        self.assertEqual(sig.prefix.hex(), "558b648b252d6675a38d5150")
        self.assertEqual(sig.body[:4].hex(), "90020648")
        self.assertTrue(sig.body.endswith(b"\x90\x00"))
        self.assertEqual(sig.pattern, sig.prefix + sig.body + sig.suffix)
        self.assertEqual(sig.opcode_counts, {0x00: 1, 0x02: 1, 0x03: 1})
        self.assertEqual(sig.wildcard_count, 2)
        self.assertTrue(sig.uses_wildcards)
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "fopex")
        self.assertEqual(d["file_offset"], 42)
        self.assertEqual(d["prefix_length"], 12)
        self.assertEqual(d["body_length"], 25)

    def test_named_pattern(self):
        sig = FopExSig(self.TRACUR)
        self.assertEqual(sig.name, "!#Tracur_LoDCheck")
        self.assertEqual(sig.name_length, 17)
        self.assertEqual(sig.prefix, bytes.fromhex("b948e2"))
        self.assertEqual(sig.body, bytes.fromhex("fd9000"))
        self.assertEqual(sig.suffix, b"")
        self.assertEqual(sig.file_offset, 7)
        self.assertEqual(sig.pattern_hex, "b9 48 e2 fd")
        self.assertTrue(sig.pattern_text.startswith("\\xb9H\\xe2"))
        self.assertEqual(sig.decode_warnings, [])

    def test_optional_suffix(self):
        sig = FopExSig(self.SUFFIX)
        self.assertEqual(sig.prefix_length, 5)
        self.assertEqual(sig.body_length, 0x42)
        self.assertEqual(sig.suffix_length, 1)
        self.assertEqual(sig.suffix, b"\x89")
        self.assertEqual(sig.file_offset, 0)
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(len(sig.pattern), 72)

    def test_record_offset_not_overwritten(self):
        # The payload's signed match offset must not clobber the VDM record
        # offset, which is the signature table's unique key.
        data = b"\x00" * 16 + self.CUTWAIL
        sig = FopExSig(data, 16)
        self.assertEqual(sig.offset, 16)
        self.assertEqual(sig.file_offset, 42)
        self.assertEqual(sig.offset + sig.record_size, 16 + len(self.CUTWAIL))

    def test_router(self):
        sig = Vdm.decode_record(self.CUTWAIL, 0)
        self.assertIsInstance(sig, FopExSig)


class Fop64Tests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:Win64/Expiro.gen!AD: x64 literal fragment.
    EXPIRO = bytes.fromhex(
        "c8240000000020009055485648574141414148494c49494cbe4c494d4dc74449"
        "4d44494c4cc7494d"
    )

    def test_fop64_literal_pattern(self):
        sig = Fop64Sig(self.EXPIRO)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_FOP64")
        self.assertEqual(sig.layout, "fop64")
        self.assertEqual(sig.pattern_length, 32)
        self.assertEqual(sig.pattern[:4].hex(), "90554856")
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        self.assertEqual(self.snapshot(sig)["layout"], "fop64")

    def test_router(self):
        sig = Vdm.decode_record(self.EXPIRO, 0)
        self.assertIsInstance(sig, Fop64Sig)


class FopEx64Tests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:Win64/Expiro.A: x64 wildcard pattern with a 70-byte offset.
    EXPIRO = bytes.fromhex(
        "c935000000001e000d00000046004c4d4c4d4d494c4d4d49484c49e8484c4849"
        "494c4d4d4d484c49e8c9e9c38b55a8489949f7fa4989c19000"
    )

    def test_fopex64_pattern(self):
        sig = FopEx64Sig(self.EXPIRO)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_FOPEX64")
        self.assertEqual(sig.layout, "fopex64")
        self.assertEqual(sig.prefix_length, 30)
        self.assertEqual(sig.body_length, 13)
        self.assertEqual(sig.suffix_length, 0)
        self.assertEqual(sig.file_offset, 70)
        self.assertTrue(sig.body.endswith(b"\x90\x00"))
        self.assertEqual(sig.decode_warnings, [])
        self.assertEqual(sig.decode_status, "decoded")
        self.assertEqual(self.snapshot(sig)["file_offset"], 70)

    def test_router(self):
        sig = Vdm.decode_record(self.EXPIRO, 0)
        self.assertIsInstance(sig, FopEx64Sig)


class FopErrorTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_fop_short_payload(self):
        with self.assertRaises(ValueError):
            FopSig(tlv(0x7F, b"\x00\x00\x02"))

    def test_fop_truncated_pattern(self):
        with self.assertRaises(ValueError):
            FopSig(tlv(0x7F, b"\x00\x00\x08\x00AB"))

    def test_fop_invalid_flags_warn(self):
        sig = FopSig(tlv(0x7F, b"\x02\x00\x02\x00AB"))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Unsupported flags", sig.decode_warnings[0])

    def test_fopex_short_payload(self):
        with self.assertRaises(ValueError):
            FopExSig(tlv(0x89, b"\x00" * 9))

    def test_fopex_truncated_blocks(self):
        payload = b"\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00A"
        with self.assertRaises(ValueError):
            FopExSig(tlv(0x89, payload))


class AsepPathTests(SignatureSnapshotMixin, unittest.TestCase):
    # Worm:Win32/Korgo.AY: CSIDL_SYSTEM + relative file name.
    KORGO = bytes.fromhex("710d000025005c6674707564702e657865")
    # Worm:Win32/Msblast.F: %windir% + nested file name.
    MSBLAST = bytes.fromhex("7114000024005c73797374656d5c657363686c702e657865")

    def test_asep_filepath(self):
        sig = AsepFilePathSig(self.KORGO)
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_ASEP_FILEPATH")
        self.assertEqual(sig.root_id, 0x25)
        self.assertEqual(sig.root_name, "SYSTEM")
        self.assertEqual(sig.path, "\\ftpudp.exe")
        self.assertEqual(sig.rendering, "%SystemRoot%\\System32\\ftpudp.exe")
        self.assertTrue(sig.ASEP)
        self.assertEqual(sig.describe(), "ASEP_FILEPATH %SystemRoot%\\System32\\ftpudp.exe")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "asep_filepath")
        self.assertTrue(d["is_asep"])
        self.assertEqual(sig.decode_status, "decoded")

    def test_asep_filepath_windir(self):
        sig = AsepFilePathSig(self.MSBLAST)
        self.assertEqual(sig.root_name, "WINDOWS")
        self.assertEqual(sig.rendering, "%windir%\\system\\eschlp.exe")

    def test_asep_foldername_shares_layout(self):
        # No 0x75 records ship in this database; the decoder shares the payload.
        sig = AsepFolderNameSig(tlv(0x75, b"\x26\x00\\common files\\kuum"))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_ASEP_FOLDERNAME")
        self.assertEqual(sig.rendering, "%ProgramFiles%\\common files\\kuum")
        self.assertIn("SIGNATURE_TYPE_ASEP_FOLDERNAME", PATHNAME_SIGS)

    def test_router(self):
        sig = Vdm.decode_record(self.KORGO, 0)
        self.assertIsInstance(sig, AsepFilePathSig)


if __name__ == "__main__":
    unittest.main()
