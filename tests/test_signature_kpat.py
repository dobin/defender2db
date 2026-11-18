"""Vectors from the shipped database for KPAT (0xbb) and KPATEX (0xbc)."""

import json
import unittest

from defender2yara.defender.signature import KpatExSig, KpatSig
from defender2yara.defender.vdm import Vdm


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        return details


class KpatTests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:DOS/Rex.1637: 16-bit boot code, no wildcards, anonymous.
    BOOT = bytes.fromhex(
        "18b80103bb0006b90100ba8000cd13bebe07803c80740583c6"
    )
    # Virus:DOS/AOS: ten 0x90 single-byte wildcards in the tail.
    WILDCARD = bytes.fromhex(
        "37b82135cd213e899e90903e8c8690900e58488ec0268b1e03000e0783eb9090"
        "81eb9090b44acd21bb9090b448cd21488ec026c606010008"
    )
    # !InfrastructureShared: PDF header pattern with a group label.
    PDF = bytes.fromhex(
        "2f255044462d312e340a25e2e3cfd30a312030206f626a3c3c2f537562747970"
        "652f546578742f436f6e74656e7473281221234b5041543a5044465f53756274"
        "797065"
    )

    def test_literal_boot_pattern(self):
        sig = KpatSig(tlv(0xBB, self.BOOT))
        self.assertEqual(sig.pattern_length, 24)
        self.assertEqual(sig.anchor.hex(), "b80103bb0006b901")
        self.assertEqual(sig.tail.hex(), "00ba8000cd13bebe07803c80740583c6")
        self.assertEqual(sig.name, "")
        self.assertFalse(sig.name_present)
        self.assertEqual(sig.wildcard_count, 0)
        self.assertFalse(sig.uses_wildcards)
        self.assertFalse(sig.text_like)
        self.assertEqual(sig.pattern_text, "")
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "kpat")
        self.assertEqual(d["anchor_length"], 8)
        self.assertEqual(d["tail_length"], 16)
        self.assertEqual(d["pattern_hex"],
                         "b8 01 03 bb 00 06 b9 01 00 ba 80 00 cd 13 "
                         "be be 07 80 3c 80 74 05 83 c6")

    def test_wildcard_tail(self):
        sig = KpatSig(tlv(0xBB, self.WILDCARD))
        self.assertEqual(sig.pattern_length, 55)
        self.assertEqual(sig.wildcard_count, 10)
        self.assertTrue(sig.uses_wildcards)
        self.assertEqual(sig.pattern_hex.count("??"), 10)
        self.assertTrue(sig.pattern_hex.startswith("b8 21 35 cd 21 3e 89 9e ?? ??"))
        self.assertEqual(sig.decode_warnings, [])

    def test_named_shared_pattern(self):
        sig = KpatSig(tlv(0xBB, self.PDF))
        self.assertEqual(sig.name, "!#KPAT:PDF_Subtype")
        self.assertEqual(sig.name_length, 18)
        self.assertTrue(sig.name_present)
        self.assertTrue(sig.text_like)
        self.assertEqual(
            sig.pattern_text,
            "%PDF-1.4\\x0a%\\xe2\\xe3\\xcf\\xd3\\x0a1 0 obj"
            "<</Subtype/Text/Contents(",
        )
        d = self.snapshot(sig)
        self.assertTrue(d["has_name"])
        self.assertEqual(d["record_name"], "!#KPAT:PDF_Subtype")

    def test_router(self):
        sig = Vdm.decode_record(tlv(0xBB, self.BOOT), 0)
        self.assertIsInstance(sig, KpatSig)


class KpatExTests(SignatureSnapshotMixin, unittest.TestCase):
    # Worm:Win32/Autorun!inf: text pattern with a skip-range wildcard.
    AUTORUN = bytes.fromhex(
        "190d0a5b4175546f72756e5d9002ff0d0a616374694f4e3d9000"
    )
    # TrojanDownloader:Win32/Swif.AB: ActionScript bytecode with a byte class.
    SWIF = bytes.fromhex(
        "2e960400080008011c3c960400080208001c4796020008034796020008049003"
        "06051c9a010040079a010000079000"
    )
    # !InfrastructureShared: short SWF string-table pattern.
    SAFESTR = bytes.fromhex(
        "0b5f536166655374725f90001f21234b5041543a5357462f4f62667573636174"
        "6f722e536166655374722e41"
    )
    # !InfrastructureShared: eight-byte anchor plus a 0x25-byte skip.
    COBALT = bytes.fromhex(
        "12fc4883e4f0eb335d8b9001257402ebe79000192123534c465045523a"
        "4b5041543a436f62426561636f6e2e41"
    )
    # !InfrastructureShared: explicit KPATEX label, zero-byte-heavy anchor.
    FRAME = bytes.fromhex(
        "1a010000006672616d65319002800a63686172436f6465417490001a21234b"
        "50415445583a6672616d65315f63686172436f64654174"
    )

    def test_text_pattern_and_skip_range(self):
        sig = KpatExSig(tlv(0xBC, self.AUTORUN))
        self.assertEqual(sig.pattern_length, 25)
        self.assertEqual(sig.tail.hex(), "756e5d9002ff0d0a616374694f4e3d9000")
        self.assertEqual(sig.opcode_counts, {0x00: 1, 0x02: 1})
        self.assertEqual(sig.wildcard_count, 1)
        self.assertTrue(sig.text_like)
        self.assertEqual(sig.pattern_hex,
                         "0d 0a 5b 41 75 54 6f 72 75 6e 5d [0-255] "
                         "0d 0a 61 63 74 69 4f 4e 3d")
        self.assertEqual(sig.pattern_text,
                         "\\x0d\\x0a[AuTorun]<skip 0..255>\\x0d\\x0aactiON=")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "kpatex")
        self.assertEqual(d["opcode_counts"], {"00": 1, "02": 1})
        self.assertEqual(sig.decode_status, "decoded")

    def test_byte_class(self):
        sig = KpatExSig(tlv(0xBC, self.SWIF))
        self.assertEqual(sig.pattern_length, 46)
        self.assertEqual(sig.opcode_counts, {0x00: 1, 0x03: 1})
        self.assertIn(
            "((1c | 9a | 01 | 00 | 40) x6)",
            sig.pattern_hex,
        )
        self.assertFalse(sig.text_like)
        self.assertEqual(sig.decode_warnings, [])

    def test_named_short_pattern(self):
        sig = KpatExSig(tlv(0xBC, self.SAFESTR))
        self.assertEqual(sig.pattern_length, 11)
        self.assertEqual(sig.anchor, b"_SafeStr")
        self.assertEqual(sig.tail, b"_\x90\x00")
        self.assertEqual(sig.name, "!#KPAT:SWF/Obfuscator.SafeStr.A")
        self.assertEqual(sig.pattern_hex, "5f 53 61 66 65 53 74 72 5f")
        self.assertEqual(sig.pattern_text, "_SafeStr_")
        self.assertEqual(sig.wildcard_count, 0)  # 90 00 is the terminator
        self.assertEqual(sig.decode_status, "decoded")

    def test_skip_token(self):
        sig = KpatExSig(tlv(0xBC, self.COBALT))
        self.assertEqual(sig.name, "!#SLFPER:KPAT:CobBeacon.A")
        self.assertEqual(sig.pattern_hex,
                         "fc 48 83 e4 f0 eb 33 5d 8b [37] 74 02 eb e7")

    def test_named_extended_pattern(self):
        sig = KpatExSig(tlv(0xBC, self.FRAME))
        self.assertEqual(sig.pattern_length, 26)
        self.assertEqual(sig.name, "!#KPATEX:frame1_charCodeAt")
        self.assertEqual(sig.pattern_hex,
                         "01 00 00 00 66 72 61 6d 65 31 [0-128] "
                         "0a 63 68 61 72 43 6f 64 65 41 74")
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#KPATEX:frame1_charCodeAt")

    def test_router(self):
        sig = Vdm.decode_record(tlv(0xBC, self.AUTORUN), 0)
        self.assertIsInstance(sig, KpatExSig)


class KeyPatternErrorTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_short_payload(self):
        with self.assertRaises(ValueError):
            KpatSig(tlv(0xBB, b"\x08" + b"\x00" * 7))

    def test_pattern_shorter_than_anchor(self):
        with self.assertRaises(ValueError):
            KpatSig(tlv(0xBB, b"\x04" + b"\x00" * 8))

    def test_truncated_pattern(self):
        with self.assertRaises(ValueError):
            KpatSig(tlv(0xBB, b"\x20" + b"\x00" * 8))

    def test_truncated_name(self):
        payload = b"\x0c" + b"\x41" * 12 + b"\x20name"
        with self.assertRaises(ValueError):
            KpatExSig(tlv(0xBC, payload))

    def test_missing_terminator_is_partial(self):
        payload = b"\x0a" + b"A" * 8 + b"\x90\x01"
        sig = KpatExSig(tlv(0xBC, payload))
        self.assertEqual(sig.pattern_length, 10)
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn(
            "Pattern does not end with the 0x90 0x00 terminator",
            sig.decode_warnings,
        )

    def test_trailing_data_is_partial(self):
        payload = b"\x0a" + b"A" * 8 + b"\x90\x00" + b"\x00" + b"\x00"
        sig = KpatExSig(tlv(0xBC, payload))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Unexpected trailing data: 1 bytes", sig.decode_warnings)


if __name__ == "__main__":
    unittest.main()
