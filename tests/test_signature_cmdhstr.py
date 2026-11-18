import struct
import unittest

from defender2yara.defender.signature.hstr import (
    CmdHStrExtSig,
    DexHStrExtSig,
    HStrExtSig,
    decode_hstr_pattern,
)
from defender2yara.defender.subrule.hstr import HStrExtSubRule


def tlv(sig_type: int, payload: bytes) -> bytes:
    size = len(payload)
    return bytes([sig_type, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF]) + payload


def subrule(weight: int, flags: int, pattern: bytes, extra: int | None = None) -> bytes:
    head = struct.pack("<hBB", weight, len(pattern), flags)
    if extra is not None:
        head += bytes([extra])
    return head + pattern


class CmdHStrExtTests(unittest.TestCase):
    # Trojan:Win32/Kovter.G — two UTF-16 command-line fragments.
    PATTERN = (
        b"m\x00s\x00h\x00t\x00a\x00"
        b"\x90\x02\x10"
        b"j\x00a\x00v\x00a\x00s\x00c\x00r\x00i\x00p\x00t\x00:\x00"
        b"\x90\x00"
    )

    def payload(self) -> bytes:
        return (
            struct.pack("<HHH", 1, 1, 1)
            + b"\x00"
            + subrule(1, 0x02, self.PATTERN)
            + b"\x00\x00"
        )

    def test_command_line_signature_decodes_as_wide_text(self):
        sig = CmdHStrExtSig(tlv(0xD7, self.payload()))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_CMDHSTR_EXT")
        self.assertEqual(sig.threshold, 1)
        self.assertEqual(sig.tail_words, [0])
        self.assertEqual(len(sig.subrules), 1)
        rule = sig.subrules[0]
        self.assertTrue(rule.wildcard)
        self.assertFalse(rule.case_sensitive)
        self.assertEqual(rule.encoding, "utf-16-le")
        self.assertEqual(
            rule.pattern_text,
            "mshta<skip 0..16>javascript:",
        )
        self.assertEqual(sig.patterns, [rule.pattern_text])
        details = sig.to_details()
        self.assertEqual(details["scan_target"], "command_line")
        self.assertIn("HSTR_CALLER_CMDLINE", " ".join(details["scan_callers"]))
        self.assertEqual(details["variant"], "normal")

    def test_fast_variant(self):
        sig = CmdHStrExtSig(tlv(0xDD, self.payload()))
        self.assertEqual(sig.sig_type, "SIGNATURE_TYPE_CMDHSTR_FAST_EXT")
        self.assertEqual(sig.to_details()["variant"], "fast")

    def test_extended_subrule_has_extra_flag_byte(self):
        payload = (
            struct.pack("<HHH", 1, 1, 1)
            + b"\x00"
            + subrule(1, 0x80, b"test", extra=1)
            + b"\x00\x00"
        )
        sig = CmdHStrExtSig(tlv(0xD7, payload))
        self.assertEqual(len(sig.subrules), 1)
        rule = sig.subrules[0]
        self.assertEqual(rule.extra, 1)
        self.assertTrue(rule.extended)
        self.assertTrue(rule.variant)
        self.assertEqual(rule.rule_bytes, b"test")
        self.assertEqual(rule.entry_size, 9)
        self.assertEqual(rule.pattern_text, "test")


class DexHStrExtTests(unittest.TestCase):
    def test_string_pattern_with_alternative(self):
        pattern = b"com\x90\x03\x01\x01./geinimi\x90\x00"
        payload = (
            struct.pack("<HHH", 1, 1, 1)
            + b"\x00"
            + subrule(1, 0x03, pattern)
            + b"\x00\x00"
        )
        sig = DexHStrExtSig(tlv(0xBE, payload))
        self.assertEqual(sig.subrules[0].pattern_text, 'com<any-of {2e} x1>/geinimi')

    def test_second_tail_word_is_exposed(self):
        pattern = b"fillSmsInfo()"
        payload = (
            struct.pack("<HHH", 1, 1, 1)
            + b"\x00"
            + subrule(1, 0x01, pattern)
            + struct.pack("<HH", 0, 3)
        )
        sig = DexHStrExtSig(tlv(0xBE, payload))
        self.assertEqual(sig.tail_words, [0, 3])
        self.assertEqual(sig.end_marker, 0)
        self.assertTrue(sig.flags_present)
        self.assertEqual(sig.flags, 3)
        self.assertEqual(sig.patterns, ["fillSmsInfo()"])


class HStrPatternTests(unittest.TestCase):
    def test_ascii_wildcards(self):
        text, encoding = decode_hstr_pattern(b"ab\x90\x01\x02cd\x90\x00")
        self.assertEqual(text, "ab<skip 2>cd")
        self.assertEqual(encoding, "ascii")

    def test_extended_subrule_offsets(self):
        data = subrule(2, 0x81, b"abc", extra=0)
        rule = HStrExtSubRule(data, 0)
        self.assertEqual(rule.rule_weight, 2)
        self.assertEqual(rule.rule_size, 3)
        self.assertTrue(rule.case_sensitive)
        self.assertTrue(rule.extended)
        self.assertFalse(rule.variant)
        self.assertEqual(rule.rule_bytes, b"abc")
        self.assertEqual(rule.entry_size, 8)


class OtherHStrExtTests(unittest.TestCase):
    def test_pehstr_bytes_are_still_textual_for_other_types(self):
        payload = (
            struct.pack("<HHH", 1, 1, 1)
            + b"\x00"
            + subrule(1, 0x01, b"hello")
            + b"\x00\x00"
        )
        sig = HStrExtSig(tlv(0x8C, payload))
        self.assertEqual(sig.patterns, ["hello"])


if __name__ == "__main__":
    unittest.main()
