"""Vectors from the shipped database for NDAT (0xa9), BRUTE (0xd0), BOOT (0x44)."""

import json
import unittest

from defender2yara.defender.signature import BootSig, BruteSig, NdatSig
from defender2yara.defender.vdm import Vdm


def tlv(kind, payload):
    return bytes([kind]) + len(payload).to_bytes(3, "little") + payload


class SignatureSnapshotMixin:
    def snapshot(self, sig):
        details = sig.to_details()
        self.assertEqual(json.loads(json.dumps(details, allow_nan=False)), details)
        return details


class NdatTests(SignatureSnapshotMixin, unittest.TestCase):
    # Backdoor:Win32/VB.MW: VBA project path regex, anonymous.
    PROJECT_PATH = bytes.fromhex(
        "220000005c5c4578706c6f7261646f722d52656d6f746f"
        "5c5c5365727669646f722e7662700001"
    )
    # !InfrastructureShared: RtpSkipRule log-skip entry.
    LOG_SKIP = bytes.fromhex("170000002577696e646972255c4e746672735c2a2e6c6f677c2a0005")
    # Virus:Win32/Alureon.gen!C: raw code pattern (NDAT_RKPAT).
    RKPAT = bytes.fromhex(
        "2f00000001558bec8b450883782c07538b5d0c56578b7b600f8565010000"
        "8b77048b460ca8400f84e60000008a4e3533c0900008"
    )
    # !InfrastructureShared: binary regexp (NDAT_REGEXP_GENERIC) + label.
    REGEXP = bytes.fromhex(
        "24000000044a34c60a22316a53ab3054ea3e7f02d327515ac3d0c7335c7835"
        "62e4104e7ea112f8000d2123426f6f746c6f6164657200"
    )
    # !#NRI:DoplikInstallationServer: domain string.
    DOMAIN = bytes.fromhex("0c000000736c6f6f746e692e636f6d000f")
    # !#NRI:CERT_UNC1878: certificate subject regex.
    SUBJECT = bytes.fromhex(
        "190000005e5375626a6563743a20434e3d6161617475735c2e636f6d0012"
    )
    # !InfrastructureShared: LSASS audit rule + feed label.
    AUDIT = bytes.fromhex(
        "2e00000041554449545f4d313a39653663346531662d376436302d34373266"
        "2d626131612d613339656636363965346232001521234175746f4175646974"
        "556e697175654c7361737352756c65466f724d53465400"
    )

    def test_project_path(self):
        sig = NdatSig(tlv(0xA9, self.PROJECT_PATH))
        self.assertEqual(sig.type_id, 1)
        self.assertEqual(sig.type_name, "NDAT_PROJECTPATH_REGEX")
        self.assertEqual(sig.handler_name, None)
        self.assertEqual(sig.data_length, 0x22)
        self.assertTrue(sig.data_nul_terminated)
        self.assertTrue(sig.data_is_text)
        self.assertTrue(sig.data_text.endswith(".vbp"))
        self.assertFalse(sig.has_label)
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "ndat")
        self.assertEqual(d["type_id"], 1)
        self.assertFalse(d["has_name"])

    def test_log_skip_entry(self):
        sig = NdatSig(tlv(0xA9, self.LOG_SKIP))
        self.assertEqual(sig.type_id, 5)
        self.assertEqual(sig.type_name, "NDAT_LOGSKIP_ENTRY")
        self.assertEqual(sig.handler_name, "RtpSkipRule")
        self.assertEqual(sig.data_text, "%windir%\\Ntfrs\\*.log|*")
        self.assertEqual(sig.decode_warnings, [])

    def test_raw_code_pattern_is_binary(self):
        sig = NdatSig(tlv(0xA9, self.RKPAT))
        self.assertEqual(sig.type_id, 8)
        self.assertEqual(sig.type_name, "NDAT_RKPAT")
        self.assertFalse(sig.data_is_text)
        self.assertEqual(sig.data_text, "")
        self.assertEqual(sig.data_length, 0x2F)
        self.assertTrue(sig.data.startswith(b"\x01\x55\x8b\xec"))

    def test_binary_regexp_with_label(self):
        sig = NdatSig(tlv(0xA9, self.REGEXP))
        self.assertEqual(sig.type_id, 13)
        self.assertEqual(sig.type_name, "NDAT_REGEXP_GENERIC")
        self.assertEqual(sig.handler_name, "NdatRegExpMatch")
        self.assertTrue(sig.data_nul_terminated)
        self.assertEqual(sig.label, "!#Bootloader")
        self.assertEqual(sig.label_prefix, "!")
        self.assertTrue(sig.has_label)
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#Bootloader")

    def test_nri_domain_and_subject(self):
        domain = NdatSig(tlv(0xA9, self.DOMAIN))
        self.assertEqual(domain.type_id, 15)
        self.assertEqual(domain.type_name, "NRI_DOMAIN_REGEX")
        self.assertEqual(domain.data_text, "slootni.com")
        self.assertFalse(domain.has_label)

        subject = NdatSig(tlv(0xA9, self.SUBJECT))
        self.assertEqual(subject.type_id, 18)
        self.assertEqual(subject.type_name, "NRI_CERT_SUBJECT_REGEX")
        self.assertEqual(subject.data_text, "^Subject: CN=aaatus\\.com")

    def test_labelled_audit_rule(self):
        sig = NdatSig(tlv(0xA9, self.AUDIT))
        self.assertEqual(sig.type_id, 21)
        self.assertEqual(sig.type_name, "NRI_AUDIT_RULE")
        self.assertEqual(sig.label, "!#AutoAuditUniqueLsassRuleForMSFT")
        self.assertEqual(sig.data_text,
                         "AUDIT_M1:9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2")

    def test_router(self):
        sig = Vdm.decode_record(tlv(0xA9, self.LOG_SKIP), 0)
        self.assertIsInstance(sig, NdatSig)


class BruteTests(SignatureSnapshotMixin, unittest.TestCase):
    # !InfrastructureShared: script-type agnostic pattern with an inline label.
    NAMED = bytes.fromhex(
        "292123534350543a4149437573746f6d446973636f766572792e436c617564"
        "654167656e7453444b50790001ffffffff14000000436c617564654167656e"
        "744f7074696f6e739000"
    )
    # Backdoor:Win32/Plugx.I: anonymous binary pattern.
    ANONYMOUS = bytes.fromhex(
        "000001ffffffff22000000341d1c1c1cdf719738c0fd8c1c1c1c975c18975c"
        "289d381c1d1c1c6f728fe79d9000"
    )

    def test_named_text_pattern(self):
        sig = BruteSig(tlv(0xD0, self.NAMED))
        self.assertEqual(sig.name, "!#SCPT:AICustomDiscovery.ClaudeAgentSDKPy")
        self.assertEqual(sig.name_length, 0x29)
        self.assertEqual(sig.kind, 6)  # internal "any"
        self.assertEqual(sig.script_type, "any")
        self.assertEqual(sig.mode, 1)
        self.assertEqual(sig.any_length, 0xFFFFFFFF)
        self.assertEqual(sig.pattern_length, 0x14)
        self.assertEqual(sig.pattern_text, "ClaudeAgentOptions")
        self.assertEqual(sig.flags, 0x0B20)  # mode 1 + any(6) + contiguous
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "brute")
        self.assertEqual(d["parser"], "FUN_1801828c0")
        self.assertEqual(d["table_tag"], "brut")

    def test_anonymous_binary_pattern(self):
        sig = BruteSig(tlv(0xD0, self.ANONYMOUS))
        self.assertEqual(sig.name_length, 0)
        self.assertEqual(sig.pattern_length, 0x22)
        self.assertTrue(sig.pattern.endswith(b"\x90\x00"))
        self.assertFalse(sig.uses_wildcards)  # only the 90 00 terminator

    def test_router(self):
        sig = Vdm.decode_record(tlv(0xD0, self.ANONYMOUS), 0)
        self.assertIsInstance(sig, BruteSig)


class BootTests(SignatureSnapshotMixin, unittest.TestCase):
    # Virus:DOS/Half: 30-byte literal pattern, anonymous.
    HALF = bytes.fromhex(
        "001e802e130403b90600d3e02d00108ec033c0bb007c8a470103d88c473c33c000"
    )
    # Virus:DOS/MpTestBoot: 31-byte pattern with tail wildcards.
    TEST_BOOT = bytes.fromhex(
        "001fcd90cd33cd14cd13c7167a130540e8fe11bd94ec1e3a46c2cd90cd33cd14cd"
    )
    # Virus:DOS/3nop: CRC form (8-byte anchor + covered length + CRC-32).
    CRC = bytes.fromhex(
        "002000909090fa33c08ed82a00a844fd6300000000000000000000000000000000"
    )
    # !InfrastructureShared: labelled Petya boot pattern.
    PETYA = bytes.fromhex(
        "18212354454c3a52616e736f6d3a444f532f50657479612e411fe814006648"
        "6683f80075f566a10080ea00800000f4ebfd66506631c0525657"
    )

    def test_literal_pattern(self):
        sig = BootSig(tlv(0x44, self.HALF))
        self.assertFalse(sig.is_crc_form)
        self.assertEqual(sig.pattern_length, 0x1E)
        self.assertEqual(sig.pattern.hex(),
                         "802e130403b90600d3e02d00108ec033c0bb007c8a470103d88c473c33c0")
        self.assertEqual(sig.wildcard_count, 0)
        self.assertFalse(sig.uses_wildcards)
        self.assertFalse(sig.name_length)
        self.assertEqual(sig.decode_status, "decoded")
        d = self.snapshot(sig)
        self.assertEqual(d["layout"], "boot")
        self.assertFalse(d["is_crc_form"])

    def test_tail_wildcards(self):
        sig = BootSig(tlv(0x44, self.TEST_BOOT))
        self.assertEqual(sig.pattern_length, 31)
        # The first four bytes are a literal dword, even though byte 1 is 0x90.
        self.assertTrue(sig.pattern_hex.startswith("cd 90 cd 33"))
        self.assertGreaterEqual(sig.wildcard_count, 1)
        self.assertTrue(sig.uses_wildcards)
        self.assertEqual(sig.decode_warnings, [])

    def test_crc_form(self):
        sig = BootSig(tlv(0x44, self.CRC))
        self.assertTrue(sig.is_crc_form)
        self.assertEqual(sig.anchor.hex(), "909090fa33c08ed8")
        self.assertEqual(sig.covered_length, 42)
        self.assertEqual(sig.crc32, 0x63FD44A8)
        d = self.snapshot(sig)
        self.assertEqual(d["anchor_hex"], "909090fa33c08ed8")
        self.assertEqual(d["crc32_hex"], "63fd44a8")

    def test_labelled_pattern(self):
        sig = BootSig(tlv(0x44, self.PETYA))
        self.assertEqual(sig.name, "!#TEL:Ransom:DOS/Petya.A")
        self.assertEqual(sig.name_length, 24)
        self.assertEqual(sig.pattern_length, 31)
        self.assertEqual(sig.decode_warnings, [])

    def test_router(self):
        sig = Vdm.decode_record(tlv(0x44, self.HALF), 0)
        self.assertIsInstance(sig, BootSig)


if __name__ == "__main__":
    unittest.main()
