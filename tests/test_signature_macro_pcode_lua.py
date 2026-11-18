"""Vectors from the shipped database for MACRO_PCODE64/MACRO_PCODE and Lua chunks."""

import json
import struct
import unittest

from defender2yara.defender.signature import LuaSig, MacroPcodeSig
from defender2yara.defender.signature.lua import (
    LUA_HEADER, parse_lua_chunk, phase_name,
)
from defender2yara.defender.signature.lua_crypto import (
    INSTRUCTION_TABLE, decode_word, encode_word,
)
from defender2yara.defender.signature.macro_pcode import (
    defender_crc16, defender_crc32, routine_key,
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


# TrojanDownloader:O97M/Donoff - two 64-bit keys, third slot empty.
MACRO64 = bytes.fromhex("0b24d13459be0a04" "beb2259598086d02" "0000000000000000")
# !#ALF:Trojan:Win32/NeoHash.macropcode - keys 1 and 2 unset, named.
MACRO64_NAMED = bytes.fromhex(
    "2bceff145fdc5400" "ffffffff00000000" "ffffffff00000000"
    "2123414c463a54726f6a616e3a57696e33322f4e656f486173682e6d6163726f70636f646500"
)
# #Virus:X97M/Laroux.ER - legacy 32-bit keys plus name.
MACRO32_NAMED = bytes.fromhex("14a406eb37d33719067955672356697275733a5839374d2f4c61726f75782e455200")
# Virus:X97M/Dechanop.A - third key unset.
MACRO32 = bytes.fromhex("3fa9fd4127335e9fffffffff")

# !InfrastructureShared "Bedep": a headerless body whose code array is
# substituted.  It decodes to `function(...) Infrastructure_ScanBedep(true) end`.
BEDEP_HEADERLESS_BODY = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000020204000000"
    "63319ab1143d62996b7619bd66c30563010000000419000000496e6672617374"
    "727563747572655f5363616e4265646570000000000000000000000000000000"
    "0000"
)


class LuaInstructionCipherTests(unittest.TestCase):
    def test_table_is_the_engine_table(self):
        self.assertEqual(len(INSTRUCTION_TABLE), 256)
        self.assertEqual(sorted(INSTRUCTION_TABLE), list(range(256)))
        # Spot checks: RETURN 0 1 (0x0080001e) is stored as 0x6305c366.
        self.assertEqual(INSTRUCTION_TABLE[0x66], 0x1E)
        self.assertEqual(INSTRUCTION_TABLE[0xC3], 0x66)
        self.assertEqual(INSTRUCTION_TABLE[0x05], 0x43)
        self.assertEqual(INSTRUCTION_TABLE[0x63], 0x05)

    def test_word_round_trip(self):
        self.assertEqual(decode_word(0x6305C366), 0x0080001E)
        for word in (0, 1, 0x0080001E, 0xFFFFFFFF, 0x12345678):
            with self.subTest(word=hex(word)):
                self.assertEqual(decode_word(encode_word(word)), word)


class MacroPcode64Tests(SignatureSnapshotMixin, unittest.TestCase):
    def test_two_keys_and_empty_slot(self):
        sig = MacroPcodeSig(tlv(0xCF, MACRO64))
        self.assertEqual(sig.key_bits, 64)
        self.assertTrue(sig.is_64bit)
        self.assertEqual(sig.keys, [0x040ABE5934D1240B, 0x026D08989525B2BE, 0])
        self.assertEqual(sig.key_count, 2)
        self.assertEqual(sig.unset_keys, [2])
        self.assertEqual(sig.decoded_keys[0]["crc32"], "34d1240b")
        self.assertEqual(sig.decoded_keys[0]["crc16"], "be59")
        self.assertEqual(sig.decoded_keys[0]["length"], 1034)
        self.assertEqual(sig.decoded_keys[1]["length"], 621)
        self.assertTrue(sig.decoded_keys[2]["unset"])
        d = self.snapshot(sig)
        self.assertEqual(d["key_bits"], 64)
        self.assertEqual(d["keys"][0], "040abe5934d1240b")
        self.assertEqual(d["unset_slots"], [2])
        self.assertEqual(d["record_name"], "")
        self.assertFalse(d["has_name"])

    def test_named_record_with_unset_slots(self):
        sig = MacroPcodeSig(tlv(0xCF, MACRO64_NAMED))
        self.assertEqual(sig.name, "!#ALF:Trojan:Win32/NeoHash.macropcode")
        self.assertEqual(sig.unset_keys, [1, 2])
        self.assertEqual(sig.key_count, 1)
        self.assertEqual(sig.decoded_keys[0]["length"], 0x0054)
        d = self.snapshot(sig)
        self.assertEqual(d["record_name"], "!#ALF:Trojan:Win32/NeoHash.macropcode")

    def test_truncated_and_unterminated(self):
        with self.assertRaises(ValueError):
            MacroPcodeSig(tlv(0xCF, MACRO64[:23]))
        sig = MacroPcodeSig(tlv(0xCF, MACRO64 + b"no-nul"))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Unterminated", sig.decode_warnings[0])
        trailing = MacroPcodeSig(tlv(0xCF, MACRO64 + b"name\0junk"))
        self.assertEqual(trailing.decode_status, "partial")
        self.assertIn("trailing", trailing.decode_warnings[0])

    def test_router(self):
        self.assertIsInstance(Vdm.decode_record(tlv(0xCF, MACRO64), 0), MacroPcodeSig)


class MacroPcodeTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_legacy_32bit_keys(self):
        sig = MacroPcodeSig(tlv(0x42, MACRO32))
        self.assertEqual(sig.key_bits, 32)
        self.assertFalse(sig.is_64bit)
        self.assertEqual(sig.keys, [0x41FDA93F, 0x9F5E3327, 0xFFFFFFFF])
        self.assertEqual(sig.unset_keys, [2])
        self.assertEqual(sig.decoded_keys[0], {
            "hex": "41fda93f", "crc32": "41fda93f", "unset": False,
        })
        d = self.snapshot(sig)
        self.assertEqual(d["key_bits"], 32)
        self.assertNotIn("crc16", d["decoded_keys"][0])

    def test_named_record(self):
        sig = MacroPcodeSig(tlv(0x42, MACRO32_NAMED))
        self.assertEqual(sig.name, "#Virus:X97M/Laroux.ER")
        self.assertEqual(sig.keys, [0xEB06A414, 0x1937D337, 0x67557906])
        self.assertEqual(sig.key_count, 3)
        self.assertEqual(sig.unset_keys, [])

    def test_truncated(self):
        with self.assertRaises(ValueError):
            MacroPcodeSig(tlv(0x42, MACRO32[:11]))

    def test_router(self):
        self.assertIsInstance(Vdm.decode_record(tlv(0x42, MACRO32), 0), MacroPcodeSig)


class RoutineKeyTests(unittest.TestCase):
    def test_crc_helpers_match_engine_tables(self):
        # CRC-32 with init 0xffffffff and no final xor is "123456789" -> 340bc6d9.
        self.assertEqual(defender_crc32(b"123456789"), 0x340BC6D9)
        # Reflected CRC-16/ARC with init 0 is "123456789" -> bb3d.
        self.assertEqual(defender_crc16(b"123456789"), 0xBB3D)

    def test_routine_key_layout(self):
        key = routine_key(b"123456789")
        self.assertEqual(key, 0x0009BB3D340BC6D9)
        self.assertEqual((key >> 48) & 0xFFFF, 9)
        self.assertEqual((key >> 32) & 0xFFFF, 0xBB3D)
        self.assertEqual(key & 0xFFFFFFFF, 0x340BC6D9)


def lua_function(code=(1, 30 | (2 << 23)), constants=("BMLuaLib",)):
    body = struct.pack("<III", 0, 0, 0) + bytes([0, 0, 0, 2])
    body += struct.pack("<I", len(code))
    body += b"".join(struct.pack("<I", item) for item in code)
    body += struct.pack("<I", len(constants))
    for constant in constants:
        if isinstance(constant, str):
            body += b"\x04" + struct.pack("<I", len(constant) + 1) + constant.encode() + b"\0"
        else:
            body += b"\x03" + struct.pack("<q", constant)
    body += struct.pack("<IIII", 0, 0, 0, 0)
    return body


def lua_payload(name=b"", phase=0x15, attributes=b"", body=b""):
    return (bytes([len(name), phase]) + struct.pack("<HI", len(attributes), len(body))
            + name + attributes + body)


class LuaStandaloneTests(SignatureSnapshotMixin, unittest.TestCase):
    def test_phases(self):
        self.assertEqual(phase_name(0), "Unknown")
        self.assertEqual(phase_name(1), "Infrastructure")
        self.assertEqual(phase_name(8), "PEPREEMU")
        self.assertEqual(phase_name(21), "SignatureValidator")
        self.assertEqual(phase_name(35), "ELFGen")
        self.assertEqual(phase_name(0x30), "phase_0x30")

    def test_chunk_walk(self):
        body = LUA_HEADER + lua_function(code=(1, 2, 30), constants=("mp", "CLEAN", 7))
        chunk = parse_lua_chunk(body)
        self.assertEqual(len(chunk.functions), 1)
        self.assertEqual(chunk.instruction_count, 3)
        self.assertEqual(chunk.string_constants, ["mp", "CLEAN"])
        self.assertEqual(chunk.number_constants, [7])
        self.assertEqual(chunk.opcode_counts, {"LOADK": 1, "LOADBOOL": 1, "RETURN": 1})
        details = chunk.to_details()
        self.assertEqual(details["number_encoding"], "integer")

    def test_wrapper_with_attributes(self):
        attributes = b"Includes\0BMLuaLib\0" + b"ObMpAttributes\0\x01\x02\0"
        body = LUA_HEADER + lua_function()
        sig = LuaSig(tlv(0xBD, lua_payload(b"!#Lua:Test\0", 0x0C, attributes, body)))
        self.assertEqual(sig.phase_name, "GenFirst")
        self.assertEqual([item["name"] for item in sig.attributes],
                         ["Includes", "ObMpAttributes"])
        self.assertTrue(sig.attributes[1]["obfuscated"])
        d = self.snapshot(sig)
        self.assertEqual(d["attributes"][0], {
            "name": "Includes", "value": "BMLuaLib", "obfuscated": False,
        })
        self.assertEqual(d["chunk"]["functions"], 1)
        self.assertEqual(d["summary"], sig.describe())

    def test_headerless_variant(self):
        # A marker-only body with plain words must survive the decode attempt.
        body = b"\x01" + b"\0" * 11 + lua_function()
        sig = LuaSig(tlv(0xBD, lua_payload(body=body)))
        self.assertEqual(sig.body_format, "mplua_headerless")
        self.assertEqual(sig.lua_chunk_data, LUA_HEADER + lua_function())
        self.assertIsNotNone(sig.chunk)
        self.assertEqual(sig.code_encoding, "plain")
        self.assertEqual(sig.decode_status, "decoded")

    def test_headerless_encoded_bytecode_is_decoded(self):
        # Shipped headerless records keep the normal wrapper but substitute the
        # instruction words; this is the "Bedep" body from the shipped DB.
        sig = LuaSig(tlv(0xBD, lua_payload(body=BEDEP_HEADERLESS_BODY)))
        self.assertEqual(sig.body_format, "mplua_headerless")
        self.assertIsNotNone(sig.chunk)
        self.assertEqual(sig.code_encoding, "substituted")
        self.assertEqual(sig.decode_status, "decoded")
        self.assertEqual(sig.chunk.invalid_opcode_count, 0)
        self.assertEqual(sig.chunk.instruction_count, 4)
        self.assertEqual(sig.chunk.string_constants, ["Infrastructure_ScanBedep"])
        self.assertEqual(sig.chunk.root.code[-1], 0x0080001E)  # RETURN 0 1
        details = sig.to_details()
        self.assertEqual(details["code_encoding"], "substituted")
        self.assertEqual(details["chunk"]["invalid_opcodes"], 0)

    def test_headerless_undecodable_bytecode_is_flagged(self):
        body = b"\x01" + b"\0" * 11 + lua_function(code=(0x3F3F3F3F,))
        sig = LuaSig(tlv(0xBD, lua_payload(body=body)))
        self.assertEqual(sig.body_format, "mplua_headerless")
        self.assertIsNotNone(sig.chunk)
        self.assertEqual(sig.code_encoding, "encoded")
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Non-standard Lua bytecode", sig.decode_warnings[0])

    def test_invalid_chunk_is_partial(self):
        sig = LuaSig(tlv(0xBD, lua_payload(body=b"\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01" + b"\0" * 8)))
        self.assertEqual(sig.decode_status, "partial")
        self.assertIn("Invalid Lua chunk", sig.decode_warnings[0])
        self.assertEqual(sig.to_details()["chunk"], None)
        unknown = LuaSig(tlv(0xBD, lua_payload(body=b"not lua")))
        self.assertEqual(unknown.body_format, "unknown")
        self.assertEqual(unknown.decode_status, "partial")

    def test_length_mismatch_is_an_error(self):
        payload = lua_payload(body=LUA_HEADER + lua_function())
        with self.assertRaises(ValueError):
            LuaSig(tlv(0xBD, payload + b"\0"))

    def test_router(self):
        payload = lua_payload(body=LUA_HEADER + lua_function())
        self.assertIsInstance(Vdm.decode_record(tlv(0xBD, payload), 0), LuaSig)


if __name__ == "__main__":
    unittest.main()
