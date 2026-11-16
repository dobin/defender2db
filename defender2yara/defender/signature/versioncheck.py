import struct
from typing import Optional, Tuple

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# Version constant used by check ids 0x01-0x03: it is the engine build of the
# mpengine build that was analysed (1.1.26100.4 -> 0x65f4 == 26100).
ENGINE_BUILD_CONSTANT = 0x65F4

ALWAYS_TRUE = 0x00
ALWAYS_FALSE = 0x4B

# check id -> (target, relation)
#
# The predicate is ``target RELATION value`` and the record passes when it is
# true.  ``target`` is either a literal (see IMMEDIATE_TARGETS), a field of the
# engine's environment block (DAT_18111e110 + 0xbNN), a boolean engine feature
# flag, a definition/engine version digest dword, or a timestamp.
#
# Derived from the big switch in FUN_1804f9434 (mpengine 1.1.26100.4).  Ids not
# listed here exist as well but were not decoded (they return the generic
# "check" description).
VERSION_CHECK_IDS = {
    # engine build constant
    0x01: ("engine_build", "<"),
    0x02: ("engine_build", ">"),
    0x03: ("engine_build", "=="),

    # engine environment dwords (feature/version bitfields, see notes)
    0x04: ("flag_0xb38", "bool"),
    0x05: ("definition_version_time", "date"),
    0x06: ("engine_field_0xb20", "<"),
    0x07: ("engine_field_0xb20", ">"),
    0x08: ("engine_field_0xb20", "=="),
    0x09: ("engine_field_0xb24", "<"),
    0x0A: ("engine_field_0xb24", ">"),
    0x0B: ("engine_field_0xb24", "=="),
    0x0C: ("engine_field_0xb28", "<"),
    0x0D: ("engine_field_0xb28", ">"),
    0x0E: ("engine_field_0xb28", "=="),
    0x0F: ("engine_field_0xb2c", "<"),
    0x10: ("engine_field_0xb2c", ">"),
    0x11: ("engine_field_0xb2c", "=="),
    0x12: ("engine_field_0xb60", "<"),
    0x13: ("engine_field_0xb60", ">"),
    0x14: ("engine_field_0xb60", "=="),
    0x15: ("engine_field_0xb64", "<"),
    0x16: ("engine_field_0xb64", ">"),
    0x17: ("engine_field_0xb64", "=="),
    0x18: ("engine_field_0xb5c", "<"),
    0x19: ("engine_field_0xb5c", ">"),
    0x1A: ("engine_field_0xb5c", "=="),
    0x1B: ("flag_0xb39", "bool"),
    0x1C: ("flag_0xb3a", "bool"),
    0x1D: ("flag_0xb3b", "bool"),
    0x1E: ("engine_field_0xb84", "<"),
    0x1F: ("engine_field_0xb84", ">"),
    0x20: ("engine_field_0xb84", "=="),
    0x21: ("flag_0xb3d", "bool"),
    0x22: ("definition_version_time", "date_inv"),
    0x23: ("engine_field_0xb88", "<"),
    0x24: ("engine_field_0xb88", ">"),
    0x25: ("engine_field_0xb88", "=="),
    0x26: ("os_build", "<"),
    0x27: ("os_build", ">"),
    0x28: ("os_build", "=="),
    0x29: ("global_engine_version", "=="),
    0x2A: ("global_engine_version", "!="),
    0x2B: ("flag_0xb3c", "bool"),
    0x2C: ("definition_version_time", "date"),
    0x2D: ("definition_version_time", "date_inv"),
    0x2E: ("flag_0xb3e", "bool"),
    0x2F: ("flag_0xb41", "bool"),
    0x30: ("flag_0xb42", "bool"),
    0x31: ("flag_0xb43", "bool"),
    0x32: ("flag_0xb46", "bool"),
    0x33: ("engine_field_0xb74", "=="),
    0x34: ("flag_0xb47", "bool"),
    0x35: ("flag_0xb49", "bool"),
    0x36: ("definition_version_time", "date"),
    0x37: ("definition_version_time", "date_inv"),
    0x38: ("definition_version_time", "date"),
    0x39: ("definition_version_time", "date_inv"),
    0x3A: ("flag_0xb4a", "bool"),
    0x3B: ("engine_field_0xb70", "=="),
    0x3C: ("definition_set_digest[0]", "=="),
    0x3D: ("definition_set_digest[1]", "=="),
    0x3E: ("definition_set_digest[2]", "=="),
    0x3F: ("definition_set_digest[3]", "=="),
    0x40: ("flag_0xb4e", "bool"),
    0x41: ("engine_field_0xb78", "=="),
    0x42: ("flag_0x18111e119", "bool"),
    0x43: ("flag_0xb4f", "bool"),
    0x44: ("flag_0xb52", "bool"),
    0x45: ("timestamp_0x158e0", "<"),
    0x46: ("timestamp_0x158e0", ">"),
    0x47: ("flag_0xb50", "bool"),
    0x48: ("engine_field_0xb7c", "<"),
    0x49: ("engine_field_0xb7c", ">"),
    0x4A: ("engine_field_0xb7c", "=="),
    0x4C: ("engine_field_0xb98", "=="),
    0x4D: ("flag_0xb40|flag_0xb51", "bool"),
    0x4E: ("engine_field_0xb94", "<"),
    0x4F: ("engine_field_0xb94", ">"),
    0x50: ("engine_field_0xb94", "=="),
    0x51: ("engine_field_0xb90", "<"),
    0x52: ("engine_field_0xb90", ">"),
    0x53: ("engine_field_0xb90", "=="),
    0x54: ("engine_field_0xb9c", "<"),
    0x55: ("engine_field_0xb9c", ">"),
    0x56: ("engine_field_0xb9c", "=="),
    0x57: ("engine_field_0xb98", "<"),
    0x58: ("engine_field_0xb98", ">"),
    0x59: ("flag_0xb3f", "bool"),
    0x5A: ("engine_field_0xb34", "<"),
    0x5B: ("engine_field_0xb34", ">"),
    0x60: ("flag_0xb48", "bool"),
    0x61: ("engine_field_0xbe8", "<"),
    0x62: ("engine_field_0xbe8", ">"),
    0x63: ("engine_version_digest[0]", "=="),
    0x64: ("engine_version_digest[1]", "=="),
    0x65: ("engine_version_digest[2]", "=="),
    0x66: ("engine_field_0x1588c", "=="),
    0x67: ("engine_field_0xbb4", "=="),
    0x68: ("engine_field_0xbb4", "<"),
    0x69: ("engine_field_0xbb4", ">"),
    0x6A: ("engine_dword_high_0x15970", "=="),
    0x6B: ("engine_dword_high_0x15970", "<"),
    0x6C: ("engine_dword_high_0x15970", ">"),
    0x6D: ("engine_dword_low_0x15970", "=="),
    0x6E: ("engine_dword_low_0x15970", "<"),
    0x6F: ("engine_dword_low_0x15970", ">"),
    0x70: ("engine_field_0xbf0", "<"),
    0x71: ("engine_field_0xbf0", ">"),
    0x72: ("engine_field_0xb70", "!="),
    0x73: ("flag_0xb53", "bool"),
    0x74: ("flag_0xb54", "bool"),
    0x75: ("engine_kind", "kind"),
    0x76: ("engine_kind", "kind"),
    0x77: ("engine_kind", "kind"),
    0x78: ("flag_0xb55", "bool"),
    0x79: ("engine_field_0x1596c", "bit0"),
    0x7A: ("value", "<="),
    0x7B: ("value", ">="),
    0x7C: ("value", "=="),
    0x7D: ("engine_field_0x15b80", "<"),
    0x7E: ("engine_field_0x15b80", ">"),
    0x7F: ("engine_field_0x15b80", "=="),
    0x80: ("platform_version", "=="),
    0x81: ("platform_version", "<"),
    0x82: ("platform_version", ">"),
    0x83: ("product_version", "=="),
    0x84: ("product_version", "<"),
    0x85: ("product_version", ">"),
    0x86: ("engine_kind_default5", "=="),
    0x87: ("engine_kind_default5", ">"),
    0x88: ("engine_kind_default5", "<"),
    0x89: ("flag_0xb56", "bool"),
    0x8A: ("flag_0xb44", "bool"),
    0x8C: ("value", "zero"),
    0x8D: ("engine_field_0x15970", "gt100"),
    0x8E: ("engine_field_0xbc8", "=="),
    0x8F: ("engine_field_0xbc8", "<"),
    0x90: ("engine_field_0xbc8", ">"),
    0x9A: ("engine_field_0xb20", "!="),
    0x9B: ("engine_field_0xb24", "!="),
    0x9C: ("engine_field_0xb28", "!="),
    0x9E: ("engine_field_0xb60", "!="),
    0x9F: ("engine_field_0xb64", "!="),
    0xA0: ("engine_field_0xb5c", "!="),
    0xA1: ("engine_field_0xb84", "!="),
    0xA2: ("engine_field_0xb88", "!="),
    0xA3: ("engine_field_0xb8c", "!="),
    0xA4: ("engine_field_0xb7c", "!="),
    0xA5: ("engine_field_0xb94", "!="),
    0xA6: ("engine_field_0xb90", "!="),
    0xA7: ("engine_field_0xb9c", "!="),
    0xA8: ("engine_field_0xb34", "!="),
    0xAF: ("engine_version_string_id", "=="),
    0xB0: ("product_version_string_id", "=="),
    0xB1: ("engine_kind_default5", "=="),
    0xB2: ("engine_field_0xbc8", "=="),
    0xB3: ("engine_field_0x15890", "=="),
    0xB4: ("engine_field_0x15894", "=="),
    0xB5: ("engine_field_0x15898", "=="),
    0xB6: ("engine_field_0x1589c", "=="),
    0xBB: ("flag_0x15c28", "bool"),
    0xBC: ("flag_0xb45", "bool"),
    0xBD: ("flag_0x15c29", "bool"),
    0xBE: ("engine_field_0xbd0", "=="),
    0xBF: ("engine_feature_0x758134", "bool"),
}

IMMEDIATE_TARGETS = {"engine_build": ENGINE_BUILD_CONSTANT}

_BOOL_IDS = {cid for cid, (_, rel) in VERSION_CHECK_IDS.items() if rel in ("bool", "bit0")}


class VersionCheckSig(BaseSig):
    """
    SIGNATURE_TYPE_VERSIONCHECK (0x7a), an environment gate.

    Payload (8 bytes, little endian)::

        u32 check_id
        u32 value

    mpengine does *not* register this record as a signature.  In the database
    loader (FUN_180183894) a 0x7a record is evaluated immediately with
    FUN_1804f9434; the boolean result is kept in a global "records enabled"
    flag, and while that flag is false every following record is skipped.

    So a VERSIONCHECK gates the signatures that follow it in the same threat:
    if the local engine/OS/definition environment does not satisfy the check,
    the rest of the threat's records are ignored.  ``check_id = 0`` is an
    "always pass" record and is used to re-enable record loading; the very
    common ``check_id = 0x77, value = 1`` pair is the modern unconditional form.

    Check ids cover engine build numbers, OS build numbers, product/engine
    kind, definition-version digests and timestamps, e.g.::

        0x00 / 0x4b   always true / always false
        0x01-0x03     engine build vs 26100 (the analysed engine's build)
        0x26-0x28     OS build number
        0x3c-0x3f     definition-set 16-byte digest dword
        0x63-0x65     engine-version 16-byte digest dword
        0x75-0x77     engine product/kind check
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x7A]

        if len(self.sig_data) < 8:
            raise ValueError(
                f"VERSIONCHECK payload too short: {len(self.sig_data)} < 8"
            )

        self.check_id, self.value = struct.unpack_from("<II", self.sig_data, 0)
        self.extra = bytes(self.sig_data[8:])

    @property
    def check(self) -> Optional[Tuple[str, str]]:
        """(target, relation) for this check id, if it was decoded."""
        return VERSION_CHECK_IDS.get(self.check_id)

    @property
    def is_unconditional(self) -> bool:
        """True when the record always passes, so the gate never blocks."""
        if self.check_id == ALWAYS_TRUE:
            return True
        # 0x77 with value 1 is the "always pass" form used by new definitions.
        if self.check_id == 0x77 and self.value == 1:
            return True
        if self.check_id == 0x75 and self.value > 1:
            return True
        if self.check_id == 0x76 and self.value == 0:
            return True
        return False

    def describe(self) -> str:
        """Human readable form of the predicate, e.g. ``os_build < 17763``."""
        if self.check_id == ALWAYS_TRUE:
            return "always true"
        if self.check_id == ALWAYS_FALSE:
            return "always false"

        entry = VERSION_CHECK_IDS.get(self.check_id)
        if entry is None:
            return f"engine check {self.check_id:#04x} value={self.value:#x}"

        target, rel = entry
        if rel == "bool":
            return f"bool({target}) == {bool(self.value)}"
        if rel == "bit0":
            return f"({target} & 1) == {bool(self.value)}"
        if rel == "date":
            return (
                "definition_version_date[value >> 24] < (value & 0xffffff)"
            )
        if rel == "date_inv":
            return (
                "definition_version_date[value >> 24] >= (value & 0xffffff)"
            )
        if rel == "zero":
            return f"value == 0 (check {target})"
        if rel == "gt100":
            return f"(u16({target}) > 100) == {bool(self.value)}"
        if rel == "kind":
            return f"engine_kind({target}) matches value {self.value}"
        if target in IMMEDIATE_TARGETS:
            current = IMMEDIATE_TARGETS[target]
            return f"{current:#x} {rel} value"
        return f"{target} {rel} {self.value:#x}"

    def __repr__(self) -> str:
        return (
            f"VersionCheckSig(check_id={self.check_id:#04x}, "
            f"value={self.value:#x}, {self.describe()})"
        )
