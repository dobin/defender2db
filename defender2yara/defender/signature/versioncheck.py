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

# Human-readable meanings for the engine environment-block feature flags used by
# VERSIONCHECK records.
#
# The environment block is ``DAT_18111e110``; the flags live at +0xbNN.  The
# assignments are in ``FUN_18058f8b4`` (engine environment initialisation).  A
# few of them are additionally confirmed by the counters written to the
# heartbeat in ``FUN_1804fe53c`` and by the policies they are read from, which
# is noted per entry.
#
# Only flags whose meaning is confirmed are listed.  Unknown flags fall back to
# a neutral "engine feature flag +0xNNN" description instead of guessing.
#
# offset: (short name, user-facing label, explanation)
ENGINE_FLAGS = {
    0xB42: (
        "msft_internal",
        "Microsoft-internal build",
        "Read from the SQMClient\\MSFTInternal policy. It is only set on "
        "Microsoft-managed machines.",
    ),
    0xB43: (
        "seville",
        "Defender for Endpoint (Seville)",
        "Controlled by the MpSevilleEnable policy. 'Seville' was the codename "
        "for Microsoft Defender ATP/Defender for Endpoint, so this flag gates "
        "EDR-oriented behaviour and hardening signatures.",
    ),
    0xB44: (
        "sense_installed",
        "Sense/EDR sensor installed",
        "True when the Sense service is installed (its ImagePath points at "
        "MsSense.exe).",
    ),
    0xB46: (
        "mba",
        "MBA policy",
        "Controlled by the MpEnableMBA policy.",
    ),
    0xB47: (
        "pua_mode",
        "PUA protection",
        "Defender's potentially unwanted application/software mode, controlled "
        "by the MpEnablePUS policy. The engine sets this flag when its PUA mode "
        "is 1 or 2. Detections whose name starts with 'PUA:' are suppressed "
        "when it is off.",
    ),
    0xB49: (
        "auto_submit",
        "Automatic sample submission",
        "Derived from the engine's auto-sample opt-in value. It controls "
        "whether suspicious files may be submitted to Microsoft.",
    ),
    0xB4A: (
        "pua_removal",
        "PUA removal",
        "Controlled by the MpEnablePUSRemoval policy. It allows the engine to "
        "remediate unwanted applications, not just detect them.",
    ),
    0xB50: (
        "test_signing",
        "Test signing",
        "The code-integrity test-signing option reported by the kernel.",
    ),
    0xB51: (
        "lockdown_mode",
        "Windows Lockdown Mode",
        "Queried through WldpQueryWindowsLockdownMode in wldp.dll.",
    ),
    0xB52: (
        "developer_mode",
        "Developer Mode",
        "Read from AppModelUnlock\\AllowDevelopmentWithoutDevLicense.",
    ),
    0xB54: (
        "inside_container",
        "Inside a container",
        "Reported as 'isincontaineros' in the engine heartbeat.",
    ),
}

# Windows build numbers that appear in VERSIONCHECK records.  These are the
# builds used by the OS-build checks (ids 0x26-0x28 and 0xa3).
WINDOWS_BUILD_NAMES = {
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    14393: "Windows 10 1607 / Server 2016",
    15063: "Windows 10 1703",
    16299: "Windows 10 1709",
    17134: "Windows 10 1803",
    17763: "Windows 10 1809 / Server 2019",
    18362: "Windows 10 1903",
    18363: "Windows 10 1909",
    19041: "Windows 10 2004",
    19042: "Windows 10 20H2",
    19043: "Windows 10 21H1",
    19044: "Windows 10 21H2",
    19045: "Windows 10 22H2",
    22000: "Windows 11 21H2",
    22621: "Windows 11 22H2",
    22631: "Windows 11 23H2",
    26100: "Windows 11 24H2",
}

# target -> (label, kind, optional note)
_TARGET_INFO = {
    "engine_build": (
        "Engine build",
        "engine_version",
        "The build number of mpengine itself.",
    ),
    "os_build": (
        "Windows build",
        "os",
        "The build number reported by the running Windows installation.",
    ),
    "engine_field_0xb8c": (
        "Windows build",
        "os",
        "The build number reported by the running Windows installation.",
    ),
    "engine_field_0xb60": (
        "Windows version",
        "os",
        "The major/minor version reported by Windows.",
    ),
    "engine_field_0xb84": (
        "Windows version",
        "os",
        "The major/minor version reported by Windows.",
    ),
    "engine_field_0xb88": (
        "Windows service-pack level",
        "os",
        "The service-pack/suite value reported by Windows.",
    ),
    "engine_field_0xb90": (
        "Windows revision (UBR)",
        "os",
        "The update build revision (UBR) of the running Windows build.",
    ),
    "engine_field_0xb94": (
        "Windows product type",
        "os",
        "The product/edition id returned by GetProductInfo.",
    ),
    "engine_field_0xb5c": (
        "System locale (LCID)",
        "os",
        "The system default locale id.",
    ),
    "engine_field_0xb64": (
        "Processor architecture",
        "os",
        "The processor architecture reported by GetSystemInfo.",
    ),
    "engine_field_0xb98": (
        "Cloud block level",
        "engine",
        "The engine's cloud-delivered protection block level.",
    ),
    "engine_field_0x1588c": (
        "Engine version id",
        "engine_version",
        "A numeric id for the engine version.",
    ),
    "engine_field_0xbe8": (
        "Days since engine data install",
        "engine",
        "How long ago the engine's platform data was installed.",
    ),
    "engine_field_0xbf0": (
        "Engine data install timestamp",
        "engine",
        "A timestamp derived from the engine data install time.",
    ),
    "global_engine_version": (
        "Global engine version",
        "engine_version",
        "The engine's global version identifier.",
    ),
    "engine_kind_default5": (
        "Engine product kind",
        "engine_kind",
        "The engine product kind, defaulting to 5 when unset.",
    ),
    "engine_version_string_id": (
        "Engine version string id",
        "engine_version",
        "An id for the engine version string.",
    ),
    "product_version_string_id": (
        "Product version string id",
        "engine_version",
        "An id for the product version string.",
    ),
    "product_version": (
        "Defender product version",
        "engine_version",
        "The Defender product version (as opposed to the engine build).",
    ),
    "platform_version": (
        "Platform version",
        "engine_version",
        "The engine's platform version.",
    ),
    "engine_kind": (
        "Engine product kind",
        "engine_kind",
        "Which engine flavour is running. Current definitions use the "
        "unconditional value 1 for ids 0x75-0x77.",
    ),
    "value": (
        "Engine configuration value",
        "engine",
        "An engine configuration threshold. Value 4 is the modern default "
        "used by the \"at most/at least/exactly 4\" checks.",
    ),
    "definition_version_time": (
        "Definition-update timestamp",
        "definition_version",
        "A reference into the definition-version table, used to require a "
        "minimum (or maximum) signature vintage.",
    ),
    "timestamp_0x158e0": (
        "Engine timestamp",
        "timestamp",
        "A FILETIME-style value kept by the engine.",
    ),
    "engine_dword_high_0x15970": (
        "Engine counter (high dword)",
        "engine",
        "The high 32 bits of the engine's 64-bit counter at +0x15970.",
    ),
    "engine_dword_low_0x15970": (
        "Engine counter (low dword)",
        "engine",
        "The low 32 bits of the engine's 64-bit counter at +0x15970.",
    ),
    "engine_field_0x15970": (
        "Engine counter",
        "engine",
        "The engine's 64-bit counter at +0x15970.",
    ),
    "engine_field_0x15b80": (
        "Engine environment value",
        "engine",
        "An internal engine environment value.",
    ),
    "engine_field_0xb70": (
        "Engine mode",
        "engine",
        "An internal engine mode/configuration value.",
    ),
    "engine_field_0xb74": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb78": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb7c": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xbb4": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xbc8": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xbd0": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb20": (
        "Engine product id",
        "engine_kind",
        "The engine product id (7, 10, 18, 21, 23, ...).",
    ),
    "engine_field_0xb24": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb28": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb2c": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb34": (
        "Engine configuration value",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_field_0xb3f": (
        "Engine feature flag +0xb3f",
        "engine_flag",
        "An internal engine feature flag. Its exact meaning is not decoded.",
    ),
    "engine_field_0x15890": (
        "Engine version field",
        "engine_version",
        "Part of the engine version digest/version block.",
    ),
    "engine_field_0x15894": (
        "Engine version field",
        "engine_version",
        "Part of the engine version digest/version block.",
    ),
    "engine_field_0x15898": (
        "Engine version field",
        "engine_version",
        "Part of the engine version digest/version block.",
    ),
    "engine_field_0x1589c": (
        "Engine version field",
        "engine_version",
        "Part of the engine version digest/version block.",
    ),
    "engine_field_0x1596c": (
        "Engine configuration flag",
        "engine",
        "An internal engine configuration value.",
    ),
    "engine_feature_0x758134": (
        "Engine feature flag",
        "engine_flag",
        "An internal engine feature bit.",
    ),
}

_RELATION_TEXT = {
    "<": "must be less than",
    ">": "must be greater than",
    "==": "must equal",
    "!=": "must not equal",
    "<=": "must be at most",
    ">=": "must be at least",
}


def _flag_target(target: str):
    """Return (offset, label, explanation) for a ``flag_0xNNN`` target."""
    if not target.startswith("flag_"):
        return None
    spelling = target[5:]
    try:
        offset = int(spelling, 16)
    except ValueError:
        return None
    entry = ENGINE_FLAGS.get(offset)
    if entry is not None:
        _, label, explanation = entry
        return offset, label, explanation
    return offset, f"engine feature flag +0x{offset:03x}", (
        "An internal engine feature flag. Its exact meaning has not been "
        "decoded, so this gate can only be interpreted as a capability check."
    )


def _format_value(target: str, relation: str, value: int) -> str:
    if relation in ("bool", "bit0"):
        return "enabled" if value else "disabled"
    if relation in ("date", "date_inv"):
        return f"table entry {value >> 24}, {value & 0xFFFFFF} ms (raw 0x{value:08x})"
    if target in ("engine_field_0xb60", "engine_field_0xb84"):
        # The engine packs the OS major/minor version into one dword.
        return f"{value >> 16}.{value & 0xFFFF} (raw 0x{value:06x})"
    if target in ("os_build", "engine_field_0xb8c") or target in (
            "engine_field_0xb88", "engine_field_0xb90", "engine_field_0xb94"):
        name = WINDOWS_BUILD_NAMES.get(value)
        return f"{value} ({name})" if name else str(value)
    if target == "engine_build":
        return str(value)
    if "digest" in target or value > 0xFFFF:
        return f"0x{value:08x} ({value})"
    return str(value)


def _windows_build(value: int) -> str:
    name = WINDOWS_BUILD_NAMES.get(value)
    return f"{value} ({name})" if name else str(value)


def describe_version_check(check_id: int, value: int) -> dict:
    """Turn a raw VERSIONCHECK pair into user-facing interpretation.

    Returns a dictionary that is safe to merge into the stored signature
    details.  ``description`` is deliberately not part of it: the technical
    predicate remains available under that key for API compatibility.
    """
    check_id = int(check_id) & 0xFFFFFFFF
    value = int(value) & 0xFFFFFFFF
    result = {
        "summary": "",
        "explanation": "",
        "target_label": None,
        "target_kind": None,
        "value_text": _format_value("value", "generic", value),
        "always_true": False,
        "always_false": False,
    }

    # check id 0: the loader's "records enabled" switch is turned back on.
    if check_id == ALWAYS_TRUE:
        result.update({
            "summary": "No condition - always loads the records that follow",
            "explanation": (
                "Check ID 0 makes the engine return true immediately, so this "
                "record tests nothing about the machine. Its only effect is to "
                "switch loading back on for the records below it, normally as "
                "a reset point after a conditional gate. It does not mean that "
                "the threat always detects a file."
            ),
            "target_label": "None (check ID 0)",
            "target_kind": "unconditional",
            "value_text": "not used",
            "always_true": True,
        })
        return result

    if check_id == ALWAYS_FALSE:
        result.update({
            "summary": "Never loads the records that follow",
            "explanation": (
                "Check ID 0x4b is a kill switch: it always evaluates false, so "
                "the records below it are skipped on every machine."
            ),
            "target_label": "None (check ID 0x4b)",
            "target_kind": "unconditional",
            "value_text": "not used",
            "always_false": True,
        })
        return result

    entry = VERSION_CHECK_IDS.get(check_id)
    if entry is None:
        result.update({
            "summary": f"Undecoded engine check {check_id:#04x}",
            "explanation": (
                "This check id is not in the decoded table yet. The engine "
                "still evaluates it, but its target field has no public "
                "meaning in this tool."
            ),
            "target_label": f"check {check_id:#04x}",
            "target_kind": "unknown",
        })
        return result

    target, relation = entry

    # The "always pass" short forms used by current definitions.
    if (check_id == 0x77 and value == 1) or (check_id == 0x75 and value > 1) \
            or (check_id == 0x76 and value == 0):
        result.update({
            "summary": "No effective condition - unconditional engine-kind gate",
            "explanation": (
                f"Check {check_id:#04x} is the modern unconditional form of the "
                "engine product/kind gate. With this value it always passes, so "
                "it does not filter anything; it is emitted for compatibility."
            ),
            "target_label": "Engine product kind",
            "target_kind": "engine_kind",
            "value_text": _format_value(target, relation, value),
            "always_true": True,
        })
        return result

    # Engine feature flags (including a couple of OR-ed combinations).
    if "|" in target:
        parts = []
        for part in target.split("|"):
            info = _flag_target(part)
            parts.append(info[1] if info else part)
        wanted = "enabled" if value else "disabled"
        result.update({
            "summary": f"{' or '.join(parts)} must be {wanted}",
            "explanation": (
                "The gate passes when any of these engine feature flags has "
                "the requested boolean value."
            ),
            "target_label": " or ".join(parts),
            "target_kind": "engine_flag",
            "value_text": _format_value(target, relation, value),
        })
        return result

    flag = _flag_target(target)
    if flag is not None:
        offset, label, explanation = flag
        wanted = "enabled" if value else "disabled"
        result.update({
            "summary": f"{label} must be {wanted}",
            "explanation": explanation,
            "target_label": f"{label} (engine flag +0x{offset:03x})",
            "target_kind": "engine_flag",
            "value_text": _format_value(target, relation, value),
        })
        return result

    # Definition-version timestamps.
    if relation in ("date", "date_inv"):
        direction = "older than" if relation == "date" else "at least as new as"
        result.update({
            "summary": f"Definition version must be {direction} the signature's reference",
            "explanation": (
                "This compares the definition-version table entry encoded in "
                "the value with the definition vintage the signature was built "
                "against. It is a signature-release compatibility gate, not a "
                "detection."
            ),
            "target_label": "Definition-version timestamp",
            "target_kind": "definition_version",
            "value_text": _format_value(target, relation, value),
        })
        return result

    # Definition / engine version digests.
    if target.startswith("definition_set_digest"):
        word = target[target.find("[") + 1:target.find("]")] if "[" in target else "?"
        result.update({
            "summary": "Definition-set fingerprint must match",
            "explanation": (
                f"This compares word {word} of the 16-byte definition-set "
                "digest. It pins this block of signatures to one exact "
                "definition release; the number is a fingerprint, not a "
                "readable version."
            ),
            "target_label": f"Definition-set digest word {word}",
            "target_kind": "definition_digest",
            "value_text": _format_value(target, relation, value),
        })
        return result
    if target.startswith("engine_version_digest"):
        word = target[target.find("[") + 1:target.find("]")] if "[" in target else "?"
        result.update({
            "summary": "Engine-version fingerprint must match",
            "explanation": (
                f"This compares word {word} of the 16-byte engine-version "
                "digest. It pins the signature to a specific engine build; the "
                "number is a fingerprint, not a readable version."
            ),
            "target_label": f"Engine-version digest word {word}",
            "target_kind": "engine_digest",
            "value_text": _format_value(target, relation, value),
        })
        return result

    # Engine product/kind ids.
    if relation == "kind":
        result.update({
            "summary": f"Engine product kind must match value {value}",
            "explanation": (
                "The engine reports an internal product/kind id (7, 18, 21, 23 "
                "and similar values). This gate selects which engine flavours "
                "load the following records."
            ),
            "target_label": "Engine product kind",
            "target_kind": "engine_kind",
            "value_text": _format_value(target, relation, value),
        })
        return result

    if relation == "bit0":
        wanted = "set" if value else "clear"
        label = _TARGET_INFO.get(target, (target,))[0]
        result.update({
            "summary": f"Bit 0 of {label} must be {wanted}",
            "explanation": "Checks one bit of an engine environment value.",
            "target_label": label,
            "target_kind": "engine_field",
            "value_text": _format_value(target, relation, value),
        })
        return result

    if relation == "zero":
        label = _TARGET_INFO.get(target, (target,))[0]
        result.update({
            "summary": f"{label} must be zero",
            "explanation": (
                "This check passes only when the stored engine value is zero."
            ),
            "target_label": label,
            "target_kind": "engine_field",
            "value_text": _format_value(target, relation, value),
        })
        return result

    if relation == "gt100":
        wanted = "greater than 100" if value else "not greater than 100"
        result.update({
            "summary": f"Engine value must be {wanted}",
            "explanation": "Checks the low 16 bits of an engine counter.",
            "target_label": "Engine counter",
            "target_kind": "engine",
            "value_text": _format_value(target, relation, value),
        })
        return result

    # Generic comparison against a named engine/OS field.
    info = _TARGET_INFO.get(target)
    if info is None and target.startswith("engine_field_"):
        info = (
            f"Engine field {target.removeprefix('engine_field_')}",
            "engine_field",
            "An internal engine environment field.",
        )
    label, kind, note = info if info else (target, "engine_field", "")
    relation_text = _RELATION_TEXT.get(relation, relation)

    result.update({
        "summary": f"{label} {relation_text} {_windows_build(value)}"
                   if target in ("os_build", "engine_field_0xb8c")
                   else f"{label} {relation_text} {_format_value(target, relation, value)}",
        "explanation": note or (
            "Compares a value from the engine's environment block."
        ),
        "target_label": label,
        "target_kind": kind,
        "value_text": _format_value(target, relation, value),
    })
    return result


def enrich_versioncheck_details(details: dict) -> dict:
    """Merge the human interpretation into stored VERSIONCHECK details.

    Used at read time so databases created before the interpretation was added
    still get the improved text without a rebuild.
    """
    if not isinstance(details, dict) or "check_id" not in details:
        return details
    try:
        check_id = int(details["check_id"])
        value = int(details.get("value", 0))
    except (TypeError, ValueError):
        return details
    enriched = dict(details)
    for key, value_ in describe_version_check(check_id, value).items():
        enriched.setdefault(key, value_)
    return enriched


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

    def to_details(self) -> dict:
        check = self.check
        details = {
            "check_id": self.check_id,
            "value": self.value,
            "check": list(check) if check is not None else None,
            "is_unconditional": self.is_unconditional,
            "description": self.describe(),
        }
        details.update(self.interpretation)
        return details

    @property
    def interpretation(self) -> dict:
        """User-facing summary/explanation of this gate (see module docs)."""
        return describe_version_check(self.check_id, self.value)

    @property
    def summary(self) -> str:
        return self.interpretation["summary"]

    @property
    def explanation(self) -> str:
        return self.interpretation["explanation"]

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
