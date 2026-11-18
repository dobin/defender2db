import struct
import zlib

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


SIGTREE_SIGS = [
    "SIGNATURE_TYPE_SIGTREE",
    "SIGNATURE_TYPE_SIGTREE_EXT",
    "SIGNATURE_TYPE_SIGTREE_BM",
]

# Numeric ids of the three sig-tree record types (0x40 / 0x41 / 0xb3).
SIGTREE_TYPE_IDS = frozenset((0x40, 0x41, 0xB3))

# Maximum length of the optional name at the start of the payload.
MAX_NAME_LEN = 0x40

# Condition opcodes.  The opcode is a single byte followed by a fixed-size
# blob (or, for opcode 1, a variable-size blob whose length comes from the
# edge record).
OPCODE_PATTERN = 1
OPCODE_HASHES = {
    2: ("md5", 0x10),
    3: ("sha1", 0x14),
    4: ("sha256", 0x20),
}

# The per-side flag that says "an inline pattern follows".
FLAG_INLINE = 0x10

# The per-side flag that says the pattern/hash is UTF-16LE text (inline
# patterns with flag 0x40) or that the condition is a hash compare.
FLAG_WIDE = 0x40

# Documented bits of the per-side flag byte.
#
# ``FUN_1800d5880`` is the matcher that consumes the per-side flag byte.  It
# treats the bits as follows (for a value-only condition):
#
#   0x01  suffix match   -- hash the last N characters (length - N offset)
#   0x02  "any"          -- the matcher returns true before looking at the value
#   0x04  exact          -- require live length == N, then hash the prefix
#   0x08  case-sensitive -- use the non-folding hash / memcmp variant
#   0x10  inline blob    -- a pattern follows in the record
#   0x20  list / any-of  -- resolve an attribute record and test alternatives
#   0x40  wide (UTF-16)  -- compare UTF-16LE text instead of bytes
#   0x80  callback       -- invoke an engine callback before the comparison
#
# Without 0x01 and 0x04 a value-only condition is a *prefix* match of N
# characters/bytes.  That is why the high byte of ``y`` is a "hash window"
# length rather than necessarily the full string length.
EDGE_FLAG_LABELS = {
    0x01: "suffix",
    0x02: "any",
    0x04: "exact",
    0x08: "case-sensitive",
    FLAG_INLINE: "inline pattern",
    0x20: "list/any-of",
    FLAG_WIDE: "wide",
    0x80: "callback",
}

# ``tree_kind == 2`` (SIGTREE_BM) attribute ids are behaviour-monitoring event
# ids.  The names below are the switch returned by ``FUN_1809f649c`` (the
# engine's own BM event-to-name helper); the same ids are emitted by the BM
# event paths, e.g. ``FUN_18052e7cc``.
BM_EVENT_NAMES = {
    0x4000: "BM_CreateFile",
    0x4001: "BM_ChangeFile",
    0x4002: "BM_RenameFile",
    0x4003: "BM_DeleteFile",
    0x4004: "BM_OpenFile",
    0x4005: "BM_FileMetaData",
    0x4006: "BM_RegistryKeyCreate",
    0x4007: "BM_RegistryKeyRename",
    0x4008: "BM_RegistryKeyDelete",
    0x4009: "BM_RegistrySetValue",
    0x400A: "BM_RegistryDeleteValue",
    0x400B: "BM_NetworkConnect",
    0x400C: "BM_NetworkDataSend",
    0x400D: "BM_BootSectorChange",
    0x400E: "BM_RemoteThreadCreate",
    0x400F: "BM_RawWrite",
    0x4010: "BM_ProcessCreate",
    0x4011: "BM_ProcessStart",
    0x4012: "BM_NetworkDetection",
    0x4013: "BM_ArDetection",
    0x4014: "BM_ModuleLoad",
    0x4015: "BM_RegistryBlockSet",
    0x4016: "BM_RegistryBlockDelete",
    0x4017: "BM_EngineInternal",
    0x4018: "BM_Etw_PsSetLoadImageNotifyRoutine",
    0x4019: "BM_Etw_TerminateProcess",
    0x401A: "BM_Etw_SetEventHook",
    0x401B: "BM_Etw_RegisterInputDevices",
    0x401C: "BM_Etw_NtAdjustPrivileges",
    0x401D: "BM_Etw_SetThreadContext",
    0x401E: "BM_Etw_WriteMemory",
    0x401F: "BM_Etw_OpenProcess",
    0x4020: "BM_Etw_OpenThread",
    0x4021: "BM_Etw_RegisterLastShutdown",
    0x4022: "BM_Etw_RegisterShutdown",
    0x4023: "BM_Etw_CreateLink",
    0x4024: "BM_RegistryRestore",
    0x4025: "BM_RegistryReplace",
    0x4026: "BM_RegistryBlockRename",
    0x4027: "BM_RegistryBlockRestore",
    0x4028: "BM_RegistryBlockReplace",
    0x4029: "BM_VolumeMount",
    0x402A: "BM_Desktop",
    0x402B: "BM_OpenProcess",
    0x402C: "BM_BlockOpenProcess",
    0x402D: "BM_RegistryBlockCreate",
    0x402E: "BM_Etw_CodeInjection",
    0x402F: "BM_Etw_BlockExploit",
    0x4030: "BM_Etw_SetWindowsHook",
    0x4031: "BM_Etw_GetAsyncKeyState",
    0x4032: "BM_CreateFolder",
    0x4033: "BM_Etw_AllocVmLocal",
    0x4034: "BM_Etw_DirEnum",
    0x4035: "BM_Etw_ClearLog",
    0x4036: "BM_Etw_WMIActivityNew",
    0x4037: "BM_Etw_WMIExecMethod",
    0x4038: "BM_EnumFolder",
    0x4039: "BM_RenameFolder",
    0x4048: "BM_HardLinkFile",
    0x4049: "BM_CopyFile",
    0x404D: "BM_Etw_CredReadCredentials",
    0x404E: "BM_Etw_CredEnumerate",
    0x404F: "BM_Etw_CredReadDomainCredentials",
    0x4050: "BM_Etw_CredFindBestCredential",
    0x4051: "BM_Etw_CredReadByTokenHandle",
    0x4052: "BM_Etw_CredBackupCredentials",
    0x4053: "BM_Etw_VaultFindCredentials",
    0x4054: "BM_Etw_VaultEnumerateCredentials",
    0x4055: "BM_Etw_VaultGetUniqueCredential",
    0x4056: "BM_Taint",
    0x4057: "BM_Amsi_Scan",
    0x4058: "BM_Amsi_Match",
    0x4060: "BM_Etw_LDAPSearch",
    0x4061: "BM_Etw_BITSCreate",
    0x4062: "BM_Etw_ScheduledTaskCreate",
    0x4063: "BM_Etw_ScheduledTaskUpdate",
    0x4064: "BM_Etw_LogonSuccess",
    0x4065: "BM_Etw_LogonFailure",
    0x4066: "BM_Etw_UserAccountChanged",
    0x4067: "BM_Etw_AccountPasswordChanged",
    0x4068: "BM_Etw_AccountPasswordReset",
    0x4069: "BM_Etw_HiveHistoryClear",
    0x406A: "BM_OriginalFileName",
    0x406B: "BM_SignatureTrigger",
    0x406C: "BM_Etw_UserAccountCreated",
    0x406D: "BM_Etw_ExploitProtection",
    0x406E: "BM_Network_PortOpen",
    0x406F: "BM_Network_Volume",
    0x4070: "BM_Etw_SuspendThread",
    0x4071: "BM_Etw_ResumeThread",
    0x4072: "BM_Etw_SuspendProcess",
    0x4073: "BM_Etw_ResumeProcess",
    0x4074: "BM_Etw_LoadDriver",
    0x4075: "BM_Etw_UnloadDriver",
    0x4076: "BM_Etw_LoadDevice",
    0x4077: "BM_Etw_UnloadDevice",
    0x4079: "BM_Etw_ProtectVmLocal",
    0x4080: "BM_Etw_ServiceStop",
    0x4081: "BM_Etw_ServiceChangeStartType",
    0x4082: "BM_Etw_ServiceChangeBinaryPath",
    0x4083: "BM_Etw_ServiceChangeAccountInfo",
    0x4084: "BM_Etw_ServiceHostStarted",
    0x4085: "BM_Etw_ServiceStarted",
    0x4086: "BM_Network_Failure",
    0x4089: "BM_Etw_ReadVmRemote",
    0x408A: "BM_Etw_V2CodeInjection",
    0x408B: "BM_Etw_MapViewLocal",
    0x408C: "BM_Network_ConnectionOpen",
    0x408D: "BM_FileSequentialRead",
    0x408E: "BM_Parent",
    0x408F: "BM_NetworkSocket",
    0x4090: "BM_NetworkSetSocketOption",
    0x4091: "BM_ChangePermissions",
    0x4092: "BM_RegistrySetValue_From",
    0x4093: "BM_Etw_DangerousSyscall",
    0x4094: "BM_Etw_CLRModuleLoad",
    0x4095: "BM_Etw_CLRAssemblyLoad",
    0x4096: "BM_RegistryTpState",
    0x4097: "BM_Etw_ReadVmRemoteAgg",
    0x4098: "BM_Etw_WMICreateProcess",
    0x4099: "BM_ChangeOwner",
    0x409A: "BM_CloudResponse",
    0x409B: "BM_DeleteXattr",
    0x409C: "BM_SetFileUtimes",
    0x409D: "BM_SetFileFlags",
    0x409E: "BM_ForkCount",
    0x409F: "BM_AiDetection",
    0x40A0: "BM_Etw_AmsiInitFailed",
    0x40A1: "BM_DupFileDescriptor",
    0x40A2: "BM_MemoryMap",
    0x40A3: "BM_MemoryProtect",
    0x40A4: "BM_ProcessControl",
    0x40A5: "BM_Signer",
    0x40A6: "BM_ULS",
    0x40A7: "BM_Etw_ClipWrite",
    0x40A8: "BM_LoginSuccess",
    0x40A9: "BM_LoginFailure",
    0x40AA: "BM_GatekeeperOverride",
    0x40AB: "BM_TCC_Modify",
    0x40AC: "BM_XP_MalwareDetected",
    0x40AD: "BM_ScreensharingAttach",
    0x40AE: "BM_CS_Invalidated",
    0x40B0: "BM_PipeCreate",
    0x40B1: "BM_PipeOpen",
}

# What the *value* of a BM event attribute is.  This matters for the
# word-only conditions: the engine gives ``BM_ProcessStart`` /
# ``BM_ProcessCreate`` the full process command line, not just the image path,
# and gives ``BM_ModuleLoad`` the module path.  The hints are descriptive only;
# the condition words are still hashes of the live value.
BM_EVENT_VALUE_HINTS = {
    0x4000: "file path",
    0x4001: "file path",
    0x4002: "file path",
    0x4003: "file path",
    0x4004: "file path",
    0x4005: "file metadata",
    0x4006: "registry key",
    0x4007: "registry key",
    0x4008: "registry key",
    0x4009: "registry key/value",
    0x400A: "registry value",
    0x400B: "network endpoint",
    0x400C: "network data",
    0x400E: "remote thread",
    0x4010: "process command line",
    0x4011: "process command line",
    0x4012: "network indication",
    0x4014: "module path",
    0x4017: "internal tag / payload",
    0x4019: "process",
    0x402B: "process",
    0x4032: "folder path",
    0x406B: "signature / trigger name",
    0x408E: "parent process image",
    0x40FF: "opaque compiler-assigned anchor id",
    0xF000: "Lua callback group name",
}

# Attribute ids that are not BM event ids.
SPECIAL_ATTRIBUTE_NAMES = {
    0xF000: "LuaCallSigattrBM (Lua callback / !BMGroup)",
    0x40FF: "BM_SignatureAnchor (rule/group identity, not a live event)",
}

_CASE_FOLD = bytes((value + 32 if 0x41 <= value <= 0x5A else value)
                   for value in range(256))


def sigtree_value_crc(text: str, wide: bool = True) -> int:
    """CRC32 used for sig-tree value words.

    The engine hashes the ASCII-lowercased text with init ``0xffffffff`` and
    no final XOR.  Wide values are hashed as UTF-16LE code units; for ASCII
    text this is equivalent to ``(folded_char, 0)`` per character.
    ``FUN_1806765c0`` / ``FUN_180676604`` are the narrow / wide variants.
    """
    if wide:
        data = bytearray()
        for char in text:
            codepoint = ord(char)
            low = codepoint & 0xFF
            high = (codepoint >> 8) & 0xFF
            if high == 0:
                data += bytes((_CASE_FOLD[low], 0))
            else:
                data += bytes((low, high))
        payload = bytes(data)
    else:
        payload = bytes(_CASE_FOLD[value] for value in text.encode("latin-1", "replace"))
    return (zlib.crc32(payload) & 0xFFFFFFFF) ^ 0xFFFFFFFF


# A value-only sigtree side stores only a CRC32 of the attribute text.  The
# engine computes it over lowercased text with init 0xffffffff and no final
# XOR (``FUN_1806765c0`` narrow, ``FUN_180676604`` wide, called from
# ``FUN_1802371d0``).  The strings below are *candidate* matches only: CRC32
# is a 32-bit hash and a match is not proof, especially when scanning large
# candidate corpora.  Use ``sigtree_value_crc()`` to test a specific string.
# The key is ``(crc32, length)`` where length is in characters for wide values.
KNOWN_VALUE_STRINGS = {
    # BM_EngineInternal event tags (first parameter).
    (0x98E9D724, 10): "SMS_THREAT",
    (0x67F1CC42, 11): "BM_FILEOPEN",
    (0x6BF27EA1, 21): "BM_BLOCKPROCESSCREATE",
    (0x6DFB367B, 8): "CmdLowfi",
    (0x35C89E67, 9): "INTEGRITY",
    (0xF9AB6713, 9): "FILE_COPY",
    (0xC54CF93F, 10): "BM_STARTUP",
    (0xCA280C53, 10): "APIHOOKWOW",
    (0x2A045D89, 7): "SEVILLE",
    (0x40235293, 11): "REMEDIATION",
    (0x1C8FE211, 9): "TELEMETRY",
    (0x36A43164, 11): "FOLDERGUARD",
    (0x16464D4E, 21): "FolderGuardTargetDisk",
    (0x1E9A080B, 20): "ConnectionCacheEntry",
    (0x9951F5A3, 15): "DeferredActions",
    # Common process-path suffixes (BM_ProcessStart / BM_ProcessCreate).
    (0xC7F18C20, 15): "\\powershell.exe",
    (0xE0B63504, 8): "\\cmd.exe",
    (0x7072D606, 13): "\\rundll32.exe",
    (0xFE3A6F6A, 12): "\\wscript.exe",
    (0x0B6CB62B, 12): "\\cscript.exe",
    (0x14D93181, 12): "\\svchost.exe",
    (0x25BE5A07, 13): "\\certutil.exe",
    (0x5109CA91, 13): "\\regsvr32.exe",
    (0xB0C5EF3C, 10): "\\mshta.exe",
    (0xDE038D24, 9): "mshta.exe",
    (0x8464C128, 9): "\\wmic.exe",
    (0x2F6A201E, 11): "\\psexec.exe",
    (0x77D328EF, 11): "\\regasm.exe",
    (0x33AE3E51, 10): "\\bitsadmin",
    (0x487AC9E3, 7): "\\sc.exe",
    (0x76EEB249, 8): "\\net.exe",
    (0xF63025E3, 8): "\\reg.exe",
    (0x6F188314, 9): "\\curl.exe",
    # Candidate SMS threat-chain values (Sigma: 0x4017 + SMS_THREAT).
    (0x060419AD, 33): "HackTool:Win32/CobaltStrike.I!sms",
    (0x1B31E528, 33): "HackTool:Win64/CobaltStrike.I!sms",
}


def bm_event_name(attribute_id: int, tree_kind: int = None) -> str:
    """Return the engine/BM name for a sig-tree attribute id."""
    if attribute_id in SPECIAL_ATTRIBUTE_NAMES:
        return SPECIAL_ATTRIBUTE_NAMES[attribute_id]
    if tree_kind == 2:
        return BM_EVENT_NAMES.get(attribute_id, f"BM_event_0x{attribute_id:04x}")
    return f"0x{attribute_id:04x}"


def bm_event_value_hint(attribute_id: int, tree_kind: int = None):
    """Engine value semantics for a BM event attribute, or ``None``."""
    if tree_kind != 2:
        return None
    return BM_EVENT_VALUE_HINTS.get(attribute_id)


def describe_value(value: int, length: int, flags: int) -> str:
    """Render the expected value word of a value-only condition."""
    known = KNOWN_VALUE_STRINGS.get((value, length))
    if known is not None:
        return f"'{known}'"
    kind = "wide chars" if flags & FLAG_WIDE else "bytes"
    return f"crc32=0x{value:08x} ({length} {kind})"


def describe_side(flags: int, length: int, value: int,
                  condition=None, written=None,
                  value_hint: str = None) -> str:
    """Human-readable predicate for one side of a sig-tree edge.

    ``value_hint`` names the live value the condition is evaluated against,
    e.g. ``process command line`` for ``BM_ProcessStart``.  Including it keeps
    a value-only predicate from being mistaken for a test of the file content
    or image path.
    """
    if flags & 0x02 and condition is None:
        text = "any"
    elif condition is not None:
        if getattr(condition, "is_pattern", False):
            text = condition.text
            if flags & 0x10:
                text = (f"wide pattern {text!r}" if flags & FLAG_WIDE
                        else f"pattern {text!r}")
            else:
                text = f"pattern {text!r}"
        elif getattr(condition, "is_hash", False):
            text = f"{condition.kind} == {condition.text}"
        else:
            text = condition.text
    elif value is None:
        text = f"conditional ({length})"
    elif flags & 0x100:
        text = f"numeric == 0x{value:08x}"
    else:
        if flags & 0x01:
            operator = "ends with"
        elif flags & 0x04:
            operator = "equals"
        else:
            operator = "starts with"
        text = f"{operator} {describe_value(value, length, flags)}"

    if value_hint and text != "any":
        return f"{value_hint} {text}"
    return text

# ``tree_kind`` -> attribute id namespace observed in the rules.
# The engine selects a per-kind sigattr notifier context
# (``DAT_181112bf0 + kind * 0xa0``); kind 6 is the NRI (network) notifier.
TREE_KIND_ATTRIBUTE_NAMESPACES = {
    0: "0x51xx",
    1: "0x50xx",
    2: "behaviour-monitoring event ids (0x4000-0x40b1)",
    3: "0x30xx (file/PE metadata)",
    4: "0x52xx",
    5: "0x60xx",
    6: "0x70xx (NRI network attributes)",
}


def edge_flags_text(flags: int) -> str:
    """Render a per-side edge flag byte with the confirmed bits named."""
    known = 0
    parts = []
    for bit, label in EDGE_FLAG_LABELS.items():
        known |= bit
        if flags & bit:
            parts.append(label)
    unknown = flags & ~known
    if unknown:
        parts.append(f"0x{unknown:02x}")
    return "|".join(parts) if parts else "0x00"


def _decode_literal(data: bytes) -> str:
    """Decode a literal run as UTF-16LE when it looks like text, else latin-1."""
    if len(data) >= 2 and len(data) % 2 == 0 and data[1::2] == b"\x00" * (len(data) // 2):
        try:
            return data.decode("utf-16le")
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1", "replace")


def decode_tree_pattern(data: bytes) -> str:
    """
    Best-effort readable rendering of a sigtree condition blob.

    Sig-tree patterns are either byte strings or UTF-16LE strings with the
    single-byte ``0x90`` wildcard opcodes from the HSTR format embedded in
    them::

        90 00        end of pattern
        90 01 XX     skip exactly XX bytes
        90 02 XX     skip 0..XX bytes

    Opcodes 3..5 (alternatives / regex) are left verbatim.
    """
    out = []
    literal = bytearray()
    i = 0
    size = len(data)

    def flush():
        if literal:
            out.append(_decode_literal(bytes(literal)))
            literal.clear()

    while i < size:
        if data[i] == 0x90 and i + 1 < size:
            op = data[i + 1]
            if op == 0:
                flush()
                i += 2
                continue
            if op in (1, 2) and i + 2 < size:
                flush()
                if op == 1:
                    out.append(f"<skip {data[i + 2]}>")
                else:
                    out.append(f"<skip 0..{data[i + 2]}>")
                i += 3
                continue
        literal.append(data[i])
        i += 1

    flush()
    return "".join(out)


class SigTreeCondition:
    """One condition (left or right operand) of a sig-tree edge."""

    def __init__(self, side: str, kind: str, flags: int, data: bytes) -> None:
        self.side = side
        self.kind = kind  # "pattern", "md5", "sha1" or "sha256"
        self.flags = flags
        self.data = data

    def to_details(self) -> dict:
        return {
            "side": self.side,
            "kind": self.kind,
            "flags": self.flags,
            "data_hex": self.data.hex(),
            "text": self.text,
            "is_pattern": self.is_pattern,
            "is_hash": self.is_hash,
        }

    @property
    def is_pattern(self) -> bool:
        return self.kind == "pattern"

    @property
    def is_hash(self) -> bool:
        return self.kind in ("md5", "sha1", "sha256")

    @property
    def text(self) -> str:
        if self.is_pattern:
            return decode_tree_pattern(self.data)
        return self.data.hex()

    def __repr__(self) -> str:
        return (
            f"SigTreeCondition({self.side}, {self.kind}, "
            f"flags=0x{self.flags:02x}, data={self.data.hex()})"
        )


class SigTreeEdge:
    """
    One edge of a sig tree.

    ``x`` packs the two per-side flag bytes (``x & 0xff`` = right,
    ``x >> 8 & 0xff`` = left) and ``y`` packs the two inline pattern lengths
    (``y >> 16 & 0xff`` = right, ``y >> 24 & 0xff`` = left).  ``z``, ``w``
    and the optional ``extra`` / ``extra2`` words are node/action values that
    are not interpreted here.
    """

    def __init__(self, x: int, y: int, z: int, w: int,
                 extra: int = 0, extra2: int = 0,
                 conditions: list = None, tree_kind: int = None) -> None:
        self.x = x
        self.y = y
        self.z = z
        self.w = w
        self.extra = extra
        self.extra2 = extra2
        self.conditions = conditions or []
        self.tree_kind = tree_kind

    def to_details(self) -> dict:
        return {
            "x": self.x,
            "y": self.y,
            "z": self.z,
            "w": self.w,
            "extra": self.extra,
            "extra2": self.extra2,
            "left_flags": self.left_flags,
            "right_flags": self.right_flags,
            "left_length": self.left_length,
            "right_length": self.right_length,
            "attribute_id": self.attribute_id,
            "attribute_id_hex": f"0x{self.attribute_id:04x}",
            "attribute_name": self.attribute_name,
            "value_hint": self.value_hint,
            "control_flags": self.control_flags,
            "control_flags_hex": f"0x{self.control_flags:04x}",
            "left_flags_text": edge_flags_text(self.left_flags),
            "right_flags_text": edge_flags_text(self.right_flags),
            "left_value": self.left_value,
            "right_value": self.right_value,
            "left_value_text": self.left_value_text,
            "right_value_text": self.right_value_text,
            "left_predicate": self.left_predicate,
            "right_predicate": self.right_predicate,
            "summary": self.summary,
            "conditions": [condition.to_details() for condition in self.conditions],
        }

    @property
    def attribute_id(self) -> int:
        """Low 16 bits of ``y``: the sigattr attribute/field being compared.

        ``FUN_1803a02a8`` copies ``y`` to the node's first dword and the tree
        walker binary-searches the node index by that ``u16`` against the
        current match context's attribute id (``FUN_1800d2510``).  Each
        ``tree_kind`` uses its own attribute namespace, e.g. ``0x30xx`` for
        file/PE metadata trees.
        """
        return self.y & 0xFFFF

    @property
    def left_value(self):
        """Expected value for the left side when it has no inline condition.

        The engine stores ``z`` as the node's left condition word and compares
        it against a 32-bit hash of the live attribute value; ``FUN_1803a02a8``
        overwrites that word when an inline pattern or opcode blob follows, in
        which case the on-disk value is unused.
        """
        if self.condition("left") is not None:
            return None
        return self.z

    @property
    def right_value(self):
        """Expected value for the right side (see :attr:`left_value`)."""
        if self.condition("right") is not None:
            return None
        return self.w

    @property
    def control_flags(self) -> int:
        """Upper 16 bits of ``x``: per-node control bits (mostly undecoded)."""
        return (self.x >> 16) & 0xFFFF

    @property
    def attribute_name(self) -> str:
        """Engine name for :attr:`attribute_id` (BM event names for kind 2)."""
        return bm_event_name(self.attribute_id, self.tree_kind)

    @property
    def value_hint(self):
        """What kind of live value the BM event carries, when known."""
        return bm_event_value_hint(self.attribute_id, self.tree_kind)

    @property
    def left_value_text(self):
        """Known plain text for the left value word, or ``None``.

        A condition blob normally overrides the value word.  The compiler can
        still fill ``z``/``w`` with a CRC, so the candidate-value table is
        checked either way.  These are hints, not proof.
        """
        return KNOWN_VALUE_STRINGS.get((self.z, self.left_length))

    @property
    def right_value_text(self):
        """Known plain text for the right value word, or ``None``."""
        return KNOWN_VALUE_STRINGS.get((self.w, self.right_length))

    @property
    def left_predicate(self) -> str:
        """Readable predicate for the left side of the edge."""
        condition = self.condition("left")
        text = describe_side(
            self.left_flags, self.left_length, self.left_value, condition,
            value_hint=self.value_hint,
        )
        if condition is not None and condition.is_hash and self.left_value_text:
            text += f"; value word decodes to '{self.left_value_text}'"
        return text

    @property
    def right_predicate(self) -> str:
        """Readable predicate for the right side of the edge."""
        condition = self.condition("right")
        text = describe_side(
            self.right_flags, self.right_length, self.right_value, condition,
            value_hint=self.value_hint,
        )
        if condition is not None and condition.is_hash and self.right_value_text:
            text += f"; value word decodes to '{self.right_value_text}'"
        return text

    @property
    def summary(self) -> str:
        """One-line decoded description of the edge."""
        return (
            f"{self.attribute_name}: left {self.left_predicate}; "
            f"right {self.right_predicate}"
        )

    @property
    def left_flags(self) -> int:
        return (self.x >> 8) & 0xFF

    @property
    def right_flags(self) -> int:
        return self.x & 0xFF

    @property
    def left_flags_text(self) -> str:
        return edge_flags_text(self.left_flags)

    @property
    def right_flags_text(self) -> str:
        return edge_flags_text(self.right_flags)

    @property
    def left_length(self) -> int:
        return (self.y >> 24) & 0xFF

    @property
    def right_length(self) -> int:
        return (self.y >> 16) & 0xFF

    def condition(self, side: str):
        for cond in self.conditions:
            if cond.side == side:
                return cond
        return None

    def __repr__(self) -> str:
        return (
            f"SigTreeEdge(x=0x{self.x:08x}, y=0x{self.y:08x}, "
            f"z=0x{self.z:08x}, w=0x{self.w:08x}, "
            f"conds={self.conditions!r})"
        )


class SigTreeSig(BaseSig):
    """
    SIGNATURE_TYPE_SIGTREE (0x40), SIGTREE_EXT (0x41) and SIGTREE_BM (0xb3).

    All three types share one parser in mpengine (the handlers registered by
    the ``sigtree`` module, ``FUN_1803a0220`` / ``FUN_1803a0190`` /
    ``FUN_1803a0100`` -> ``FUN_1803a02a8``).  On-disk layout::

        u8  edge_count
        u8  variant       0..4 (number of optional words per edge)
        u8  unknown
        u8  tree_kind     0..6 (per-kind generator state index)
        u8  name[]        NUL-terminated, normally empty
        u32 meta          only when variant > 2
        edge[edge_count]:
            u32 x         right flags (b0), left flags (b1),
                          right length (b2), left length (b3)
            u32 y         parallel data word; lengths for x are in b20/b30
            u32 z
            u32 w
            u32 extra     only when variant >= 1
                          bit 8 = right condition has an opcode blob
                          bit 16 = left condition has an opcode blob
            u32 extra2    only when variant >= 2
            condition blobs, left first then right:
                inline (flag 0x10): extra-length raw bytes
                opcode 1: one byte opcode + inline length bytes
                opcode 2: 16-byte MD5
                opcode 3: 20-byte SHA-1
                opcode 4: 32-byte SHA-256

    A condition blob is a byte pattern or a UTF-16LE string that may contain
    the usual ``0x90`` HSTR wildcard opcodes (see
    :func:`decode_tree_pattern`).

    ``y & 0xffff`` is the **attribute id** of the edge.  The engine binary
    searches its node index by that ``u16`` against the current sigattr match
    context (``FUN_1800d2510``), so a sig tree is a decision tree over object
    attributes (PE metadata, registry, process, network request, ...), not over
    file bytes.  Each ``tree_kind`` selects one attribute namespace:
    ``0x30xx`` = file/PE metadata (kind 3), ``0x60xx``/``0x70xx`` = process and
    NRI network attributes (kinds 5/6); see
    :data:`TREE_KIND_ATTRIBUTE_NAMESPACES`.

    ``SIGTREE`` (0x40) stores only the precomputed 32-bit attribute values in
    ``z``/``w`` (with the hash-window lengths in the high bytes of ``y``) and
    never carries inline patterns or hashes.  ``SIGTREE_EXT`` (0x41) uses the
    same tree format and additionally embeds the leaf patterns/hashes in the
    record — the "EXT" is the in-record condition blob.  ``SIGTREE_BM``
    (0xb3) is the behaviour-monitoring flavour: in the shipped database every
    ``0xb3`` record uses ``tree_kind == 2`` and it is the type that carries
    most of the behaviour string patterns.  Its edges test BM event ids
    (``BM_EVENT_NAMES``); ``0xf000`` is a Lua-callback pseudo-attribute and
    ``0x40ff`` is a compiler-assigned *signature anchor* (rule/group id).
    ``0x40ff`` is not a live BM event: it appears as a root (control bit
    ``0x04``) or as the final node, always has an "any" right side, and carries
    either a CRC32 or an MD5 of a 36-character opaque identifier.

    All 17,940 ``0xb3``, 15,058 ``0x40`` and 4,207 ``0x41`` records in the
    shipped database consume their payload exactly (0x40: 0 patterns/hashes;
    0x41: 47,140 patterns and 15,467 MD5 hashes).
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type in SIGTREE_SIGS

        payload = self.sig_data
        if len(payload) < 5:
            raise ValueError(
                f"Unexpected {self.sig_type} payload size: {len(payload)}"
            )

        self.edge_count = payload[0]
        self.variant = payload[1]
        self.unknown = payload[2]
        self.tree_kind = payload[3]

        if self.variant >= 5:
            raise ValueError(f"Unsupported sigtree variant: {self.variant}")
        if self.tree_kind >= 7:
            raise ValueError(f"Unsupported sigtree kind: {self.tree_kind}")

        name_end = payload.find(b"\x00", 4, 4 + MAX_NAME_LEN + 1)
        if name_end < 0:
            raise ValueError("Unterminated sigtree name")
        self.name_raw = payload[4:name_end]
        self.name = self.name_raw.decode("utf-8", "replace")
        pos = name_end + 1

        self.meta = None
        if self.variant > 2:
            self.meta, = struct.unpack_from("<I", payload, pos)
            pos += 4

        self.edges = []
        for _ in range(self.edge_count):
            pos = self._parse_edge(payload, pos)

        self.trailing = bytes(payload[pos:])

    def _parse_edge(self, payload: bytes, pos: int) -> int:
        if pos + 16 > len(payload):
            raise ValueError("Truncated sigtree edge")
        x, y, z, w = struct.unpack_from("<IIII", payload, pos)
        pos += 16

        extra = 0
        if self.variant >= 1:
            extra, = struct.unpack_from("<I", payload, pos)
            pos += 4
        extra2 = 0
        if self.variant >= 2:
            extra2, = struct.unpack_from("<I", payload, pos)
            pos += 4

        conditions = []
        pos = self._parse_condition(
            payload, pos, "left", x >> 8 & 0xFF, y >> 24 & 0xFF,
            extra >> 16 & 1, conditions,
        )
        pos = self._parse_condition(
            payload, pos, "right", x & 0xFF, y >> 16 & 0xFF,
            extra >> 8 & 1, conditions,
        )

        self.edges.append(
            SigTreeEdge(x, y, z, w, extra, extra2, conditions, self.tree_kind)
        )
        return pos

    def _parse_condition(self, payload: bytes, pos: int, side: str,
                         flags: int, length: int, has_opcode: int,
                         conditions: list) -> int:
        if flags & FLAG_INLINE:
            if pos + length > len(payload):
                raise ValueError("Truncated sigtree pattern")
            conditions.append(
                SigTreeCondition(side, "pattern", flags, payload[pos:pos + length])
            )
            return pos + length

        if not has_opcode:
            return pos

        if pos >= len(payload):
            raise ValueError("Truncated sigtree condition opcode")

        opcode = payload[pos]
        pos += 1
        if opcode == OPCODE_PATTERN:
            length = length * 2 if flags & 0x40 else length
            kind = "pattern"
        else:
            entry = OPCODE_HASHES.get(opcode)
            if entry is None:
                raise ValueError(f"Unknown sigtree condition opcode: {opcode}")
            kind, length = entry

        if pos + length > len(payload):
            raise ValueError("Truncated sigtree condition data")

        conditions.append(
            SigTreeCondition(side, kind, flags, payload[pos:pos + length])
        )
        return pos + length

    def to_details(self) -> dict:
        return {
            "edge_count": self.edge_count,
            "variant": self.variant,
            "unknown": self.unknown,
            "tree_kind": self.tree_kind,
            "attribute_namespace": self.attribute_namespace,
            "attribute_ids": self.attribute_ids,
            "attribute_names": self.attribute_names,
            "name": self.name,
            "meta": self.meta,
            "is_behavior": self.is_behavior,
            "has_inline_conditions": self.has_inline_conditions,
            "description": self.describe(),
            "decoded_summary": " | ".join(edge.summary for edge in self.edges),
            "edges": [edge.to_details() for edge in self.edges],
        }

    @property
    def is_behavior(self) -> bool:
        return self.sig_type == SIG_TYPES[0xB3]

    @property
    def attribute_namespace(self) -> str:
        """Best-effort label for the attribute-id namespace of this kind."""
        return TREE_KIND_ATTRIBUTE_NAMESPACES.get(self.tree_kind, "unknown")

    @property
    def attribute_ids(self) -> list:
        """Distinct attribute ids referenced by the tree, in first-use order."""
        seen = []
        for edge in self.edges:
            if edge.attribute_id not in seen:
                seen.append(edge.attribute_id)
        return seen

    @property
    def attribute_names(self) -> list:
        """Engine names for :attr:`attribute_ids`, in first-use order."""
        return [bm_event_name(value, self.tree_kind) for value in self.attribute_ids]

    @property
    def has_inline_conditions(self) -> bool:
        return bool(self.patterns or self.hashes)

    @property
    def patterns(self) -> list:
        return [c for e in self.edges for c in e.conditions if c.is_pattern]

    @property
    def hashes(self) -> list:
        return [c for e in self.edges for c in e.conditions if c.is_hash]

    def describe(self) -> str:
        text = (
            f"{self.sig_type} kind={self.tree_kind} variant={self.variant} "
            f"edges={self.edge_count}"
        )
        if self.attribute_ids:
            ids = ",".join(f"0x{value:04x}" for value in self.attribute_ids[:4])
            if len(self.attribute_ids) > 4:
                ids += ",..."
            text += f" attrs={ids}"
        if self.name:
            text += f" name={self.name!r}"
        return text


class _ConditionView:
    """Adapter that lets dict details use the same predicates as objects."""

    def __init__(self, data: dict) -> None:
        self.data = data
        self.kind = data.get("kind", "")
        self.text = data.get("text") or data.get("data_hex", "")
        self.flags = data.get("flags", 0)

    @property
    def is_pattern(self) -> bool:
        return self.kind == "pattern"

    @property
    def is_hash(self) -> bool:
        return self.kind in ("md5", "sha1", "sha256")


def enrich_sigtree_details(details: dict) -> dict:
    """Add decoded event names / predicates to stored details.

    The shipped database predates the BM event-name and flag decoding, so the
    HTML/API layer calls this on read.  It is idempotent for freshly parsed
    records (``SigTreeSig.to_details`` already contains the same fields).
    """
    if not isinstance(details, dict) or not details.get("edges"):
        return details

    details = dict(details)
    kind = details.get("tree_kind")
    details["attribute_namespace"] = TREE_KIND_ATTRIBUTE_NAMESPACES.get(kind, "unknown")
    edges = []
    names = []
    for raw_edge in details["edges"]:
        edge = dict(raw_edge)
        attribute_id = edge.get("attribute_id")
        if attribute_id is None:
            attribute_id = int(edge.get("y", 0)) & 0xFFFF
            edge["attribute_id"] = attribute_id
        name = bm_event_name(attribute_id, kind)
        hint = bm_event_value_hint(attribute_id, kind)
        edge["attribute_id_hex"] = f"0x{attribute_id:04x}"
        edge["attribute_name"] = name
        edge["value_hint"] = hint
        if name not in names:
            names.append(name)

        control = (int(edge.get("x", 0)) >> 16) & 0xFFFF
        edge["control_flags"] = control
        edge["control_flags_hex"] = f"0x{control:04x}"

        conditions = edge.get("conditions") or []
        by_side = {cond.get("side"): _ConditionView(cond) for cond in conditions}
        for side in ("left", "right"):
            flags = int(edge.get(f"{side}_flags", 0))
            length = int(edge.get(f"{side}_length", 0))
            value = edge.get(f"{side}_value")
            if value is None:
                value = edge.get("z" if side == "left" else "w", 0)
                edge[f"{side}_value"] = value
            condition = by_side.get(side)
            known = KNOWN_VALUE_STRINGS.get((value, length))
            predicate = describe_side(
                flags, length, value, condition, value_hint=hint,
            )
            if condition is not None and condition.is_hash and known:
                predicate += f"; value word decodes to '{known}'"
            edge[f"{side}_flags_text"] = edge_flags_text(flags)
            edge[f"{side}_value_text"] = known
            edge[f"{side}_predicate"] = predicate
        edge["summary"] = (
            f"{name}: left {edge['left_predicate']}; "
            f"right {edge['right_predicate']}"
        )
        edges.append(edge)

    details["edges"] = edges
    details["attribute_names"] = names
    details["decoded_summary"] = " | ".join(edge["summary"] for edge in edges)
    return details

